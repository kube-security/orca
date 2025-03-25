from.utils import calculate_sha256
from.logger import logger
import base64
import os
import requests
from.types import PackageRecord, to_record
import re
from packaging.version import Version


def search_vulnerabilities(name: str,version: str):
    """
    Code adapted from : https://github.com/pypa/packaging/blob/main/src/packaging/version.py
    """
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    response : requests.Response = requests.get(url,timeout=10)
    # TODO: error handling
    response_json = response.json()
    results: list = []
    vulns = response_json.get("vulnerabilities")

    # No `vulnerabilities` key means that there are no vulnerabilities for any version
    if vulns is None:
        return results
    for v in vulns:
        id = v["id"]

        # If the vulnerability has been withdrawn, we skip it entirely.
        withdrawn_at = v.get("withdrawn")
        if withdrawn_at is not None:
            logger.debug(f"PyPI vuln entry '{id}' marked as withdrawn at {withdrawn_at}")
            continue

        # Put together the fix versions list
        try:
            fix_versions = [Version(fixed_in) for fixed_in in v["fixed_in"]]
        except Exception as _:
            logger.error(f'Received malformed version from PyPI: {v["fixed_in"]}')

        # The ranges aren't guaranteed to come in chronological order
        fix_versions.sort()

        description = v.get("summary")
        if description is None:
            description = v.get("details")

        if description is None:
            description = "N/A"

        # The "summary" field should be a single line, but "details" might
        # be multiple (Markdown-formatted) lines. So, we normalize our
        # description into a single line (and potentially break the Markdown
        # formatting in the process).
        description = description.replace("\n", " ")

        results.append({
            'id':id,
            'description':description,
            'fix_versions':fix_versions,
            'aliases':set(v["aliases"])
        })
    return results



def analyze_record(directory: str, record: PackageRecord) -> bool:
    #logger.info(f"Analysing record {directory}/{record.path}")
    if not os.path.exists(f"{directory}/{record.path}") and record.nlines is not None:
        logger.error(f"Path does not exist {directory}/{record.path}")
        print(record)
    if record.nlines is not None:
        fp = open(f"{directory}/{record.path}","rb")
        content = fp.read()
        if len(content) != record.nlines:
            logger.error(f"File {directory}/{record.path} has incorrect number of bytes: expected {record.nlines}, actual {len(content)}")
            return False
        assert record.hashtype == "sha256"
        hash = calculate_sha256(f"{directory}/{record.path}")
        digest = base64.urlsafe_b64encode(hash).decode()
        if digest[-1] == "=":
            digest = digest[:-1]
        if digest != record.hash:
            logger.error(f"Hash value does not match for file: {directory}/{record.path}")
            return False


    return True

def get_package_version(directory: str, package: str) -> str:
    version_regex = r'\nVersion: (.*)'
    assert os.path.exists(f"{directory}/{package}/METADATA")
    fp = open(f"{directory}/{package}/METADATA")
    content = fp.read()
    matches = re.findall(version_regex,content)
    assert len(matches) == 1
    version = matches[0]
    package_name = package.split("-")[0]
    return (package_name,version) 


def analyze_package(directory: str,package: str):
    # Read the content of RECORD FILE
    assert os.path.exists(f"{directory}/{package}/RECORD")
    fp = open(f"{directory}/{package}/RECORD")
    content = fp.read()
    logger.info(f"Analysing package {package}")
    integrity = []
    for record_item in content.split("\n"): # Package integrity
        if len(record_item) > 1:
            record = to_record(record_item)
            integrity.append(analyze_record(directory, record))
    (name, version) = get_package_version(directory,package)
    results = search_vulnerabilities(name,version)
    if results != []:
        for result in results:
            logger.error(f"Vulnerability {result['id']} found on dependency")
        return False
    return not any(integrity)
