import argparse
import datetime
import json
import os
from typing import List, Set

from orca.lib.apk import get_apk
from orca.lib.ascii_checkers import parse_gemspec
from orca.lib.bin_checkers import check_binaries
from orca.lib.composer import get_composer
from orca.lib.cpe2cve import cpe2cve
from orca.lib.dnf import get_dnf
from orca.lib.dpkg import get_dpkg
from orca.lib.golang import extract_go_dependencies, get_gomod
from orca.lib.jar import get_jar
from orca.lib.package_json import get_package_json
from orca.lib.path import get_filepaths
from orca.lib.perl import get_perl
from orca.lib.pkgconfig import get_pkgconfig
from orca.lib.python import extract_python_dependencies
from orca.lib.rpm_packages import get_rpm
from orca.lib.logger import logger
from orca.lib.types import VulnerabilityReport

unuseful_extensions = [".php",".h",".c",".xml",".png",".csv",".js",".css",".jar"]



def is_executable(file_path):
    return os.path.isfile(file_path) and os.access(file_path, os.X_OK)


def get_executables(files,directory) -> List[str]:
    no_ext = filter(lambda x: "." not in x.split("/")[-1],files) # First no extension.
    no_ext_executable = filter(lambda x: is_executable(os.path.join(directory,x)),no_ext)

    no_ext_binary = list(filter(lambda x: is_binary_executable(os.path.join(directory,x)),no_ext_executable))
    libs = list(filter(lambda x:  x.endswith(".so"),files))
    return no_ext_binary + libs

def split_executable_files(files, directory):
    executables = []
    non_executables = []
    for path in files:
       file = path.split("/")[-1]
       real_path = os.path.join(directory, path)
       if any([file.endswith(ext) for ext in unuseful_extensions]):
           non_executables.append(path)
       elif file.startswith("lib")  and ".so" in file:
           continue
       elif is_binary_executable(real_path):
        executables.append(path)
       elif os.path.isdir(real_path):
           continue
       else:
            non_executables.append(path)
    return executables, non_executables


def is_binary_executable(file_path):
    if not os.path.isfile(file_path):
        return False
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
    except Exception:
        return False

    return magic == b"\x7fELF"  # Check for ELF magic number

def add_duplicate_links(directory,paths,files):
    fcopy = set()
    for file in paths.union(files):
        if len(file) < 2:
            # paths.remove(file)
            continue
        orig_path = directory + "/" + file
        realpath = os.path.realpath(orig_path)
        cleanpath = realpath.replace(directory + "/", "")

        if orig_path != realpath and (
            (cleanpath in files and file not in files)
            or (cleanpath in paths and file in files)
        ):
            fcopy.add(cleanpath)
            fcopy.add(file)
    return fcopy

def remove_links(directory,paths):
    real_paths = set()
    for file in paths:
        if len(file) < 2:
            # paths.remove(file)
            continue
        orig_path = directory + "/" + file
        realpath = os.path.realpath(orig_path)
        cleanpath = realpath.replace(directory + "/", "")

        if orig_path != realpath:
            real_paths.add(cleanpath)
        else:
            real_paths.add(file)
    return real_paths

def maybe_binary(file: str):
    end = file.split("/")[-1]
    return ("." not in file or ".so" in file) and end.lower() == end

def scan_os(paths: List[str],directory: str)-> None:
    OS_INFOS = ["etc/os-release","etc-release","usr/lib/os-release","etc/debian_version"]
    os_relevant_paths = [path for path in paths if path in OS_INFOS ]
    if len(os_relevant_paths) == 0:
        logger.warning("Could not find os information")
    else:
        osinfo = {}
        for path in os_relevant_paths:
            content = open(os.path.join(directory,path)).read()
            if "debian_version" in path:
                osinfo["version"] =  content.strip().split("/")[0]
            data = {}
            for line in content.split("\n"):
            # Strip the line of extra whitespace and ignore comments or empty lines
                line = line.strip()
                if line and not line.startswith('#'):
                    # Split the line by '=' to separate key and value
                    try:
                        key, value = line.split('=', 1)
                    except Exception as _:
                        break
                    # Remove surrounding quotes if the value is quoted
                    value = value.strip('"')
                    # Add to the dictionary
                    data[key] = value
            if "NAME" in data:
                osinfo["name"] = data.get("NAME")
                osinfo["major"] = data.get("VERSION_ID")
                osinfo["codename"] = data.get("VERSION_CODENAME")
                osinfo["cpe"] = data.get("CPE_NAME")
                osinfo["prettyname"] = data.get("PRETTY_NAME")
            
            
        return osinfo 
    return None

def scan_filesystem(directory,analyze_binaries=False,accurate=False) -> VulnerabilityReport:
    paths: Set[str] = get_filepaths(directory)


    report: VulnerabilityReport = VulnerabilityReport(paths)
    
    osinfo = scan_os(report.remaining_files,directory)
    if osinfo is not None:
        report.os = osinfo
    
    # OS-packages
    logger.info(f"Initial files {len(paths)}")
    
    logger.info("Parsing executables")
    executable = get_executables(report.remaining_files, directory)
    logger.info(f"Found {len(executable)} executables")

    # assume go
    go = extract_go_dependencies(executable, directory)
    report.add_package_files(go)
    
    
    # Try to remove duplicates probably could be removed
    if accurate:
        logger.info("Removing duplicates")
        duplicates = add_duplicate_links(directory,paths,report.analyzed_files)
        report.analyzed_files.update(duplicates)
        report.remaining_files = report.remaining_files.difference(duplicates)


    logger.info("Parsing language-specific packages")
 
    report.add_package_files(extract_python_dependencies(paths,directory))
    report.add_package_files(get_jar(report.remaining_files,directory))
    report.add_package_files(get_package_json(report.remaining_files,directory))
    report.add_package_files(get_composer(report.remaining_files, directory))
    report.add_package_files(get_perl(report.remaining_files,directory))
    report.add_package_files(parse_gemspec(report.remaining_files,directory))
    report.add_package_files(get_gomod(report.remaining_files,directory))
    


    logger.info("Parsing OS package managers")
    report.add_package_files(get_dpkg(report.remaining_files, directory))
    report.add_package_files(get_rpm(report.remaining_files, directory))
    report.add_package_files(get_apk(report.remaining_files,directory))
    report.add_package_files(get_dnf(report.remaining_files,directory))
    report.add_package_files(get_pkgconfig(report.remaining_files,directory))

    if analyze_binaries:
        binaries = check_binaries(directory,executable) 
        report.add_package_files(binaries)


    logger.info(f"Files not indexed {len(report.remaining_files)}")
    logger.info(f"Total Packages {len(report.packages)}")
    return report


def get_cpes(directory,analyze_binaries=False,store_cpes=True,store_cpe_files=True,accurate=False,analyze_cves=False):

    report:VulnerabilityReport = scan_filesystem(directory,analyze_binaries,accurate) 
    pkgset = list(set(report.packages))

    if store_cpes:
        with open("result.csv","w") as fp:
            fp.write("product,version,vendor\n")
            for pkg in pkgset:
                fp.write(pkg.to_csv_entry() + "\n")
            fp.close()

    if store_cpe_files:
        with open("cpe_files.json","w") as fp:
            json.dump(report.to_json(),fp,indent="\t")
            fp.close()

    if analyze_cves:
        cpeset = set([cpe.to_cpe() for cpe in report.packages])
        total_cves = set()
        for cpe in cpeset:
            cves = cpe2cve(cpe)
            total_cves.update(cves)
            for cve in cves:
                logger.error(cve)
        logger.error(f"Found {len(total_cves)} CVEs")
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Scans for CPEs in a given directory. Currently in alpha phase, the program will randomly select N=30 subfolders and scan for cpes therein"""
    )
    parser.add_argument(
        "-d", "--directory", type=str, help="Directory to analyze", required=True
    )
    parser.add_argument(
        "--store-cpes", type=bool, help="Store cpes to file (result.csv)", required=False,default=True
    )
    parser.add_argument(
        "--store-cpe-files", type=bool, help="Store cpe-related files to file (cpe_files.json)", required=False,default=True
    )
    parser.add_argument(
        "--analyze-cves", type=bool, help="Scan for CVEs", required=False,default=False
    )
    args = parser.parse_args()

    path: str = args.directory
    store_cpes = args.store_cpes
    store_cpe_files = args.store_cpe_files
    analyze_cves = args.analyze_cves
    subdirs = [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
    for subdir in subdirs:
        directory = os.path.join(path,subdir)
        start = datetime.datetime.now()
        get_cpes(directory,analyze_binaries=False,store_cpes=store_cpes,store_cpe_files=store_cpe_files,analyze_cves=analyze_cves)
        end = datetime.datetime.now()
        logger.info(f"Elapsed time: {(end-start).total_seconds() * 1000} ms")
        logger.debug("------END------")
