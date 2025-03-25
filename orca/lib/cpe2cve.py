# Original Author: Matteo (xonoxitron) Pisani
# Description: Given a CPE, this script returns all related CVE, ordered by severity (desc)
# Usage: python3 cpe2cve.py -c cpe:2.3:a:apache:http_server:2.4.54

# Import necessary modules
import requests

CPES_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
# Function to retrieve CVE data for a given CPE
def get_cve_data(session:requests.Session,cpe:str):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="
    response = session.get(base_url + cpe)
    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        try:
            cve_data = response.json()
            
            return cve_data.get("vulnerabilities", [])
        except Exception:
            print(response.text)
            exit()
    else:
        print(f"Error in HTTP request: {response.status_code}")
        print(response.text)
        return []


# Function to retrieve the CVE ID from a CVE object
def get_cve_id(cve):
    try:
        return cve["cve"]["CVE_data_meta"]["ID"]
    except (KeyError, TypeError, ValueError):
        # In case of missing or non-numeric data, assign a high value for non-evaluability
        return "N/A/"


# Function to retrieve metric version
def get_cve_metric_version(cve):
    if "baseMetricV4" in cve["impact"]:
        return "4"
    if "baseMetricV3" in cve["impact"]:
        return "3"
    if "baseMetricV2" in cve["impact"]:
        return "2"
    if "baseMetricV1" in cve["impact"]:
        return "1"
    return "N/A"


# Function to retrieve the score from a CVE object
def get_cve_score(cve):
    try:
        v = get_cve_metric_version(cve)
        return float(cve["impact"]["baseMetricV" + v]["cvssV" + v]["baseScore"])
    except (KeyError, TypeError, ValueError):
        # In case of missing or non-numeric data, assign a high value for non-evaluability
        return float("inf")


# Function to retrieve the severity from a CVE object
def get_cve_severity(cve):
    v = get_cve_metric_version(cve)
    cvss = cve["impact"]["baseMetricV" + v]
    if "severity" in cvss:
        return cvss["severity"]
    if "baseSeverity" in cvss["cvssV" + v]:
        return cvss["cvssV" + v]["baseSeverity"]
    return "N/A"


def create_session():
    s = requests.Session()
    s.headers.update({"apiKey":"1d424904-314b-4ebe-9740-23b427694cf4"})
    return s

def search_cpe(session: requests.Session,cpe:str):
    response = session.get(f"{CPES_URL}?cpeMatchString={cpe}")
    cpes = []
    if response.status_code != 200:
        return []
    json_response = response.json()
    products = json_response.get("products",[])
    for product in products:
        cpeName = product["cpe"]["cpeName"]
        cpes.append(cpeName)
    return cpes




# Main function for parsing command-line arguments and performing the sorting and printing
def cpe2cve(cpe:str):
    # Set up the argument parser
    session = create_session()
    cpeNames = search_cpe(session,cpe)
    print(cpeNames)
    cves = []
    for cpeName in cpeNames:
    # Retrieve CVE data for the given CPE
        cve_data = get_cve_data(session,cpeName)
        for item in cve_data:
            print(item["cve"]["id"])
            cves.append(item["cve"]["id"])

        
    return cves
    if len(cve_data) == 0:
        return []
    # Sort the CVEs by score in descending order
    sorted_cve = sorted(cve_data["CVE_Items"], key=get_cve_score, reverse=True)

    # Print the sorted CVEs
    i = 1
    cves = []
    for cve in sorted_cve:
        cve_id = get_cve_id(cve)
        score = get_cve_score(cve)
        severity = get_cve_severity(cve)
        cves.append(f"[{i}] ID: {cve_id}, Score: {score}, Severity: {severity}")
        i += 1
    return cves
