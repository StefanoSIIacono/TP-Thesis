import os 
CTI_PATH = "./cti"

if (not os.path.exists(CTI_PATH)):
    import subprocess   
    completed = subprocess.run(["git", "clone", "https://github.com/mitre/cti.git"])
    completed.check_returncode()

from stix2 import FileSystemSource, Filter
import requests
from constants import parts

def get_related_cwes_by_capec_id(capec_id):
    fs = FileSystemSource('./cti/capec/2.1')

    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', 'CAPEC-' + capec_id),
        Filter('external_references.source_name', '=', 'capec'),
    ]

    attack_pattern = fs.query(filt)[0]

    cwe_ids = [ref['external_id'] for ref in attack_pattern['external_references'] if ref['source_name'] == 'cwe']

    return cwe_ids

def get_related_cwes_and_attributes_by_capec_id(capec_id):
    fs = FileSystemSource('./cti/capec/2.1')

    # Define the filter to query for the specific CAPEC attack pattern
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', 'CAPEC-' + capec_id),
        Filter('external_references.source_name', '=', 'capec'),
    ]

    # Query the attack pattern
    attack_pattern = fs.query(filt)[0]

    # Retrieve CWE IDs
    cwe_ids = [ref['external_id'] for ref in attack_pattern['external_references'] if ref['source_name'] == 'cwe']

    # Retrieve additional attributes
    name = attack_pattern.get('name', '')
    prerequisites = attack_pattern.get('x_capec_prerequisites', [])
    resources_required = attack_pattern.get('x_capec_resources_required', [])
    skills_required = attack_pattern.get('x_capec_skills_required', {})
    likelihood_of_attack = attack_pattern.get('x_capec_likelihood_of_attack', '')
    consequences = attack_pattern.get('x_capec_consequences', {})

    # Return a dictionary with all relevant information
    return {
        'cwe_ids': cwe_ids,
        'name': name,
        'prerequisites': prerequisites,
        'resources_required': resources_required,
        'skills_required': skills_required,
        'likelihood_of_attack': likelihood_of_attack,
        'consequences': consequences
    }

def create_capec_dictionary(capec_ids):
    capecs = {}

    for capec_id in capec_ids:
        try:
            capecs[capec_id] = get_related_cwes_and_attributes_by_capec_id(capec_id)
        except Exception as e:
            print(f"Error retrieving data for CAPEC-{capec_id}: {e}")

    return capecs

# Example usage
capec_ids = []
for i in range(3):
  capec_ids.append(input("Enter CAPEC ID: "))

capec_dictionary = create_capec_dictionary(capec_ids)

# Print the results
for capec_id, info in capec_dictionary.items():
    print(f"CAPEC-{capec_id}:")
    print(f"  Name: {info['name']}")
    print(f"  CWE IDs: {info['cwe_ids']}")
    print(f"  Prerequisites: {info['prerequisites']}")
    print(f"  Resources Required: {info['resources_required']}")
    print(f"  Skills Required: {info['skills_required']}")
    print(f"  Likelihood of Attack: {info['likelihood_of_attack']}")
    print(f"  Consequences: {info['consequences']}\n")

def fetch_cves_with_cwe(cwe_id):
    # NVD API endpoint for CVE data
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Construct the CPE string for querying
    #cpe_string = f"?cpeName=cpe:2.3:a:{asset_name}:{asset_version}"
    cwe_string = f"?cweId=CWE-{cwe_id}"
    # Query the NVD API for CVEs related to the specified asset
    response = requests.get(f"{nvd_url}{cwe_string}")

    if response.status_code == 200:
        data = response.json()
        #print(data)
        # Initialize a list to store CVE IDs
        tot_res = data['totalResults']
        res_per_page = data['resultsPerPage']
        results_start = data['startIndex']

        if not tot_res:
            print("\tNo CVEs found for this asset.")
            return
        print(f"\tTotal results {tot_res}\n\tTotal result per page {res_per_page}")
        cve_list = []
        vulnerabilities = data['vulnerabilities']

        # Extract CVE IDs from the vulnerabilities section
        for vulnerability in vulnerabilities:
          cve = vulnerability['cve']
          cve_id = cve['id']
          cve_list.append(cve_id)

        # Print the list of CVE IDs
        print("\tList of CVEs:")
        for cve in cve_list:
            print(f"\t\t{cve}")

    else:
        print(f"Failed to fetch data: {response.status_code}")

# Look for CVEs related to the specified CWEs
for capec_id, info in capec_dictionary.items():
  print(f"CAPEC ID: {capec_id}")
  related_cwes = info['cwe_ids']

  for cwe in related_cwes:
    cwe_id = cwe[4:]
    print(f"\tCWE ID: {cwe_id}\n")
    fetch_cves_with_cwe(cwe_id)
    print("\n")

def fetch_cves_with_cpe_cwe(part, vendor, product, version, cwe_id, others = []):
    # NVD API endpoint for CVE data
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Construct the CPE string for querying
    cpe_string = "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version

    if others.__len__() > 7:
      print("Too many optional parameters.")
      return
    # If optional parameters are available
    elif others.__len__() == 0:
      print("No optional parameters.")
    else:
      for other in others:
          cpe_name += ":" + other

    #cpe_string = f"?cpeName=cpe:2.3:a:{asset_name}:{asset_version}"
    cwe_string = f"CWE-{cwe_id}"
    # Query the NVD API for CVEs related to the specified asset
    response = requests.get(f"{nvd_url}?cpeName={cpe_string}&cweID={cwe_string}")
    #response = requests.get(f"{nvd_url}?cpeName={cpe_string}")
    if response.status_code == 200:
        data = response.json()
        #print(data)
        # Initialize a list to store CVE IDs
        tot_res = data['totalResults']
        res_per_page = data['resultsPerPage']
        results_start = data['startIndex']

        if not tot_res:
            print("No CVEs found for this asset.")
            return
        print(f"Total results {tot_res}\nTotal result per page {res_per_page}")
        cve_list = []
        vulnerabilities = data['vulnerabilities']

        # Extract CVE IDs from the vulnerabilities section
        for vulnerability in vulnerabilities:
          cve = vulnerability['cve']
          cve_id = cve['id']
          cve_list.append(cve_id)

        # Print the list of CVE IDs
        print("List of CVEs:")
        for cve in cve_list:
            print(cve)

    else:
        print(f"Failed to fetch data: {response.status_code}")

# Input asset details
cwe_id = input("Enter the CWE ID (e.g., 'CWE-123'): CWE-")
product = input("Enter the product name: ")
version = input("Enter the version: ")
vendor = input("Enter the vendor name: ")
part = input("Enter the part (e.g., 'a'): ")

# If part is valid
if part in parts:
  fetch_cves_with_cpe_cwe(part, vendor, product, version, cwe_id)

else:
  print("Invalid part.")

