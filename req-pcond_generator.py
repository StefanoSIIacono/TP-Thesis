import json

# Carica il file JSON
def load_cve_details(filename):
    with open(filename, 'r') as file:
        return json.load(file)

# Genera i prerequisiti
def generate_prerequisites(cvss_metrics):
    prerequisites = {
        "Attack_Vector": cvss_metrics.get("Attack_Vector", "UNKNOWN"),
        "Privileges_Required": cvss_metrics.get("Privileges_Required", "UNKNOWN"),
        "User_Interaction": cvss_metrics.get("User_Interaction", "UNKNOWN"),
        "CPE": "Specific Platform"  # Modifica se hai un campo per il CPE
    }
    return prerequisites

# Genera le post-condizioni
def generate_post_conditions(cvss_metrics, cvss_scores):
    post_conditions = {
        "Privileges_Gained": "Admin" if cvss_metrics.get("Privileges_Required") == "LOW" else "User",
        "Impact": {
            "Confidentiality": cvss_metrics.get("Confidentiality_Impact", "UNKNOWN"),
            "Integrity": cvss_metrics.get("Integrity_Impact", "UNKNOWN"),
            "Availability": cvss_metrics.get("Availability_Impact", "UNKNOWN"),
        },
        "Exploitability": {
            "Base_Score": cvss_scores.get("Base_Score", 0),
            "Impact_Score": cvss_scores.get("Impact_Score", 0),
            "Exploitability_Score": cvss_scores.get("Exploitability_Score", 0)
        }
    }
    return post_conditions

# Salva i risultati in un file JSON
def save_results(filename, prerequisites, post_conditions):
    cve_id = filename.split("_")[0]

    output = {
        "CVE_ID": cve_id,
        "Prerequisites": prerequisites,
        "Post_Conditions": post_conditions
    }
    

    output_filename = filename.replace("_details.json", "_analysis.json")
    with open(output_filename, 'w') as file:
        json.dump(output, file, indent=4)
    print(f"Results saved to {output_filename}")

# Main function
def main():
    filename = "CVE-2022-23087_details.json"  # Modifica con il nome del tuo file
    cve_data = load_cve_details(filename)
    
    cvss_metrics = cve_data.get("CVSS_Metrics", {})
    cvss_scores = cve_data.get("CVSS_Scores", {})
    
    prerequisites = generate_prerequisites(cvss_metrics)
    post_conditions = generate_post_conditions(cvss_metrics, cvss_scores)
    
    save_results(filename, prerequisites, post_conditions)

if __name__ == "__main__":
    main()
