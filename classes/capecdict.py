from stix2 import FileSystemSource, Filter

class CapecDictionary:
    def __init__(self):
        self.capecs = {}

    # Retrieves all the information provided by capec for each id in capec_ids
    def populateCapecDict(self, capec_ids):
        fs = FileSystemSource('./cti/capec/2.1')

        for capec_id in capec_ids:
            try:
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

                self.capecs[capec_id] = {
                                        'cwe_ids': cwe_ids,
                                        'name': name,
                                        'prerequisites': prerequisites,
                                        'resources_required': resources_required,
                                        'skills_required': skills_required,
                                        'likelihood_of_attack': likelihood_of_attack,
                                        'consequences': consequences
                                        }
            except Exception as e:
                print(f"Error retrieving data for CAPEC-{capec_id}: {e}")