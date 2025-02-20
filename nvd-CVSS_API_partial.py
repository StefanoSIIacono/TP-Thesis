import asyncio
import aiohttp
import json
import sys
import os
from typing import Optional, Dict, Any, List

API_KEY = "3e4f3894-05b2-432b-b17d-3734249c23c1"

class NVDAsyncClient:
    def __init__(self, api_key: Optional[str] = None):
        """
        Inizializza il client asincrono per NVD con filtro specifico
        
        :param api_key: Chiave API opzionale per NVD
        """
        self.api_key = api_key
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    async def fetch_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Recupera i dettagli filtrati per un singolo CVE
        
        :param cve_id: ID del CVE da recuperare
        :return: Dizionario con i dettagli specifici del CVE
        """
        headers = {
            'User-Agent': 'FilteredCVERetriever/1.0',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.base_url}?cveId={cve_id}', 
                    headers=headers, 
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    # Gestione codici di stato
                    if response.status == 404:
                        print(f"CVE {cve_id} non trovato.")
                        return None
                    
                    response.raise_for_status()
                    
                    # Parsa il JSON
                    data = await response.json()
                    
                    # Verifica esistenza vulnerabilità
                    if not data.get('vulnerabilities'):
                        print(f"Nessun dato trovato per {cve_id}")
                        return None
                    
                    # Estrazione dati CVSS
                    vulnerability = data['vulnerabilities'][0]
                    cvss_data = vulnerability.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0]
                    
                    # Struttura filtrata con soli dati richiesti
                    return {
                        'CVE_ID': cve_id,
                        'CVSS_Scores': {
                            'Base_Score': cvss_data.get('cvssData', {}).get('baseScore'),
                            'Impact_Score': cvss_data.get('impactScore'),
                            'Exploitability_Score': cvss_data.get('exploitabilityScore')
                        },
                        'CVSS_Metrics': {
                            'Attack_Vector': cvss_data.get('cvssData', {}).get('attackVector'),
                            'Privileges_Required': cvss_data.get('cvssData', {}).get('privilegesRequired'),
                            'User_Interaction': cvss_data.get('cvssData', {}).get('userInteraction'),
                            'Confidentiality_Impact': cvss_data.get('cvssData', {}).get('confidentialityImpact'),
                            'Integrity_Impact': cvss_data.get('cvssData', {}).get('integrityImpact'),
                            'Availability_Impact': cvss_data.get('cvssData', {}).get('availabilityImpact')
                        }
                    }
        
        except aiohttp.ClientResponseError as e:
            print(f"Errore di risposta per {cve_id}: {e}")
            return None
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"Errore di connessione per {cve_id}: {e}")
            return None

    async def fetch_multiple_cves(self, cve_ids: List[str]) -> Dict[str, Optional[Dict]]:
        """
        Recupera i dettagli per più CVE in modo concorrente
        
        :param cve_ids: Lista di CVE ID
        :return: Dizionario con risultati per ogni CVE
        """
        tasks = [self.fetch_cve_details(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks)
        
        return {cve_id: result for cve_id, result in zip(cve_ids, results)}

async def main():
    # Controlla gli argomenti
    if len(sys.argv) < 2:
        print("Uso: python script.py CVE-XXXX-XXXXX [CVE-YYYY-YYYYY ...] [API_KEY]")
        sys.exit(1)
    
    # Estrai CVE IDs e API key
    args = sys.argv[1:]
    api_key = API_KEY
    
    # Verifica se l'ultimo argomento è una potential API key
    if args[-1].startswith('CVE-') == False:
        api_key = args[-1]
        args = args[:-1]
    
    # Crea client NVD
    nvd_client = NVDAsyncClient(api_key)
    
    # Recupera dettagli
    results = await nvd_client.fetch_multiple_cves(args)
    
    # Salva e stampa risultati
    for cve_id, details in results.items():
        if details:
            # Stampa
            print(json.dumps(details, indent=2))
            
            # Salva file JSON
            with open(f'{cve_id}_details.json', 'w') as f:
                json.dump(details, f, indent=2)
            
            print(f"\nDettagli salvati in {cve_id}_details.json")

if __name__ == "__main__":
    asyncio.run(main())
