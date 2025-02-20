from arango import ArangoClient
from arango.exceptions import ArangoError

DB = 'BRON'
USERNAME = 'root'
PASSWORD = 'changeme'

DEFAULT = 5

def get_cve_severity(cve_id: str):#, username: str = "root", password: str = "password"):
    """Retrieve the severity (weight) of a CVE from the BRON Database on ArangoDB."""
    
    # Configuration
    client = ArangoClient(hosts="http://localhost:8529")
    
    try:
        # Connection
        db = client.db(name=DB, username=USERNAME, password=PASSWORD)
        
        # Query 
        collection = db.collection("cve")
        document = collection.get(cve_id)
        
        '''
        if document:
            return document['metadata'].get("weight")
        '''  
        if document and "metadata" in document and "weight" in document["metadata"]:
            return float(document["metadata"]["weight"])
        return DEFAULT
         
    except ArangoError as e:
        print(f"Error during the query for {cve_id}: {str(e)}")
        return DEFAULT  # Fallback
    finally:
        client.close()

def main():
    # Utilization example 
    cve_severity = get_cve_severity("CVE-2002-0392")
    print(f"Severity: {cve_severity}")

if __name__ == '__main__':
    main()