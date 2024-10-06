from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

# Definizione del modello
model = BayesianNetwork([('WebServerCompromised', 'FirewallBypassed'),
                         ('FirewallBypassed', 'DatabaseCompromised'),
                         ('DatabaseCompromised', 'SensitiveDataCompromised')])

# CPD: Probabilità di compromissione del Web Server (CVE-2021-41773)
cpd_web_server = TabularCPD(variable='WebServerCompromised', variable_card=2,
                            values=[[0.2], [0.8]])

# CPD: Probabilità di bypassare il Firewall, dato che il Web Server è compromesso
cpd_firewall = TabularCPD(variable='FirewallBypassed', variable_card=2,
                          values=[[0.4, 0.7], [0.6, 0.3]],
                          evidence=['WebServerCompromised'], evidence_card=[2])

# CPD: Probabilità di compromissione del Database, dato che il Firewall è bypassato
cpd_database = TabularCPD(variable='DatabaseCompromised', variable_card=2,
                          values=[[0.3, 0.6], [0.7, 0.4]],
                          evidence=['FirewallBypassed'], evidence_card=[2])

# CPD: Probabilità di compromissione dei dati sensibili, dato che il Database è compromesso
cpd_sensitive_data = TabularCPD(variable='SensitiveDataCompromised', variable_card=2,
                                values=[[0.1, 0.9], [0.9, 0.1]],
                                evidence=['DatabaseCompromised'], evidence_card=[2])

# Aggiunta delle CPD al modello
model.add_cpds(cpd_web_server, cpd_firewall, cpd_database, cpd_sensitive_data)

# Verifica del modello
assert model.check_model()

# Inferenza
infer = VariableElimination(model)

# Calcolo della probabilità di compromissione dei dati sensibili
result = infer.query(variables=['SensitiveDataCompromised'], evidence={'WebServerCompromised': 1})
print(result)
