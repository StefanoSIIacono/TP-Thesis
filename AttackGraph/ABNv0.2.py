from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from tkinter import filedialog
import pandas as pd
import numpy as np
from AttackGraph import compute_attack_graph, load_graph
from itertools import product

def create_improved_bn(graph, vertices):

    def get_node_probability(node_id, node_data):
        node_type = vertices.loc[vertices['ID'] == node_id, 'Type'].iloc[0]
        node_label = vertices.loc[vertices['ID'] == node_id, 'Label'].iloc[0]
        
        if node_type == 'LEAF':
            if 'vulExists' in node_label:
                # Usa CVSS per vulnerabilità
                vuln_id = extract_vuln_id(node_label)
                return get_cvss_probability(vuln_id)
            else:
                # Usa il valore iniziale di MulVAL
                return vertices.loc[vertices['ID'] == node_id, 'InitialValue'].iloc[0]
        
        return None  # Per nodi non-LEAF

    def create_cpt(node_id, parents):
        node_type = vertices.loc[vertices['ID'] == node_id, 'Type'].iloc[0]
        
        if node_type == 'AND':
            return create_and_cpt(parents)
        elif node_type == 'OR':
            return create_or_cpt(parents)
        
        return None

    # Implementazione delle funzioni helper
    def create_and_cpt(parents):
        n_parents = len(parents)
        cpt_values = []
        for parent_combination in product([0, 1], repeat=n_parents):
            if all(parent_combination):
                prob_true = 0.9  # Alta probabilità se tutti i genitori sono True
            else:
                prob_true = 0.1
            cpt_values.append([1 - prob_true, prob_true])
        return np.array(cpt_values).T.tolist()

    def create_or_cpt(parents):
        n_parents = len(parents)
        cpt_values = []
        for parent_combination in product([0, 1], repeat=n_parents):
            if any(parent_combination):
                prob_true = 0.8  # Alta probabilità se almeno un genitore è True
            else:
                prob_true = 0.1
            cpt_values.append([1 - prob_true, prob_true])
        return np.array(cpt_values).T.tolist()

    def get_cvss_probability(vuln_id):
        """Converte CVSS score in probabilità"""
        if vuln_id == 'CAN-2002-0392':
            cvss_score = get_cvss_score(vuln_id)
            # Normalizza e aggiusta basandosi sulla difficoltà di exploit
            base_prob = cvss_score / 10.0
            exploit_difficulty = get_exploit_complexity(vuln_id)
            return adjust_probability(base_prob, exploit_difficulty)
        return 0.5  # Valore default per vulnerabilità sconosciute

    def adjust_probability(base_prob, exploit_complexity):
        """Aggiusta probabilità basandosi sulla complessità dell'exploit"""
        complexity_factors = {
            'LOW': 1.0,
            'MEDIUM': 0.7,
            'HIGH': 0.4
        }
        return base_prob * complexity_factors.get(exploit_complexity, 0.5)

    def enhanced_inference(bn, vertices):
        """Inferenza migliorata con analisi dei percorsi critici"""
        inference = VariableElimination(bn)

        # Trova i nodi target (tipicamente execCode con root)
        target_nodes = [node for node in bn.nodes() 
                        if 'execCode' in vertices.loc[vertices['ID'] == node, 'Label'].iloc[0]
                        and 'root' in vertices.loc[vertices['ID'] == node, 'Label'].iloc[0]]

        results = {}
        for target in target_nodes:
            # Calcola probabilità di compromissione
            query_result = inference.query(variables=[target])
            
            # Trova percorso critico
            critical_path = find_critical_path(bn, target)
            
            results[target] = {
                'probability': query_result,
                'critical_path': critical_path
            }

        return results

    def generate_security_report(inference_results, vertices):
        """Genera report dettagliato dell'analisi"""
        report = []

        for target, data in inference_results.items():
            node_label = vertices.loc[vertices['ID'] == target, 'Label'].iloc[0]
            prob = data['probability'].values[1]  # Probabilità di successo
            
            report.append(f"Target: {node_label}")
            report.append(f"Probabilità di compromissione: {prob:.2%}")
            
            if prob > 0.5:
                report.append("ALTO RISCHIO - Azione immediata richiesta")
                report.append("Percorso critico di attacco:")
                for node in data['critical_path']:
                    report.append(f"  → {vertices.loc[vertices['ID'] == node, 'Label'].iloc[0]}")

        return "\n".join(report)