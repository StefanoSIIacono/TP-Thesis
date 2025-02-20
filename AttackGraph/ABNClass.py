from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from tkinter import filedialog
import networkx as nx
import pandas as pd
import numpy as np
#from AttackGraph import compute_attack_graph, load_graph
from itertools import product

class AttackGraphBN:
    def __init__(self, vertices_file, arcs_file):
        # Carica i dati e inizializza le strutture
        self.vertices = self._load_vertices(vertices_file)
        self.arcs = self._load_arcs(arcs_file)
        self.attack_graph = self._create_attack_graph()
        self.bayesian_network = self._create_bayesian_network()
        self.inference_engine = VariableElimination(self.bayesian_network)

    def _load_vertices(self, vertices_file):
        """Carica e processa il file dei vertici"""
        return pd.read_csv(vertices_file, 
                          header=None, 
                          names=['ID', 'Label', 'Type', 'InitialValue'])

    def _load_arcs(self, arcs_file):
        """Carica e processa il file degli archi"""
        return pd.read_csv(arcs_file, 
                          header=None, 
                          names=['Parent', 'Child', 'Weight'])

    def _create_attack_graph(self):
        """Crea il grafo di attacco usando NetworkX"""
        graph = nx.DiGraph()
        
        for _, row in self.vertices.iterrows():
            graph.add_node(row['ID'], 
                         label=row['Label'], 
                         type=row['Type'], 
                         value=row['InitialValue'])
        
        for _, row in self.arcs.iterrows():
            graph.add_edge(row['Parent'], row['Child'])
        
        return graph

    def _create_bayesian_network(self):
        """Converte l'attack graph in Bayesian Network"""
        bn = BayesianNetwork()
        bn.add_edges_from(self.attack_graph.edges())
        
        # Aggiungi CPDs per ogni nodo
        cpds = []
        for node in self.attack_graph.nodes():
            cpd = self._create_node_cpd(node)
            if cpd:
                cpds.append(cpd)
        
        bn.add_cpds(*cpds)
        return bn

    def _create_node_cpd(self, node):
        """Crea la CPT per un singolo nodo"""
        node_type = self.vertices.loc[self.vertices['ID'] == node, 'Type'].iloc[0]
        parents = list(self.attack_graph.predecessors(node))

        if node_type == 'LEAF':
            return self._create_leaf_cpd(node)
        elif node_type in ['AND', 'OR']:
            return self._create_gate_cpd(node, parents, node_type)

    def get_attack_probability(self, target_node):
        """Calcola la probabilità di successo per un dato target"""
        query_result = self.inference_engine.query(variables=[target_node])
        return query_result.values[1]  # Probabilità di True

    def get_critical_path(self, target_node):
        """Identifica il percorso critico verso il target"""
        return nx.shortest_path(self.attack_graph, 
                              source=self._find_root_nodes()[0],
                              target=target_node)

    def generate_report(self, target_nodes=None):
        """Genera un report di analisi"""
        if target_nodes is None:
            target_nodes = self._find_terminal_nodes()

        report = []
        for node in target_nodes:
            prob = self.get_attack_probability(node)
            path = self.get_critical_path(node)
            
            report.append(self._format_node_report(node, prob, path))
        
        return "\n\n".join(report)

    def update_vulnerability(self, vuln_id, new_cvss_score):
        """Aggiorna la probabilità di una vulnerabilità"""
        # Implementazione dell'aggiornamento
        pass