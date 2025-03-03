# bayesian_network.py
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from pgmpy.inference import BeliefPropagation
from attack_graph import AttackGraph
from probability_calculator import ProbabilityCalculator

class SecurityBayesianNetwork:
    def __init__(self, attack_graph: AttackGraph, rules_file: str = None):
        self.attack_graph = attack_graph
        self.bn = BayesianNetwork()
        self.probability_calculator = ProbabilityCalculator(rules_file)
        
    def build_network(self) -> BayesianNetwork:
        """Convert attack graph to Bayesian Network"""

        # Add nodes from attack graph
        self.bn.add_nodes_from(self.attack_graph.graph.nodes())

        # Check if edges are consistent with nodes
        edges = []
        for edge in self.attack_graph.graph.edges():
            parent, child = edge
            if parent in self.bn.nodes() and child in self.bn.nodes():
                edges.append(edge)
            else:
                print(f"Warning: Arc is not valid {edge}. One node does not exist.")

        # Add edges from attack graph
        self.bn.add_edges_from(self.attack_graph.graph.edges())
        
        # Create CPDs for each node
        cpds = []
        for node in self.attack_graph.graph.nodes():
            cpd = self._create_node_cpd(node)
            if cpd:
                cpds.append(cpd)

        # Add CPDs to network
        self.bn.add_cpds(*cpds)
        
        if not self.bn.check_model():
            raise ValueError("Invalid Bayesian Network structure")
        
        return self.bn

    def _create_node_cpd(self, node: int) -> TabularCPD:
        """Create CPD for a specific node based on its type and relationships"""
        node_info = self.attack_graph.get_node_info(node)
        parents = list(self.attack_graph.graph.predecessors(node))
        
        # Filter out not existing parents
        valid_parents = [p for p in parents if p in self.bn.nodes()]

        return self.probability_calculator.calculate_cpd(node, node_info, valid_parents)

    def perform_inference(self, target_nodes=None, evidence=None):
        """Perform probabilistic inference on the network"""
        inference = VariableElimination(self.bn)
        #inference = BeliefPropagation(self.bn)
        
        if target_nodes is None:
            target_nodes = list(self.bn.nodes())
        elif isinstance(target_nodes, (int, str)):
            target_nodes = [target_nodes]
            
        results = {}
        for node in target_nodes:
            try:
                query_result = inference.query(variables=[node], evidence=evidence if evidence else {})
                node_info = self.attack_graph.get_node_info(node)
                results[node] = {
                    'probabilities': query_result,
                    'info': node_info
                }
            except Exception as e:
                print(f"Error performing inference on node {node}: {str(e)}")
        
        return results