# attack_graph.py
import networkx as nx
import pandas as pd

class AttackGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.vertices = None
        self.arcs = None

    def load_data(self, vertices_path: str, arcs_path: str) -> None:
        """Load data from MulVAL output files"""
        self.vertices = pd.read_csv(vertices_path, header=None, 
                                  names=['ID', 'Label', 'Type', 'InitialValue'])
        
        # Parent and child are inverted because of the representation of the graph 
        # It is no more Parent -> Child but Precondition -> Postcondition
        self.arcs = pd.read_csv(arcs_path, header=None, 
                              names=['Child', 'Parent', 'Weight'])
        
        # Verify vertices and arcs are properly loaded
        print("Vertices:")
        print(self.vertices)
        print("\nArcs:")
        print(self.arcs)

    def build_graph(self) -> nx.DiGraph:
        """Create the attack graph structure"""
        for _, row in self.vertices.iterrows():
            self.graph.add_node(row['ID'], 
                              label=row['Label'], 
                              type=row['Type'], 
                              value=row['InitialValue'])

        for _, row in self.arcs.iterrows():
            parent = row['Parent']
            child = row['Child']
            if parent in self.graph.nodes() and child in self.graph.nodes():
                self.graph.add_edge(parent, child)
            else:
                print(f"SKIPPED invalid edge: {parent} -> {child}")

        return self.graph

    def get_node_info(self, node_id: int) -> dict:
        """Get information about a specific node"""
        node_data = self.vertices[self.vertices['ID'] == node_id].iloc[0]
        return {
            'id': node_id,
            'label': node_data['Label'],
            'type': node_data['Type'],
            'value': node_data['InitialValue']
        }