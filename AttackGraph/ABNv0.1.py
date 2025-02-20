from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from tkinter import filedialog
import pandas as pd
import numpy as np
from AttackGraph import compute_attack_graph, load_graph
from itertools import product

def create_bn_from_attack_graph(graph, vertices):
    """
    Create a Bayesian Network from the attack graph with meaningful CPTs.
    
    The CPTs are created with the following logic:
    - Root nodes (no parents): 80% chance of being False (0), 20% chance of being True (1)
    - Non-root nodes: 
      - If any parent is True, higher chance of being True
      - If all parents are False, higher chance of being False
    """
    # Initialize Bayesian Network
    bn = BayesianNetwork()
    
    # Add edges from the attack graph
    bn.add_edges_from(graph.edges())
    
    # Create CPDs for each node
    cpds = []
    for node in graph.nodes():
        parents = list(graph.predecessors(node))
        
        if not parents:
            # Root node (no parents)
            cpd = TabularCPD(
                variable=node,
                variable_card=2,
                values=[[0.8], [0.2]]  # [P(False), P(True)]
            )
        else:
            # Node with parents
            n_parents = len(parents)
            parent_cards = [2] * n_parents
            
            # Generate CPT values based on parent combinations
            cpt_values = []
            for parent_combination in product([0, 1], repeat=n_parents):
                true_parents = sum(parent_combination)
                
                if true_parents == 0:
                    # If all parents are False
                    prob_true = 0.1
                else:
                    # Probability increases with number of True parents
                    prob_true = min(0.9, 0.3 + (0.6 * true_parents / n_parents))
                
                cpt_values.append([1 - prob_true, prob_true])
            
            # Transpose the values to match pgmpy's expected format
            cpt_values = np.array(cpt_values).T.tolist()
            
            cpd = TabularCPD(
                variable=node,
                variable_card=2,
                values=cpt_values,
                evidence=parents,
                evidence_card=parent_cards
            )
        
        cpds.append(cpd)
    
    # Add CPDs to the network
    bn.add_cpds(*cpds)
    
    # Verify that the network is valid
    if not bn.check_model():
        raise ValueError("Invalid Bayesian Network")
    
    return bn

def show_bn(bn):
    """Display the structure and CPDs of the Bayesian Network."""
    print("\nBayesian Network Structure:")
    print("Nodes:", bn.nodes())
    print("\nEdges:", bn.edges())
    
    print("\nConditional Probability Distributions:")
    for cpd in bn.get_cpds():
        print(f"\nCPD of {cpd.variable}:")
        print(cpd)

def perform_inference(bn, query_nodes=None):
    """
    Perform inference on specified nodes or all nodes if none specified.
    Returns marginal probabilities for the queried nodes.
    """
    inference = VariableElimination(bn)
    
    if query_nodes is None:
        query_nodes = list(bn.nodes())
    elif isinstance(query_nodes, (int, str)):
        query_nodes = [query_nodes]
    
    results = {}
    for node in query_nodes:
        try:
            query_result = inference.query(variables=[node])
            results[node] = query_result
        except Exception as e:
            print(f"Error performing inference on node {node}: {str(e)}")
    
    return results

def main():
    # File selection
    import os
    cwd = os.getcwd()
    
    vertices_csv = filedialog.askopenfile(initialdir=cwd, title='Vertices file', 
                                        filetypes=[("Comma Separated Values", ".csv")])
    arcs_csv = filedialog.askopenfile(initialdir=cwd, title='Arcs file', 
                                     filetypes=[("Comma Separated Values", ".csv")])
    
    if not vertices_csv or not arcs_csv:
        print("File selection cancelled")
        return
    
    try:
        # Load data and compute attack graph
        vertices, arcs = load_graph(vertices_csv.name, arcs_csv.name)
        graph = compute_attack_graph(vertices, arcs)
        
        # Convert attack graph to Bayesian Network
        bn = create_bn_from_attack_graph(graph, vertices)
        
        # Display the Bayesian Network
        show_bn(bn)
        
        # Perform inference on all nodes
        print("\nPerforming inference on all nodes:")
        results = perform_inference(bn)
        for node, result in results.items():
            print(f"\nNode {node} marginal probabilities:")
            print(result)
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        vertices_csv.close()
        arcs_csv.close()

if __name__ == '__main__':
    main()