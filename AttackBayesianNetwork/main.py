# main.py
from attack_graph import AttackGraph
from bayesian_network import SecurityBayesianNetwork
import os
from tkinter import filedialog
from tkinter import messagebox

def main():
    cwd = os.getcwd()
    
    # File selection dialogs
    vertices_csv = filedialog.askopenfile(initialdir=cwd, title='Vertices file', 
                                        filetypes=[("Comma Separated Values", ".csv")])
    arcs_csv = filedialog.askopenfile(initialdir=cwd, title='Arcs file', 
                                     filetypes=[("Comma Separated Values", ".csv")])
    rules_file = filedialog.askopenfile(initialdir=cwd, title='MulVAL Rules file', 
                                       filetypes=[("Prolog Files", ".P")])
    
    if not vertices_csv or not arcs_csv or not rules_file:
        print("File selection cancelled")
        return
    
    elif 'VERTICES.CSV' not in vertices_csv.name or 'ARCS.CSV' not in arcs_csv.name:
        print("File selection failed: only vertices and arcs in csv format can be loaded.")
        messagebox.showerror("Error", "File selection failed: only vertices and arcs in csv format can be loaded.")
        return
    
    elif 'running_rules.P' not in rules_file.name:
        print("File selection failed: a running_rule.P file must be loaded.")
        messagebox.showerror("Error", "A running_rule.P file must be loaded.")
        return
    
    try: 
        # Create and build attack graph
        ag = AttackGraph()
        ag.load_data(vertices_csv.name, arcs_csv.name)
        attack_graph = ag.build_graph()
        print("Valid parents for node 7:", list(ag.graph.predecessors(7)))
        # Create and build Bayesian network with enhanced probability calculation
        bn_system = SecurityBayesianNetwork(ag, rules_file.name) 
        print(f'\n Rules: {bn_system.probability_calculator.rule_extractor.rules}\n')                                         
        bayesian_network = bn_system.build_network()

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
    finally:
        vertices_csv.close()
        arcs_csv.close()
        if rules_file:
            rules_file.close()

    # Perform inference
    all_results = bn_system.perform_inference()
    print("\nMarginal probabilities for all nodes:")
    for node, result in all_results.items():
        print(f"\nNode {node} ({result['info']['label']}):")
        print(result['probabilities'])
    
    # Target specific node (e.g., root access)
    target_node = 1  # execCode(workStation,root)
    target_results = bn_system.perform_inference(target_node)
    print(f"\nProbability analysis for target node {target_node}:")
    print(target_results[target_node]['probabilities'])

if __name__ == '__main__':
    main()