import pandas as pd
import networkx as nx
from tkinter import filedialog

def show_graph(graph):
    '''Show graph'''

    print("Nodes:")
    for node in graph.nodes(data=True):
        print(f'{node}')

    print("\nEdges:")
    for edge in graph.edges():
        print(f'{edge}')

def load_graph(vertices_csv, arcs_csv):
    '''Load data from the MulVAL attack graph'''

    vertices = pd.read_csv(vertices_csv, header=None, names=['ID', 'Label', 'Type', 'InitialValue'])
    arcs = pd.read_csv(arcs_csv, header=None, names=['Parent', 'Child', 'Weight'])
    return vertices, arcs

def compute_attack_graph(vertices, arcs):
    '''Create the attack graph'''

    graph = nx.DiGraph()

    for _, row in vertices.iterrows():
        graph.add_node(row['ID'], label=row['Label'], type=row['Type'], value=row['InitialValue'])

    for _, row in arcs.iterrows():
        graph.add_edge(row['Parent'], row['Child'])

    return graph

def main ():
    import os
    cwd = os.getcwd()

    vertices_csv = filedialog.askopenfile(initialdir=cwd, title='Vertices file', filetypes=[("Comma Separated Values", ".csv")])
    arcs_csv = filedialog.askopenfile(initialdir=cwd, title='Arcs file', filetypes=[("Comma Separated Values", ".csv")])

    vertices, arcs = load_graph(vertices_csv, arcs_csv)
    
    graph = compute_attack_graph(vertices, arcs)

    show_graph(graph)

if __name__ == '__main__':
    main()
