# TP-Thesis

This thesis regards the threat propagation topic in the field of cybersecurity.
The work in this repository represents a Proof-of-Concept that is able to take the MulVAL output and to create an Attack Bayesian Network to perform inference between nodes and to take the probabilities of a target node.

## Windows Setup

From the work directory:
- To create a new virtual environmet  

        python -m venv ./venv

- To activate the virtual environemnt

        ./venv/Scripts/activate

- To install all the dependencies into the environment

        python -m pip install -r ./requirements.txt

The tool needs to run BRON (https://github.com/ALFA-group/BRON/tree/master) locally in order to work properly, since it is queried for the CVEs' severities.  
The project provides the how to install guide for the Docker to run it locally (it is really easy to set up, even with Windows users using Docker Desktop, which I used for my tests).

## Structure

Structure of the tool:

- `main.py` contains the main program that must be launched, in order to select the MulVAL files and run the tool
- `attack_graph.py` contains the class **AttackGraph** that builds the graph from the MulVAL output files
- `bayesian_network.py` contains the class **SecurityBayesianNetwork** that builds the ABN starting from the AttackGraph and calls the CPD constructor. In the end, it performs the inference
- `arango_client.py` contains the API to query the BRON Database for the CVE severity, represented as weight, in order to build the ABN
- `probability_calculator.py` contains the classes:
  - **MulValRuleExtractor**, that extracts the probabilities from the MulVAL generated file *running_rules.P*
  - **CVSSCalculator**, that launches the query to the BRON Database and normalizes the severity 
  - **ProbabilityCalculator**, performs the TabularCPDs basing on the type of the node within the ABN, taking advantage on the previous classes to determine the probabilities


## Required files:

- **ARCS.CSV** that contains the arcs of the MulVAL generated attack graph
- **VERTICES.CSV** that contatins the vertices of the MulVAL generated attack graph
- **running_rules.P** that contains the rules that are used for the specific attack graph, from the pool of rules in MulVAL

## How to run

Run the Docker image for BRON. It requires some seconds, but then it will be available for the tool. If you want to look at it, it exposes at http://localhost:8529/, the credential are:

username: root
password: changeme

After that, you can launch the main, sequential dialog windows will ask for the required files, that you must select.
It automatically performs building, querying and inferring and outputs the results on the terminal.

The results are the marginal probabilities of each node and the probability to reach a target node in the graph.
The target node is selected in main.py, so you need to modify it.