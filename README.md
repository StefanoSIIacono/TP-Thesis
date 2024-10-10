# TP-Thesis

## Windows Setup

From the work directory:
- To create a new virtual environmet  

        python -m venv ./venv

- To activate the virtual environemnt

        ./venv/Scripts/activate

- To install all the dependencies into the environment

        python -m pip install -r ./requirements.txt

## Structure
It is only an initial configuration that will have several and consistent changed in the future.

- *Classes* contains the classes that have been created to face the problem (WIP)
    - `asset.py` contains the class Asset
    - `capecdict.py` contains the class CapecDict, including all the information about a list of capecs
- *Constants* contains some defined constants (WIP)
    - `parts.py` contains some constants to define the type of CPE
- `BN.py` contains the snippet to create a bayesian network (not yet update to latest version discussed)
- `nvd-API.ipynb` contains some code to automatize the process to retrieve capecs details (WIP)
- `nvd-API.py` starting creating a Python file containing code in *nvd-API.ipynb*