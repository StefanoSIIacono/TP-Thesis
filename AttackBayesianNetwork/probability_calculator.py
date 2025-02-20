# probability_calculator.py
from pgmpy.factors.discrete import TabularCPD
import numpy as np
from itertools import product
import re
import json
import os
from arango_client import get_cve_severity

class MulValRuleExtractor:
    """Extract and manage probability rules from MulVAL"""
    def __init__(self, rules_file: str):
        self.rules = {}
        if rules_file and os.path.exists(rules_file):
            self._extract_rules(rules_file)

    def _extract_rules(self, rules_file):
        """Extract probability rules from MulVAL Prolog file"""
        with open(rules_file, 'r') as f:
            content = f.read()
        
        rule_pattern = r"interaction_rule\(\s*\((.*?)\),\s*rule_desc\('(.*?)',\s*([\d.]+)\)\)"
        matches = re.finditer(rule_pattern, content, re.DOTALL)
        
        for match in matches:
            rule_head = match.group(1).split(':-')[0].strip()
            description = match.group(2)
            probability = float(match.group(3))
            
            self.rules[rule_head] = {
                'description': description,
                'probability': probability
            }

    def get_rule_probability(self, predicate):
        """Get probability for a given predicate"""
        for rule_head, rule_info in self.rules.items():
            if rule_head.split('(')[0] in predicate:
                return rule_info['probability']
        return None

class CVSSCalculator:
    """Handle CVSS score calculations and conversions"""
    @staticmethod
    def normalize_cvss(cvss_score):
        """Convert CVSS score (0-10) to probability (0-1)"""
        return cvss_score / 10.0

    @staticmethod
    def get_cvss_probability(vuln_id):
        """Get probability from CVSS score"""

        score = get_cve_severity(vuln_id)
        return CVSSCalculator.normalize_cvss(score)

class ProbabilityCalculator:
    """Handle probability calculations for different node types"""
    
    def __init__(self, rules_file=None):
        self.rule_extractor = MulValRuleExtractor(rules_file)
        
    def calculate_cpd(self, node: int, node_info: dict, parents: list) -> TabularCPD:
        """Calculate CPD based on node type and characteristics"""
        if node_info['type'] == 'LEAF':
            return self._create_leaf_cpd(node, node_info)
        
        elif parents:
            if node_info['type'] == 'AND':
                return self._create_and_cpd(node, node_info, parents)
            elif node_info['type'] == 'OR':
                return self._create_or_cpd(node, node_info, parents)
        
        else:
            return self._create_root_cpd(node, node_info)

    def _get_vulnerability_probability(self, vuln_label: str) -> float:
        """Calculate probability for vulnerability nodes"""
        # Extract vulnerability ID
        vuln_match = re.search(r"vulExists\([^,]+,'([^']+)'", vuln_label)
        if vuln_match:
            vuln_id = vuln_match.group(1)
            if vuln_id.startswith("CAN-"):
                cve_id = vuln_id.replace("CAN-", "CVE-", 1)
            else:
                cve_id = vuln_id
            return CVSSCalculator.get_cvss_probability(cve_id)
        
        # Get rule-based probability if available
        rule_prob = self.rule_extractor.get_rule_probability(vuln_label)
        if rule_prob is not None:
            return rule_prob
            
        return 0.5  # Default probability

    def _create_leaf_cpd(self, node: int, node_info: dict) -> TabularCPD:
        """Create CPD for leaf nodes with enhanced probability calculation"""
        base_prob = node_info['value']
        
        if 'vulExists' in node_info['label']:
            base_prob = self._get_vulnerability_probability(node_info['label'])
        elif node_info['value'] == 1:  # Explicit LEAF node
            base_prob = 1.0
        else:
            rule_prob = self.rule_extractor.get_rule_probability(node_info['label'])
            if rule_prob is not None:
                base_prob = rule_prob
        
        return TabularCPD(
            variable=node,
            variable_card=2,
            values=[[1 - base_prob], [base_prob]]
        )

    def _create_and_cpd(self, node: int, node_info: dict, parents: list) -> TabularCPD:
        """Create CPD for AND nodes with rule-based probabilities"""
        n_parents = len(parents)
        cpt_values = []
        
        # Get rule probability if available
        rule_prob = self.rule_extractor.get_rule_probability(node_info['label'])
        success_prob = rule_prob if rule_prob is not None else 0.9
        
        for parent_combination in product([0, 1], repeat=n_parents):
            if all(parent_combination):
                prob_true = success_prob
            else:
                prob_true = 0.1
            cpt_values.append([1 - prob_true, prob_true])
        
        return TabularCPD(
            variable=node,
            variable_card=2,
            values=np.array(cpt_values).T.tolist(),
            evidence=parents,
            evidence_card=[2] * n_parents
        )

    def _create_or_cpd(self, node: int, node_info: dict, parents: list) -> TabularCPD:
        """Create CPD for OR nodes with rule-based probabilities"""
        n_parents = len(parents)
        cpt_values = []
        
        # Get rule probability if available
        rule_prob = self.rule_extractor.get_rule_probability(node_info['label'])
        max_prob = rule_prob if rule_prob is not None else 0.9
        
        for parent_combination in product([0, 1], repeat=n_parents):
            true_parents = sum(parent_combination)
            if true_parents > 0:
                # Scale probability based on number of true parents
                prob_true = min(max_prob, 0.3 + ((max_prob - 0.3) * true_parents / n_parents))
            else:
                prob_true = 0.1
            cpt_values.append([1 - prob_true, prob_true])
        
        return TabularCPD(
            variable=node,
            variable_card=2,
            values=np.array(cpt_values).T.tolist(),
            evidence=parents,
            evidence_card=[2] * n_parents
        )

    def _create_root_cpd(self, node: int, node_info: dict) -> TabularCPD:
        """Create CPD for root nodes with rule-based probabilities"""
        rule_prob = self.rule_extractor.get_rule_probability(node_info['label'])
        base_prob = rule_prob if rule_prob is not None else 0.2
        
        return TabularCPD(
            variable=node,
            variable_card=2,
            values=[[1 - base_prob], [base_prob]]
        )