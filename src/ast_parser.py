import ast
from typing import List
from dataclasses import dataclass, field
from enum import Enum


class SecurityRiskLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityNode:
    node_type: str  # e.g., "FunctionDef", "Call", "Assign"
    name: str  # Function name, variable name, etc.
    line_number: int
    risk_level: SecurityRiskLevel
    cwe_ids: List[str]  # Potential CWE vulnerabilities
    security_concern: str  # Human-readable concern
    code_snippet: str  # The actual code
    children: List['SecurityNode'] = field(default_factory=list)


class ASTSecurityParser:
    def __init__(self):
        self.security_nodes: List[SecurityNode] = []
        self.source_lines: List[str] = []

    def parse(self, source_code: str) -> List[SecurityNode]:
        self.source_lines = source_code.split('\n')
        self.security_nodes = []

        try:
            tree = ast.parse(source_code)
            # using ast.walk to traverse.. recursive seemed like it'll be hard to debug
            for node in ast.walk(tree):
                self._analyze_node(node)
        except SyntaxError as e:
            raise ValueError(f"Invalid Python syntax: {e}")

        return self.security_nodes

    def _analyze_node(self, node: ast.AST):
        
        # TODO: Add security pattern detection in future commits

        pass

    def _get_code_snippet(self, node: ast.AST) -> str:
        if not hasattr(node, 'lineno'):
            return ""

        line_num = node.lineno - 1  # 0-indexed
        if 0 <= line_num < len(self.source_lines):
            return self.source_lines[line_num].strip()
        return ""
