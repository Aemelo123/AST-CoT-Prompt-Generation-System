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
    # CWE-94: Code Injection - dangerous functions that execute arbitrary code
    CODE_INJECTION_FUNCTIONS = {'eval', 'exec', 'compile'}

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
        # Only check Call nodes (function calls)
        if not isinstance(node, ast.Call):
            return

        func_name = self._get_function_name(node)
        if not func_name:
            return

        # Check for CWE-94: Code Injection
        if func_name in self.CODE_INJECTION_FUNCTIONS:
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-94"],
                security_concern=f"Code injection risk: {func_name}() executes arbitrary code",
                code_snippet=self._get_code_snippet(node)
            ))

    def _get_code_snippet(self, node: ast.AST) -> str:
        if not hasattr(node, 'lineno'):
            return ""

        line_num = node.lineno - 1  # 0-indexed
        if 0 <= line_num < len(self.source_lines):
            return self.source_lines[line_num].strip()
        return ""

    def _get_function_name(self, node: ast.Call) -> str:
        # Simple case: eval(), exec(), etc.
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""
