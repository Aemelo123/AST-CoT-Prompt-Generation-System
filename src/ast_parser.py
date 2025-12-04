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
    """
    AST-based security vulnerability detector targeting CWE Top 25.

    Detected CWEs:
    - CWE-78: OS Command Injection
    - CWE-79: Cross-site Scripting (XSS)
    - CWE-89: SQL Injection
    - CWE-94: Code Injection
    - CWE-22: Path Traversal
    - CWE-502: Deserialization of Untrusted Data
    - CWE-611: XXE (XML External Entity)
    - CWE-798: Hardcoded Credentials
    """

    # CWE-94: Code Injection - dangerous functions that execute arbitrary code
    CODE_INJECTION_FUNCTIONS = {'eval', 'exec', 'compile'}

    # CWE-78: OS Command Injection - functions that execute shell commands
    COMMAND_INJECTION_FUNCTIONS = {'system', 'popen', 'call', 'run', 'Popen'}
    COMMAND_INJECTION_MODULES = {'os', 'subprocess'}

    # CWE-89: SQL Injection - database query functions
    SQL_FUNCTIONS = {'execute', 'executemany', 'raw', 'rawQuery'}

    # CWE-502: Deserialization - unsafe modules (pickle, marshal, shelve)
    UNSAFE_DESERIALIZE_MODULES = {'pickle', 'marshal', 'shelve', 'dill', 'cloudpickle'}

    # CWE-611: XXE - unsafe XML parsing
    UNSAFE_XML_FUNCTIONS = {'parse', 'fromstring', 'iterparse'}
    UNSAFE_XML_MODULES = {'xml.etree.ElementTree', 'xml.dom', 'lxml'}
    SAFE_XML_MODULES = {'defusedxml'}

    # CWE-502: Eval injection via yaml.load without SafeLoader
    UNSAFE_YAML_LOAD = {'load'}

    # CWE-22: Path Traversal - file operations that may access restricted paths
    PATH_TRAVERSAL_FUNCTIONS = {'send_file', 'send_from_directory'}

    # CWE-79: XSS - functions that render unescaped HTML
    XSS_UNSAFE_FUNCTIONS = {'Markup', 'mark_safe', 'SafeString', 'format_html'}
    XSS_TEMPLATE_FUNCTIONS = {'render_template_string'}

    # CWE-798: Hardcoded Credentials - assignment patterns to detect
    CREDENTIAL_KEYWORDS = {'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
                           'token', 'auth_token', 'access_token', 'private_key'}

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
        # Check for CWE-798: Hardcoded Credentials in assignments
        if isinstance(node, ast.Assign):
            self._check_hardcoded_credentials(node)
            return

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

        # Check for CWE-78: OS Command Injection
        elif self._is_command_injection(node, func_name):
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-78"],
                security_concern=f"Command injection risk: {func_name}() executes shell commands",
                code_snippet=self._get_code_snippet(node)
            ))

        # Check for CWE-89: SQL Injection (only if not parameterized)
        elif self._is_unsafe_sql(node, func_name):
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-89"],
                security_concern=f"SQL injection risk: {func_name}() may execute unsafe queries",
                code_snippet=self._get_code_snippet(node)
            ))

        # Check for CWE-502: Unsafe Deserialization (pickle, marshal, etc.)
        elif self._is_unsafe_deserialize(node, func_name):
            module_name = self._get_module_name(node)
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-502"],
                security_concern=f"Unsafe deserialization: {module_name}.{func_name}() can execute arbitrary code",
                code_snippet=self._get_code_snippet(node)
            ))

        # Check for CWE-611: XXE via unsafe XML parsing
        elif self._is_unsafe_xml(node, func_name):
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-611"],
                security_concern=f"XXE risk: use defusedxml instead of {func_name}()",
                code_snippet=self._get_code_snippet(node)
            ))

        # Check for CWE-502: yaml.load without SafeLoader
        elif self._is_unsafe_yaml(node, func_name):
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-502"],
                security_concern="yaml.load() can execute arbitrary code, use yaml.safe_load()",
                code_snippet=self._get_code_snippet(node)
            ))

        # Check for CWE-22: Path Traversal
        elif func_name in self.PATH_TRAVERSAL_FUNCTIONS:
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-22"],
                security_concern=f"Path traversal risk: {func_name}() may expose files outside intended directory",
                code_snippet=self._get_code_snippet(node)
            ))

        # Check for CWE-79: XSS via unsafe HTML rendering
        elif func_name in self.XSS_UNSAFE_FUNCTIONS:
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-79"],
                security_concern=f"XSS risk: {func_name}() marks content as safe without escaping",
                code_snippet=self._get_code_snippet(node)
            ))

        # Check for CWE-79: XSS via render_template_string
        elif func_name in self.XSS_TEMPLATE_FUNCTIONS:
            self.security_nodes.append(SecurityNode(
                node_type="Call",
                name=func_name,
                line_number=node.lineno,
                risk_level=SecurityRiskLevel.HIGH,
                cwe_ids=["CWE-79"],
                security_concern=f"XSS/SSTI risk: {func_name}() with user input enables template injection",
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
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _get_module_name(self, node: ast.Call) -> str:
        # Get the module/object the function is called on (e.g., "pickle" from pickle.loads)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return node.func.value.id
        return ""

    def _is_unsafe_deserialize(self, node: ast.Call, func_name: str) -> bool:
        # Only flag loads/load if called on unsafe modules like pickle
        if func_name not in {'loads', 'load'}:
            return False
        module = self._get_module_name(node)
        return module in self.UNSAFE_DESERIALIZE_MODULES

    def _is_unsafe_xml(self, node: ast.Call, func_name: str) -> bool:
        # Flag xml parsing when called on unsafe modules (ET.fromstring, etc.)
        if func_name not in self.UNSAFE_XML_FUNCTIONS:
            return False
        module = self._get_module_name(node)
        # Only flag if explicitly called on known unsafe modules
        # Skip direct calls (like fromstring()) since we can't track imports
        if not module:
            return False
        # Safe if module contains 'defused' or the code uses defusedxml
        code_snippet = self._get_code_snippet(node)
        if 'defused' in module.lower() or 'defused' in code_snippet.lower():
            return False
        # Flag known unsafe module aliases
        return module in {'ET', 'ElementTree', 'etree', 'xml', 'dom', 'lxml'}

    def _is_unsafe_yaml(self, node: ast.Call, func_name: str) -> bool:
        # Flag yaml.load() but not yaml.safe_load()
        if func_name != 'load':
            return False
        module = self._get_module_name(node)
        if module != 'yaml':
            return False
        # Check if it's safe_load (which is fine)
        code_snippet = self._get_code_snippet(node)
        return 'safe_load' not in code_snippet

    def _is_command_injection(self, node: ast.Call, func_name: str) -> bool:
        # Check if it's a command injection function called on os/subprocess
        if func_name not in self.COMMAND_INJECTION_FUNCTIONS:
            return False
        module = self._get_module_name(node)
        # Direct calls like system() or Popen() without module prefix
        if not module and func_name in {'system', 'Popen'}:
            return True
        # Module-qualified calls like os.system(), subprocess.run()
        if module not in self.COMMAND_INJECTION_MODULES:
            return False
        # Check for shell=True which is dangerous
        code_snippet = self._get_code_snippet(node)
        # subprocess.run with list args (no shell=True) is safe
        if func_name in {'run', 'call', 'Popen'} and 'shell=True' not in code_snippet:
            return False
        return True

    def _is_unsafe_sql(self, node: ast.Call, func_name: str) -> bool:
        # Only flag SQL functions that appear to use string concatenation
        if func_name not in self.SQL_FUNCTIONS:
            return False
        code_snippet = self._get_code_snippet(node)
        # Safe patterns: parameterized queries use ? or %s placeholders with separate args
        # Unsafe patterns: string concatenation (+) or f-strings
        if '+' in code_snippet or 'f"' in code_snippet or "f'" in code_snippet:
            return True
        # If query has only one argument, it might be unsafe
        if len(node.args) == 1:
            # Check if the single arg is a string literal (safe) or expression (unsafe)
            if isinstance(node.args[0], ast.BinOp):
                return True
            if isinstance(node.args[0], ast.JoinedStr):  # f-string
                return True
        return False

    def _check_hardcoded_credentials(self, node: ast.Assign):
        # Check for hardcoded credentials in variable assignments
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id.lower()
            # Check if variable name contains credential keywords
            for keyword in self.CREDENTIAL_KEYWORDS:
                if keyword in var_name:
                    # Only flag if assigned a string literal (hardcoded)
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        # Skip empty strings and obvious placeholders
                        value = node.value.value
                        if value and value not in {'', 'None', 'null', 'TODO', 'CHANGEME'}:
                            self.security_nodes.append(SecurityNode(
                                node_type="Assign",
                                name=target.id,
                                line_number=node.lineno,
                                risk_level=SecurityRiskLevel.HIGH,
                                cwe_ids=["CWE-798"],
                                security_concern=f"Hardcoded credential: '{target.id}' contains sensitive value",
                                code_snippet=self._get_code_snippet(node)
                            ))
                    break
