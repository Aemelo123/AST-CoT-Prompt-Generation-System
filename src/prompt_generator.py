import ast
from src.reasoning_tree import ReasoningNode


class PromptGenerator:
    # Converts ReasoningNode trees into LLM prompts

    # Explicit security rules mapped to CWE Top 25
    SECURITY_RULES = {
        "CWE-78": {
            "name": "OS Command Injection",
            "rule": "NEVER use os.system() or subprocess with shell=True. Use subprocess.run() with a list of arguments.",
            "safe": "subprocess.run(['cmd', 'arg1'], capture_output=True)",
            "unsafe": "os.system(user_input) or subprocess.run(cmd, shell=True)"
        },
        "CWE-79": {
            "name": "Cross-site Scripting (XSS)",
            "rule": "NEVER use Markup(), mark_safe(), or render_template_string() with user input. Always escape HTML.",
            "safe": "escape(user_input) or use template auto-escaping",
            "unsafe": "Markup(user_input) or render_template_string(user_input)"
        },
        "CWE-89": {
            "name": "SQL Injection",
            "rule": "NEVER concatenate user input into SQL. Always use parameterized queries with placeholders.",
            "safe": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "unsafe": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
        },
        "CWE-94": {
            "name": "Code Injection",
            "rule": "NEVER use eval(), exec(), or compile() with user input. Use ast.literal_eval() for safe parsing.",
            "safe": "ast.literal_eval(user_input) for parsing literals",
            "unsafe": "eval(user_input) or exec(user_input)"
        },
        "CWE-22": {
            "name": "Path Traversal",
            "rule": "NEVER pass user input directly to file operations. Validate paths with os.path.basename().",
            "safe": "safe_path = os.path.join(base_dir, os.path.basename(filename))",
            "unsafe": "open(user_input) or send_file(user_input)"
        },
        "CWE-502": {
            "name": "Unsafe Deserialization",
            "rule": "NEVER use pickle.loads() or yaml.load() with untrusted data. Use json or yaml.safe_load().",
            "safe": "json.loads(data) or yaml.safe_load(data)",
            "unsafe": "pickle.loads(data) or yaml.load(data)"
        },
        "CWE-611": {
            "name": "XML External Entity (XXE)",
            "rule": "NEVER use xml.etree.ElementTree with untrusted XML. Use defusedxml instead.",
            "safe": "from defusedxml.ElementTree import parse",
            "unsafe": "from xml.etree.ElementTree import parse"
        },
        "CWE-798": {
            "name": "Hardcoded Credentials",
            "rule": "NEVER hardcode passwords, API keys, or secrets. Use environment variables.",
            "safe": "api_key = os.environ.get('API_KEY')",
            "unsafe": "api_key = 'sk-1234567890abcdef'"
        }
    }

    def generate_ast_guided_prompt(self, tree: ReasoningNode, task: str) -> str:
        # Generate numbered steps from the reasoning tree
        lines = []
        lines.append(f"Task: {task}")
        lines.append("")
        lines.append("Follow these steps to write secure code:")
        lines.append("")

        # Root step
        lines.append(f"1. {tree.step}")

        # Iterate through CWE branches (level 1 children)
        for i, cwe_branch in enumerate(tree.children, start=1):
            lines.append(f"   1.{i}. {cwe_branch.step}")

            # Iterate through findings (level 2 children)
            for finding in cwe_branch.children:
                lines.append(f"        - {finding.step}")
                concern = finding.metadata.get("security_concern", "")
                if concern:
                    lines.append(f"          Concern: {concern}")

        lines.append("")
        lines.append("Now implement the solution, addressing each security concern above.")

        return "\n".join(lines)

    def generate_explicit_ast_prompt(self, code: str, task: str) -> str:
        # Generate prompt with AST structure containing embedded security rules
        lines = []
        lines.append(f"Task: {task}")
        lines.append("")

        # Parse code to get AST with security annotations
        try:
            tree = ast.parse(code)
            ast_summary = self._get_ast_summary(tree)
            if ast_summary:
                lines.append("## Security-Annotated AST Analysis")
                lines.append("```")
                lines.append(ast_summary)
                lines.append("```")
                lines.append("")
        except SyntaxError:
            pass

        lines.append("## Instructions")
        lines.append("1. Review the security annotations in the AST above")
        lines.append("2. Replace any UNSAFE patterns with the SAFE alternatives shown")
        lines.append("3. Write secure code that follows the guidance embedded in the AST")
        lines.append("")
        lines.append("Now write the secure implementation:")

        return "\n".join(lines)

    def _get_ast_summary(self, tree: ast.AST) -> str:
        # Get AST with embedded security annotations
        lines = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                warning = self._get_security_warning(func_name)
                if warning:
                    lines.append(f"Call: {func_name}()")
                    lines.append(f"  SECURITY: {warning['rule']}")
                    lines.append(f"  SAFE: {warning['safe']}")
                    lines.append(f"  UNSAFE: {warning['unsafe']}")
                    lines.append("")

        if not lines:
            return ast.dump(tree, indent=2)

        # Return annotated AST + full structure
        annotated = "\n".join(lines)
        full_ast = ast.dump(tree, indent=2)
        return f"=== Security-Annotated Calls ===\n{annotated}\n=== Full AST ===\n{full_ast}"

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return ""

    def _get_security_warning(self, func_name: str) -> dict:
        # Map function calls to security rules
        dangerous_patterns = {
            "os.system": "CWE-78",
            "system": "CWE-78",
            "subprocess.run": "CWE-78",
            "subprocess.call": "CWE-78",
            "subprocess.Popen": "CWE-78",
            "eval": "CWE-94",
            "exec": "CWE-94",
            "compile": "CWE-94",
            "cursor.execute": "CWE-89",
            "execute": "CWE-89",
            "pickle.loads": "CWE-502",
            "pickle.load": "CWE-502",
            "yaml.load": "CWE-502",
            "Markup": "CWE-79",
            "mark_safe": "CWE-79",
            "render_template_string": "CWE-79",
            "send_file": "CWE-22",
            "open": "CWE-22",
            "ET.parse": "CWE-611",
            "ElementTree.parse": "CWE-611",
        }

        for pattern, cwe in dangerous_patterns.items():
            if pattern in func_name or func_name == pattern.split(".")[-1]:
                return self.SECURITY_RULES.get(cwe)
        return None

    def _get_detected_rules(self, code: str) -> list:
        """Get only the security rules relevant to detected dangerous calls in the code."""
        detected_cwes = set()
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = self._get_call_name(node)
                    warning = self._get_security_warning(func_name)
                    if warning:
                        # Find which CWE this warning belongs to
                        for cwe_id, rule in self.SECURITY_RULES.items():
                            if rule == warning:
                                detected_cwes.add(cwe_id)
                                break
        except SyntaxError:
            pass

        # Return rules for detected CWEs only
        return [(cwe_id, self.SECURITY_RULES[cwe_id]) for cwe_id in detected_cwes]

    def generate_baseline_prompt(self, code: str, task: str) -> str:
        # Generate natural language prompt with ONLY detected security rules (no AST)
        lines = []
        lines.append(f"Task: {task}")
        lines.append("")

        # Get only rules relevant to the code
        detected_rules = self._get_detected_rules(code)

        if detected_rules:
            lines.append("## Security Guidelines")
            lines.append("")
            for cwe_id, rule in detected_rules:
                lines.append(f"- {rule['name']}: {rule['rule']}")
                lines.append(f"  SAFE: {rule['safe']}")
                lines.append(f"  UNSAFE: {rule['unsafe']}")
                lines.append("")

        lines.append("## Instructions")
        lines.append("1. Review the security guidelines above")
        lines.append("2. Replace any UNSAFE patterns with the SAFE alternatives shown")
        lines.append("3. Write secure code that follows the guidelines")
        lines.append("")
        lines.append("Now write the secure implementation:")

        return "\n".join(lines)
