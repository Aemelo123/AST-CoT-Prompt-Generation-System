from src.ast_parser import ASTSecurityParser, SecurityNode, SecurityRiskLevel


def test_basic_parsing():
    parser = ASTSecurityParser()

    code = """
def hello_world():
    print("Hello, World!")
    return 42
"""

    # Should parse without errors
    results = parser.parse(code)

    # Safe code should have no security findings
    assert isinstance(results, list)
    assert len(results) == 0  # No dangerous patterns in this code
    print("PASS - Basic parsing works")


def test_invalid_syntax():
    parser = ASTSecurityParser()

    code = """
def broken(
    print("missing closing paren"
"""

    try:
        parser.parse(code)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid Python syntax" in str(e)
        print("PASS - Syntax error handling works")


def test_code_snippet_extraction():
    parser = ASTSecurityParser()

    code = """
x = 1
y = 2
z = 3
"""

    parser.source_lines = code.split('\n')

    # Create a mock node
    import ast
    tree = ast.parse(code)

    # Get first assignment node
    first_assign = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            first_assign = node
            break

    assert first_assign is not None
    snippet = parser._get_code_snippet(first_assign)
    assert "x = 1" in snippet
    print("PASS - Code snippet extraction works")


def test_cwe94_code_injection():
    # Test detection of CWE-94: Code Injection (eval, exec, compile).
    parser = ASTSecurityParser()

    code = """
user_input = input("Enter code: ")
result = eval(user_input)
exec("print('hello')")
compiled = compile(user_input, '<string>', 'exec')
"""

    results = parser.parse(code)

    # Should detect 3 dangerous calls: eval, exec, compile
    assert len(results) == 3, f"Expected 3 findings, got {len(results)}"

    # All should be CWE-94
    for node in results:
        assert "CWE-94" in node.cwe_ids
        assert node.risk_level == SecurityRiskLevel.HIGH
        assert node.name in ("eval", "exec", "compile")

    print("PASS - CWE-94 code injection detection works")


def test_cwe78_command_injection():
    # Test detection of CWE-78: OS Command Injection
    parser = ASTSecurityParser()

    code = """
import os
import subprocess
os.system("ls -la")
subprocess.call(["ls", "-la"])
subprocess.run("echo hello", shell=True)
"""

    results = parser.parse(code)
    cwe78_results = [r for r in results if "CWE-78" in r.cwe_ids]

    assert len(cwe78_results) == 3, f"Expected 3 CWE-78 findings, got {len(cwe78_results)}"
    print("PASS - CWE-78 command injection detection works")


def test_cwe89_sql_injection():
    # Test detection of CWE-89: SQL Injection
    parser = ASTSecurityParser()

    code = """
import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.executemany("INSERT INTO users VALUES (?)", data)
"""

    results = parser.parse(code)
    cwe89_results = [r for r in results if "CWE-89" in r.cwe_ids]

    assert len(cwe89_results) == 2, f"Expected 2 CWE-89 findings, got {len(cwe89_results)}"
    print("PASS - CWE-89 SQL injection detection works")


def test_cwe502_deserialization():
    # Test detection of CWE-502: Deserialization of Untrusted Data
    parser = ASTSecurityParser()

    code = """
import pickle
import yaml
data = pickle.loads(untrusted_data)
config = yaml.load(open("config.yaml"))
"""

    results = parser.parse(code)
    cwe502_results = [r for r in results if "CWE-502" in r.cwe_ids]

    assert len(cwe502_results) == 2, f"Expected 2 CWE-502 findings, got {len(cwe502_results)}"
    print("PASS - CWE-502 deserialization detection works")


def test_cwe22_path_traversal():
    # Test detection of CWE-22: Path Traversal
    parser = ASTSecurityParser()

    code = """
user_file = input("Enter filename: ")
f = open(user_file, "r")
content = f.read()
"""

    results = parser.parse(code)
    cwe22_results = [r for r in results if "CWE-22" in r.cwe_ids]

    assert len(cwe22_results) == 2, f"Expected 2 CWE-22 findings, got {len(cwe22_results)}"
    assert cwe22_results[0].risk_level == SecurityRiskLevel.MEDIUM
    print("PASS - CWE-22 path traversal detection works")


if __name__ == "__main__":
    test_basic_parsing()
    test_invalid_syntax()
    test_code_snippet_extraction()
    test_cwe94_code_injection()
    test_cwe78_command_injection()
    test_cwe89_sql_injection()
    test_cwe502_deserialization()
    test_cwe22_path_traversal()
    print("\nAll tests passed!")
