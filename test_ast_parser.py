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


if __name__ == "__main__":
    test_basic_parsing()
    test_invalid_syntax()
    test_code_snippet_extraction()
    test_cwe94_code_injection()
    print("\nAll tests passed!")
