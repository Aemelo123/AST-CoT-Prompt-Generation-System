"""
Tests for AST Security Parser
"""

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

    # should be no security findings yet
    assert isinstance(results, list)
    assert len(results) == 0  # No detection logic yet
    print("PASS - Basic parsing works")


def test_invalid_syntax():
    """Test that parser handles syntax errors gracefully."""
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


if __name__ == "__main__":
    test_basic_parsing()
    test_invalid_syntax()
    test_code_snippet_extraction()
    print("\nAll Commit 1 tests passed!")
