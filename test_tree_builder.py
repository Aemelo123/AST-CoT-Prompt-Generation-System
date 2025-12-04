from src.ast_parser import ASTSecurityParser
from src.tree_builder import ReasoningTreeBuilder
from src.visualizer import ReasoningTreeVisualizer


def test_tree_builder():
    # Parse some vulnerable code
    parser = ASTSecurityParser()
    code = """
user_input = input("Enter command: ")
eval(user_input)
os.system(user_input)
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
    findings = parser.parse(code)

    # Build the reasoning tree
    builder = ReasoningTreeBuilder()
    tree = builder.build(findings)

    # Check the tree structure
    assert tree.step == "Analyze code for security vulnerabilities"
    assert len(tree.children) == 3  # 3 CWE types found

    # Check CWE IDs are collected
    all_cwes = tree.get_all_cwe_ids()
    assert "CWE-94" in all_cwes
    assert "CWE-78" in all_cwes
    assert "CWE-89" in all_cwes

    print("PASS - Tree builder works")

    # Visualize the tree
    visualizer = ReasoningTreeVisualizer()
    print("\nGenerated Tree:")
    print(visualizer.visualize(tree))


if __name__ == "__main__":
    test_tree_builder()
