from src.reasoning_tree import ReasoningNode
from src.visualizer import visualize_tree  # Already added!
import ast


def test_basic_tree():
    """Test creating a simple reasoning tree"""
    
    # Create a simple tree
    root = ReasoningNode(
        step="Analyze code for security vulnerabilities",
        security_focus="security_analysis"
    )
    
    # Add children
    root.add_child(
        ReasoningNode(
            step="Check for SQL injection",
            cwe_ids=["CWE-89"],
            security_focus="sql_injection"
        )
    )
    
    root.add_child(
        ReasoningNode(
            step="Check for XSS vulnerabilities", 
            cwe_ids=["CWE-79"],
            security_focus="xss"
        )
    )
    
    # Test the tree
    print("=== Basic Reasoning Tree Test ===")
    print(f"Root step: {root.step}")
    print(f"Number of children: {len(root.children)}")
    print(f"Tree depth: {root.get_depth()}")
    print(f"Total steps: {root.count_steps()}")
    print(f"CWE IDs covered: {root.get_all_cwe_ids()}")
    
    print("\nChildren:")
    for i, child in enumerate(root.iter_child_nodes(), 1):
        print(f"  {i}. {child.step} (CWE: {child.cwe_ids})")
    
    # ADD THESE TWO LINES:
    print("\n=== Tree Visualization ===")
    print(visualize_tree(root, show_cwe=True, show_focus=True))


def test_nested_tree():
    """Test creating a multi-level tree"""
    
    # Create a deeper tree
    root = ReasoningNode(
        step="Secure code generation"
    )
    
    # Level 1
    analysis = ReasoningNode(step="Code analysis")
    analysis.add_children(
        ReasoningNode(step="Parse syntax"),
        ReasoningNode(step="Identify patterns")
    )
    
    # Level 1
    vulnerability = ReasoningNode(step="Vulnerability detection")
    vulnerability.add_children(
        ReasoningNode(step="Check SQL injection", cwe_ids=["CWE-89"]),
        ReasoningNode(step="Check XSS", cwe_ids=["CWE-79"]),
        ReasoningNode(step="Check input validation", cwe_ids=["CWE-20"])
    )
    
    root.add_children(analysis, vulnerability)
    
    print("\n=== Nested Reasoning Tree Test ===")
    print(f"Tree depth: {root.get_depth()}")
    print(f"Total steps: {root.count_steps()}")
    print(f"All CWE IDs: {root.get_all_cwe_ids()}")
    
    # REPLACE lines 79-81 WITH THESE TWO LINES:
    print("\n=== Tree Visualization ===")
    print(visualize_tree(root, show_cwe=True, show_focus=False))


if __name__ == "__main__":
    test_basic_tree()
    test_nested_tree()