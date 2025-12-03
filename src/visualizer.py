from typing import List
from .reasoning_tree import ReasoningNode


class ReasoningTreeVisualizer:
    """
    Creates visual representations of reasoning trees.
    """
    
    def __init__(self, show_cwe: bool = True, show_focus: bool = False):
        self.show_cwe = show_cwe
        self.show_focus = show_focus
    
    def visualize(self, node: ReasoningNode) -> str:
        lines = []
        self._visualize_node(node, lines, "", True)
        return '\n'.join(lines)
    
    def _visualize_node(self, node: ReasoningNode, lines: List[str], prefix: str, is_last: bool):
        # Create the branch character
        branch = "└── " if is_last else "├── "
        
        # Build the node label
        label = node.step
        
        # Add CWE IDs if enabled and present
        if self.show_cwe and node.cwe_ids:
            label += f" [{', '.join(node.cwe_ids)}]"
        
        # Add security focus if enabled and present
        if self.show_focus and node.security_focus:
            label += f" ({node.security_focus})"
        
        # Add this node to the output
        lines.append(f"{prefix}{branch}{label}")
        
        # Prepare prefix for children
        extension = "    " if is_last else "│   "
        child_prefix = prefix + extension
        
        # Visualize all children
        for i, child in enumerate(node.children):
            is_last_child = (i == len(node.children) - 1)
            self._visualize_node(child, lines, child_prefix, is_last_child)


def visualize_tree(node: ReasoningNode, show_cwe: bool = True, show_focus: bool = False) -> str:
    visualizer = ReasoningTreeVisualizer(show_cwe=show_cwe, show_focus=show_focus)
    return visualizer.visualize(node)