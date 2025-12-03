import ast
from typing import List, Optional, Any
from dataclasses import dataclass, field

@dataclass
class ReasoningNode(ast.AST):
    # Required fields
    step: str  # The reasoning step description
    
    # Optional fields with defaults
    children: List['ReasoningNode'] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)  # examples -> ["CWE-89", "CWE-79"]
    security_focus: Optional[str] = None  # examples -> "input_validation", "sql_injection"
    metadata: dict = field(default_factory=dict)
    
    # AST compatibility fields (required for ast.AST)
    _fields: tuple = field(default=('step', 'children', 'cwe_ids'), init=False, repr=False)
    _attributes: tuple = field(default=(), init=False, repr=False)

    def add_child(self, child: 'ReasoningNode') -> 'ReasoningNode':
        """Add a child reasoning step and return self for chaining."""
        self.children.append(child)
        return self
    
    def add_children(self, *children: 'ReasoningNode') -> 'ReasoningNode':
        """Add multiple child reasoning steps and return self for chaining."""
        self.children.extend(children)
        return self
    
    def iter_child_nodes(self):
        """Yield all direct child nodes (compatible with ast module)."""
        for child in self.children:
            yield child
    
    def get_depth(self) -> int:
        """Calculate the maximum depth of this reasoning tree."""
        if not self.children:
            return 1
        return 1 + max(child.get_depth() for child in self.children)
    
    def get_all_cwe_ids(self) -> List[str]:
        """Get all CWE IDs covered by this node and its children."""
        all_cwes = set(self.cwe_ids)
        for child in self.children:
            all_cwes.update(child.get_all_cwe_ids())
        return sorted(list(all_cwes))
    
    def count_steps(self) -> int:
        """Count total number of reasoning steps in this tree."""
        return 1 + sum(child.count_steps() for child in self.children)


