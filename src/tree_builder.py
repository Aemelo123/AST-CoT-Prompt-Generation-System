from typing import List, Dict
from src.reasoning_tree import ReasoningNode
from src.ast_parser import SecurityNode


# Human-readable names for each CWE
CWE_NAMES = {
    "CWE-94": "Code Injection",
    "CWE-78": "OS Command Injection",
    "CWE-89": "SQL Injection",
    "CWE-502": "Unsafe Deserialization",
    "CWE-22": "Path Traversal",
}


class ReasoningTreeBuilder:
    # Builds a ReasoningNode tree from SecurityNode findings

    def build(self, findings: List[SecurityNode]) -> ReasoningNode:
        # Create root node
        root = ReasoningNode(
            step="Analyze code for security vulnerabilities",
            cwe_ids=[],
            security_focus="security_analysis"
        )

        # Group findings by CWE
        grouped = self._group_by_cwe(findings)

        # Create a branch for each CWE type
        for cwe_id, cwe_findings in grouped.items():
            cwe_name = CWE_NAMES.get(cwe_id, cwe_id)

            cwe_branch = ReasoningNode(
                step=f"Check for {cwe_name} ({cwe_id})",
                cwe_ids=[cwe_id],
                security_focus=cwe_id.lower().replace("-", "_")
            )

            # Add each finding as a child
            for finding in cwe_findings:
                finding_node = ReasoningNode(
                    step=f"Found {finding.name}() on line {finding.line_number} - {finding.risk_level.value.upper()} risk",
                    cwe_ids=[cwe_id],
                    security_focus=finding.name,
                    metadata={
                        "line_number": finding.line_number,
                        "code_snippet": finding.code_snippet,
                        "security_concern": finding.security_concern
                    }
                )
                cwe_branch.add_child(finding_node)

            root.add_child(cwe_branch)

        return root

    def _group_by_cwe(self, findings: List[SecurityNode]) -> Dict[str, List[SecurityNode]]:
        # Group findings by their CWE ID
        grouped = {}
        for finding in findings:
            for cwe_id in finding.cwe_ids:
                if cwe_id not in grouped:
                    grouped[cwe_id] = []
                grouped[cwe_id].append(finding)
        return grouped
