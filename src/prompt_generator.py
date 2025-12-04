from src.reasoning_tree import ReasoningNode


class PromptGenerator:
    # Converts ReasoningNode trees into LLM prompts

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

    def generate_baseline_prompt(self, task: str) -> str:
        # Generate a generic natural language CoT prompt (no AST guidance)
        lines = []
        lines.append(f"Task: {task}")
        lines.append("")
        lines.append("Let's think step by step about security.")
        lines.append("First, consider what vulnerabilities might exist in this type of code.")
        lines.append("Then, think about how to write secure code.")
        lines.append("Finally, implement the solution carefully.")
        lines.append("")
        lines.append("Now implement the solution with security in mind.")

        return "\n".join(lines)
