from src.ast_parser import ASTSecurityParser
from src.tree_builder import ReasoningTreeBuilder
from src.prompt_generator import PromptGenerator


class Pipeline:
    # Runs the full AST-CoT prompt generation pipeline

    def __init__(self, use_explicit_rules: bool = False):
        self.parser = ASTSecurityParser()
        self.tree_builder = ReasoningTreeBuilder()
        self.prompt_generator = PromptGenerator()
        self.use_explicit_rules = use_explicit_rules

    def run(self, code: str, task: str) -> tuple:
        # Step 1: Parse code for security issues
        findings = self.parser.parse(code)

        # Step 2: Build reasoning tree
        tree = self.tree_builder.build(findings)

        # Step 3: Generate prompts based on mode
        if self.use_explicit_rules:
            # New approach: explicit AST + security rules
            ast_prompt = self.prompt_generator.generate_explicit_ast_prompt(code, task)
        else:
            # Original approach: reasoning tree
            ast_prompt = self.prompt_generator.generate_ast_guided_prompt(tree, task)

        baseline_prompt = self.prompt_generator.generate_baseline_prompt(code, task)

        return ast_prompt, baseline_prompt

    def get_findings_count(self, code: str) -> int:
        findings = self.parser.parse(code)
        return len(findings)
