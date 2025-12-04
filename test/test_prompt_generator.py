from src.ast_parser import ASTSecurityParser
from src.tree_builder import ReasoningTreeBuilder
from src.prompt_generator import PromptGenerator


def test_prompt_generator():
    # Parse vulnerable code
    parser = ASTSecurityParser()
    code = """
user_input = input("Enter: ")
eval(user_input)
os.system(user_input)
"""
    findings = parser.parse(code)

    # Build tree
    builder = ReasoningTreeBuilder()
    tree = builder.build(findings)

    # Generate prompts
    generator = PromptGenerator()
    task = "Write a function that executes user commands safely"

    # AST-guided prompt
    ast_prompt = generator.generate_ast_guided_prompt(tree, task)
    print("=== AST-GUIDED PROMPT ===")
    print(ast_prompt)
    print()

    # Baseline prompt
    baseline_prompt = generator.generate_baseline_prompt(task)
    print("=== BASELINE PROMPT ===")
    print(baseline_prompt)

    print("\nPASS - Prompt generator works")


if __name__ == "__main__":
    test_prompt_generator()
