from src.pipeline import Pipeline
from src.llm_client import LLMClient


def test_llm_integration():
    # Setup
    pipeline = Pipeline()
    llm = LLMClient()

    # Example vulnerable code to analyze
    code = """
user_input = input("Enter: ")
eval(user_input)
"""

    task = "Write a secure function that safely evaluates user expressions"

    # Generate both prompts
    ast_prompt, baseline_prompt = pipeline.run(code, task)

    print("Testing Claude...")
    claude_ast_response = llm.generate_code(ast_prompt, model="claude")
    claude_baseline_response = llm.generate_code(baseline_prompt, model="claude")

    print("\n" + "="*50)
    print("CLAUDE - AST-GUIDED RESPONSE")
    print("="*50)
    print(claude_ast_response[:500] + "...")

    print("\n" + "="*50)
    print("CLAUDE - BASELINE RESPONSE")
    print("="*50)
    print(claude_baseline_response[:500] + "...")

    print("\nTesting GPT-4o...")
    gpt_ast_response = llm.generate_code(ast_prompt, model="gpt")
    gpt_baseline_response = llm.generate_code(baseline_prompt, model="gpt")

    print("\n" + "="*50)
    print("GPT-4o - AST-GUIDED RESPONSE")
    print("="*50)
    print(gpt_ast_response[:500] + "...")

    print("\n" + "="*50)
    print("GPT-4o - BASELINE RESPONSE")
    print("="*50)
    print(gpt_baseline_response[:500] + "...")

    print("\nPASS - LLM integration works")


if __name__ == "__main__":
    test_llm_integration()
