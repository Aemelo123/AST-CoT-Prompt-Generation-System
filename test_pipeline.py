from src.pipeline import Pipeline


def test_pipeline():
    pipeline = Pipeline()

    code = """
import os
import pickle

user_input = input("Enter command: ")
eval(user_input)
os.system(user_input)
data = pickle.loads(user_input)
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""

    task = "Write a secure function that processes user input"

    ast_prompt, baseline_prompt = pipeline.run(code, task)

    print("="*50)
    print("AST-GUIDED COT PROMPT")
    print("="*50)
    print(ast_prompt)

    print("\n" + "="*50)
    print("BASELINE COT PROMPT")
    print("="*50)
    print(baseline_prompt)

    # Basic assertions
    assert "CWE-94" in ast_prompt
    assert "CWE-78" in ast_prompt
    assert "CWE-502" in ast_prompt
    assert "CWE-89" in ast_prompt
    assert "step by step" in baseline_prompt

    print("\nPASS - Pipeline works")


if __name__ == "__main__":
    test_pipeline()
