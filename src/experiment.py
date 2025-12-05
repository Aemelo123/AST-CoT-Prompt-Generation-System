import json
import re
import subprocess
import pandas as pd
from datetime import datetime
from datasets import load_dataset
from src.pipeline import Pipeline
from src.llm_client import LLMClient
from src.ast_parser import ASTSecurityParser


class Experiment:
    # Runs the full experiment comparing AST-guided vs baseline prompts

    def __init__(self, use_explicit_rules: bool = False):
        self.pipeline = Pipeline(use_explicit_rules=use_explicit_rules)
        self.llm = LLMClient()
        self.parser = ASTSecurityParser()
        self.results = []
        self.use_explicit_rules = use_explicit_rules

    def load_dataset(self, limit: int = None):
        # Load SecurityEval dataset from Hugging Face
        dataset = load_dataset("s2e-lab/SecurityEval", split="train")
        if limit:
            dataset = dataset.select(range(min(limit, len(dataset))))
        return dataset

    def run(self, limit: int = None, models: list = ["claude", "gpt"]):
        # Run the full experiment
        dataset = self.load_dataset(limit)
        total = len(dataset)

        print(f"Running experiment on {total} samples with models: {models}")

        for i, sample in enumerate(dataset):
            print(f"\nProcessing {i+1}/{total}: {sample.get('ID', 'unknown')}")

            prompt_text = sample.get("Prompt", "")
            cwe_id = sample.get("Insecure_CWE", "")

            # Generate AST-guided and baseline prompts
            task = f"Complete this code securely:\n{prompt_text}"
            ast_prompt, baseline_prompt = self.pipeline.run(prompt_text, task)

            for model in models:
                # Generate code with AST-guided prompt
                try:
                    ast_response = self.llm.generate_code(ast_prompt, model=model)
                    ast_vulns = self._count_vulnerabilities(ast_response)
                    ast_bandit = self._run_bandit(ast_response)
                    ast_semgrep = self._run_semgrep(ast_response)
                    ast_loc = self._count_lines(ast_response)
                except Exception as e:
                    ast_response = f"ERROR: {e}"
                    ast_vulns, ast_bandit, ast_semgrep, ast_loc = -1, -1, -1, -1

                # Generate code with baseline prompt
                try:
                    baseline_response = self.llm.generate_code(baseline_prompt, model=model)
                    baseline_vulns = self._count_vulnerabilities(baseline_response)
                    baseline_bandit = self._run_bandit(baseline_response)
                    baseline_semgrep = self._run_semgrep(baseline_response)
                    baseline_loc = self._count_lines(baseline_response)
                except Exception as e:
                    baseline_response = f"ERROR: {e}"
                    baseline_vulns, baseline_bandit, baseline_semgrep, baseline_loc = -1, -1, -1, -1

                # Store results
                self.results.append({
                    "sample_id": sample.get("ID", i),
                    "cwe_id": cwe_id,
                    "model": model,
                    "prompt_type": "ast_guided",
                    "generated_code": ast_response,
                    "lines_of_code": ast_loc,
                    "vuln_count_ast_parser": ast_vulns,
                    "vuln_count_bandit": ast_bandit,
                    "vuln_count_semgrep": ast_semgrep,
                    "vuln_density_ast": ast_vulns / ast_loc if ast_loc > 0 else 0,
                    "vuln_density_bandit": ast_bandit / ast_loc if ast_loc > 0 else 0,
                    "vuln_density_semgrep": ast_semgrep / ast_loc if ast_loc > 0 else 0
                })

                self.results.append({
                    "sample_id": sample.get("ID", i),
                    "cwe_id": cwe_id,
                    "model": model,
                    "prompt_type": "baseline",
                    "generated_code": baseline_response,
                    "lines_of_code": baseline_loc,
                    "vuln_count_ast_parser": baseline_vulns,
                    "vuln_count_bandit": baseline_bandit,
                    "vuln_count_semgrep": baseline_semgrep,
                    "vuln_density_ast": baseline_vulns / baseline_loc if baseline_loc > 0 else 0,
                    "vuln_density_bandit": baseline_bandit / baseline_loc if baseline_loc > 0 else 0,
                    "vuln_density_semgrep": baseline_semgrep / baseline_loc if baseline_loc > 0 else 0
                })

        return self.results

    def _extract_code(self, response: str) -> str:
        # Extract Python code from markdown code blocks
        pattern = r'```python\s*(.*?)\s*```'
        matches = re.findall(pattern, response, re.DOTALL)
        if matches:
            return '\n\n'.join(matches)
        # If no markdown blocks, return the original response
        return response

    def _count_vulnerabilities(self, code: str) -> int:
        # Count vulnerabilities using our AST parser
        try:
            extracted = self._extract_code(code)
            findings = self.parser.parse(extracted)
            return len(findings)
        except:
            return -1

    def _count_lines(self, code: str) -> int:
        # Count non-empty, non-comment lines of code
        extracted = self._extract_code(code)
        lines = extracted.split('\n')
        count = 0
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                count += 1
        return count

    def _run_bandit(self, code: str) -> int:
        # Count vulnerabilities using Bandit
        try:
            extracted = self._extract_code(code)
            temp_file = "/tmp/temp_code.py"
            with open(temp_file, "w") as f:
                f.write(extracted)

            result = subprocess.run(
                ["bandit", "-f", "json", "-q", temp_file],
                capture_output=True,
                text=True
            )

            if result.stdout:
                bandit_output = json.loads(result.stdout)
                return len(bandit_output.get("results", []))
            return 0
        except:
            return -1

    def _run_semgrep(self, code: str) -> int:
        # Count vulnerabilities using Semgrep
        try:
            extracted = self._extract_code(code)
            temp_file = "/tmp/temp_code.py"
            with open(temp_file, "w") as f:
                f.write(extracted)

            result = subprocess.run(
                ["semgrep", "--config", "auto", "--json", "-q", temp_file],
                capture_output=True,
                text=True
            )

            if result.stdout:
                semgrep_output = json.loads(result.stdout)
                return len(semgrep_output.get("results", []))
            return 0
        except:
            return -1

    def export_csv(self, filename: str = None):
        # Export results to CSV for statistical analysis
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"results/experiment_{timestamp}.csv"

        df = pd.DataFrame(self.results)
        df.to_csv(filename, index=False)
        print(f"Results exported to {filename}")
        return df

    def get_summary(self):
        # Get summary statistics
        df = pd.DataFrame(self.results)

        summary = df.groupby(["model", "prompt_type"]).agg({
            "vuln_count_ast_parser": ["mean", "std", "sum"],
            "vuln_count_bandit": ["mean", "std", "sum"],
            "vuln_count_semgrep": ["mean", "std", "sum"]
        }).round(3)

        return summary
