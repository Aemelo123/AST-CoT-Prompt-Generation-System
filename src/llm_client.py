import os
from dotenv import load_dotenv
from anthropic import Anthropic
from openai import OpenAI

load_dotenv()


class LLMClient:
    # Unified client for Claude and OpenAI

    def __init__(self):
        self.anthropic = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.openai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def generate_code(self, prompt: str, model: str = "claude") -> str:
        # Generate code using specified model
        if model == "claude":
            return self._call_claude(prompt)
        elif model == "gpt":
            return self._call_openai(prompt)
        else:
            raise ValueError(f"Unknown model: {model}")

    def _call_claude(self, prompt: str) -> str:
        response = self.anthropic.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text

    def _call_openai(self, prompt: str) -> str:
        response = self.openai.chat.completions.create(
            model="gpt-4o",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
