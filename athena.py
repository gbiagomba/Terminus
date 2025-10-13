#!/usr/bin/env python3
"""
Terminus AI Analyzer - Post-processing script for Terminus scan results

Supports multiple AI providers (local and cloud) to analyze and explain scan results
from different professional perspectives.

Usage:
    python terminus_ai_analyzer.py results.json --provider ollama --persona security
    python terminus_ai_analyzer.py results.json --provider openai --persona developer
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Optional
from enum import Enum

# Try to import optional dependencies
try:
    import requests
except ImportError:
    print("Error: requests library not found. Install with: pip install requests")
    sys.exit(1)


class Persona(Enum):
    """Available analysis personas"""
    SECURITY = "security"
    DEVELOPER = "developer"
    TPM = "tpm"


class AIProvider(Enum):
    """Supported AI providers"""
    # Local providers
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    VLLM = "vllm"
    # Cloud providers
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


PERSONA_PROMPTS = {
    Persona.SECURITY: """You are an experienced Security Engineer analyzing HTTP endpoint scan results.
Your focus is on:
- Identifying security misconfigurations and vulnerabilities
- Assessing exposure risks and attack surfaces
- Recommending security hardening measures
- Prioritizing findings by severity and exploitability
- Suggesting remediation steps with security best practices

Provide actionable security insights that help protect the infrastructure.""",

    Persona.DEVELOPER: """You are a Senior Software Engineer/Developer analyzing HTTP endpoint scan results.
Your focus is on:
- Understanding the technical implementation and architecture
- Identifying potential bugs or misconfigurations in the application
- Suggesting code-level fixes and improvements
- Explaining HTTP status codes in development context
- Recommending best practices for API design and error handling

Provide practical development-focused insights that help improve the application.""",

    Persona.TPM: """You are a Technical Program Manager analyzing HTTP endpoint scan results.
Your focus is on:
- Translating technical findings into business impact
- Prioritizing issues based on risk to project timeline and deliverables
- Creating actionable items for engineering teams
- Identifying blockers and dependencies
- Providing executive-friendly summaries

Provide high-level strategic insights that help drive project decisions."""
}


def get_persona_prompt(persona: Persona) -> str:
    """Get the system prompt for the specified persona"""
    return PERSONA_PROMPTS[persona]


def format_results_for_analysis(results: List[Dict]) -> str:
    """Format scan results into a readable format for AI analysis"""
    output = []
    output.append("=" * 80)
    output.append("TERMINUS SCAN RESULTS SUMMARY")
    output.append("=" * 80)
    output.append(f"\nTotal endpoints scanned: {len(results)}\n")

    # Group by status code
    status_groups = {}
    for result in results:
        status = result.get('status', 0)
        if status not in status_groups:
            status_groups[status] = []
        status_groups[status].append(result)

    output.append("Status Code Distribution:")
    for status in sorted(status_groups.keys()):
        count = len(status_groups[status])
        output.append(f"  {status}: {count} endpoints")

    output.append("\n" + "=" * 80)
    output.append("DETAILED RESULTS")
    output.append("=" * 80 + "\n")

    for i, result in enumerate(results, 1):
        output.append(f"[{i}] {result.get('url', 'N/A')}")
        output.append(f"    Method: {result.get('method', 'N/A')}")
        output.append(f"    Status: {result.get('status', 'N/A')}")
        output.append(f"    Port: {result.get('port', 'N/A')}")

        if result.get('headers'):
            output.append(f"    Headers: {result['headers'][:100]}...")

        if result.get('error'):
            output.append(f"    Error: {result['error']}")

        output.append("")

    return "\n".join(output)


class AIAnalyzer:
    """Base class for AI analyzers"""

    def __init__(self, provider: AIProvider, persona: Persona, model: Optional[str] = None):
        self.provider = provider
        self.persona = persona
        self.model = model or self.get_default_model()
        self.system_prompt = get_persona_prompt(persona)

    def get_default_model(self) -> str:
        """Get default model for the provider"""
        defaults = {
            AIProvider.OLLAMA: "llama3.2",
            AIProvider.LMSTUDIO: "local-model",
            AIProvider.VLLM: "local-model",
            AIProvider.OPENAI: "gpt-4",
            AIProvider.ANTHROPIC: "claude-3-5-sonnet-20241022",
            AIProvider.GEMINI: "gemini-pro"
        }
        return defaults.get(self.provider, "default-model")

    def analyze(self, results_text: str) -> str:
        """Analyze the results and return insights"""
        raise NotImplementedError("Subclasses must implement analyze()")


class OllamaAnalyzer(AIAnalyzer):
    """Analyzer using Ollama local AI"""

    def __init__(self, persona: Persona, model: Optional[str] = None, base_url: str = "http://localhost:11434"):
        super().__init__(AIProvider.OLLAMA, persona, model)
        self.base_url = base_url

    def analyze(self, results_text: str) -> str:
        """Analyze using Ollama API"""
        url = f"{self.base_url}/api/generate"

        prompt = f"""{self.system_prompt}

Please analyze the following Terminus scan results and provide insights:

{results_text}

Provide a comprehensive analysis including:
1. Summary of findings
2. Key security/technical concerns
3. Prioritized recommendations
4. Next steps
"""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }

        try:
            response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result.get('response', 'No response from Ollama')
        except requests.exceptions.RequestException as e:
            return f"Error connecting to Ollama: {e}\nMake sure Ollama is running on {self.base_url}"


class LMStudioAnalyzer(AIAnalyzer):
    """Analyzer using LM Studio local AI"""

    def __init__(self, persona: Persona, model: Optional[str] = None, base_url: str = "http://localhost:1234"):
        super().__init__(AIProvider.LMSTUDIO, persona, model)
        self.base_url = base_url

    def analyze(self, results_text: str) -> str:
        """Analyze using LM Studio API (OpenAI-compatible)"""
        url = f"{self.base_url}/v1/chat/completions"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": f"Please analyze these Terminus scan results:\n\n{results_text}"}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }

        try:
            response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result['choices'][0]['message']['content']
        except requests.exceptions.RequestException as e:
            return f"Error connecting to LM Studio: {e}\nMake sure LM Studio server is running on {self.base_url}"


class VLLMAnalyzer(AIAnalyzer):
    """Analyzer using vLLM local AI"""

    def __init__(self, persona: Persona, model: Optional[str] = None, base_url: str = "http://localhost:8000"):
        super().__init__(AIProvider.VLLM, persona, model)
        self.base_url = base_url

    def analyze(self, results_text: str) -> str:
        """Analyze using vLLM API (OpenAI-compatible)"""
        url = f"{self.base_url}/v1/chat/completions"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": f"Analyze these scan results:\n\n{results_text}"}
            ],
            "max_tokens": 2000
        }

        try:
            response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result['choices'][0]['message']['content']
        except requests.exceptions.RequestException as e:
            return f"Error connecting to vLLM: {e}\nMake sure vLLM server is running on {self.base_url}"


class OpenAIAnalyzer(AIAnalyzer):
    """Analyzer using OpenAI API"""

    def __init__(self, persona: Persona, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(AIProvider.OPENAI, persona, model)
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY environment variable or pass --api-key")

    def analyze(self, results_text: str) -> str:
        """Analyze using OpenAI API"""
        url = "https://api.openai.com/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": f"Analyze these Terminus scan results:\n\n{results_text}"}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result['choices'][0]['message']['content']
        except requests.exceptions.RequestException as e:
            return f"Error connecting to OpenAI: {e}"


class AnthropicAnalyzer(AIAnalyzer):
    """Analyzer using Anthropic Claude API"""

    def __init__(self, persona: Persona, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(AIProvider.ANTHROPIC, persona, model)
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("Anthropic API key required. Set ANTHROPIC_API_KEY environment variable or pass --api-key")

    def analyze(self, results_text: str) -> str:
        """Analyze using Anthropic API"""
        url = "https://api.anthropic.com/v1/messages"

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "max_tokens": 2000,
            "system": self.system_prompt,
            "messages": [
                {"role": "user", "content": f"Analyze these Terminus scan results:\n\n{results_text}"}
            ]
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result['content'][0]['text']
        except requests.exceptions.RequestException as e:
            return f"Error connecting to Anthropic: {e}"


class GeminiAnalyzer(AIAnalyzer):
    """Analyzer using Google Gemini API"""

    def __init__(self, persona: Persona, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(AIProvider.GEMINI, persona, model)
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key required. Set GEMINI_API_KEY environment variable or pass --api-key")

    def analyze(self, results_text: str) -> str:
        """Analyze using Gemini API"""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        prompt = f"""{self.system_prompt}

Analyze these Terminus scan results:

{results_text}"""

        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }

        try:
            response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            return result['candidates'][0]['content']['parts'][0]['text']
        except requests.exceptions.RequestException as e:
            return f"Error connecting to Gemini: {e}"


def create_analyzer(provider: str, persona: str, model: Optional[str] = None,
                   api_key: Optional[str] = None, base_url: Optional[str] = None) -> AIAnalyzer:
    """Factory function to create the appropriate analyzer"""

    provider_enum = AIProvider(provider.lower())
    persona_enum = Persona(persona.lower())

    if provider_enum == AIProvider.OLLAMA:
        return OllamaAnalyzer(persona_enum, model, base_url or "http://localhost:11434")
    elif provider_enum == AIProvider.LMSTUDIO:
        return LMStudioAnalyzer(persona_enum, model, base_url or "http://localhost:1234")
    elif provider_enum == AIProvider.VLLM:
        return VLLMAnalyzer(persona_enum, model, base_url or "http://localhost:8000")
    elif provider_enum == AIProvider.OPENAI:
        return OpenAIAnalyzer(persona_enum, model, api_key)
    elif provider_enum == AIProvider.ANTHROPIC:
        return AnthropicAnalyzer(persona_enum, model, api_key)
    elif provider_enum == AIProvider.GEMINI:
        return GeminiAnalyzer(persona_enum, model, api_key)
    else:
        raise ValueError(f"Unsupported provider: {provider}")


def main():
    parser = argparse.ArgumentParser(
        description="Terminus AI Analyzer - Analyze scan results using AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze with Ollama (local)
  python terminus_ai_analyzer.py results.json --provider ollama --persona security

  # Analyze with OpenAI
  export OPENAI_API_KEY=sk-...
  python terminus_ai_analyzer.py results.json --provider openai --persona developer

  # Analyze with custom model
  python terminus_ai_analyzer.py results.json --provider ollama --model llama3 --persona tpm

  # Analyze with LM Studio
  python terminus_ai_analyzer.py results.json --provider lmstudio --base-url http://localhost:1234
        """
    )

    parser.add_argument('input_file', help='Path to Terminus JSON output file')
    parser.add_argument('--provider', '-p',
                       choices=['ollama', 'lmstudio', 'vllm', 'openai', 'anthropic', 'gemini'],
                       default='ollama',
                       help='AI provider to use (default: ollama)')
    parser.add_argument('--persona', '-r',
                       choices=['security', 'developer', 'tpm'],
                       default='security',
                       help='Analysis persona (default: security)')
    parser.add_argument('--model', '-m',
                       help='Specific model to use (provider-dependent)')
    parser.add_argument('--api-key', '-k',
                       help='API key for cloud providers (or set via environment variable)')
    parser.add_argument('--base-url', '-u',
                       help='Base URL for local AI providers')
    parser.add_argument('--output', '-o',
                       help='Output file for analysis (default: stdout)')

    args = parser.parse_args()

    # Load results
    try:
        with open(args.input_file, 'r') as f:
            results = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input_file}: {e}", file=sys.stderr)
        sys.exit(1)

    # Format results for analysis
    results_text = format_results_for_analysis(results)

    # Create analyzer
    try:
        analyzer = create_analyzer(
            args.provider,
            args.persona,
            args.model,
            args.api_key,
            args.base_url
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Perform analysis
    print(f"Analyzing with {args.provider} using {args.persona} persona...\n")
    analysis = analyzer.analyze(results_text)

    # Output results
    output_text = f"""
{'=' * 80}
TERMINUS AI ANALYSIS
{'=' * 80}
Provider: {args.provider.upper()}
Model: {analyzer.model}
Persona: {args.persona.upper()}
{'=' * 80}

{analysis}

{'=' * 80}
END OF ANALYSIS
{'=' * 80}
"""

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_text)
        print(f"Analysis written to {args.output}")
    else:
        print(output_text)


if __name__ == '__main__':
    main()
