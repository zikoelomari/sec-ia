"""
Générateur de code utilisant les API OpenAI et Anthropic.
Fallback automatique sur simulation si aucune clé API disponible.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import logging
import os
import time
from typing import Dict, Literal, Optional, TypedDict

# Imports conditionnels avec fallback
try:
    from openai import AsyncOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    AsyncOpenAI = None

try:
    from anthropic import AsyncAnthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False
    AsyncAnthropic = None

try:
    import tiktoken
    HAS_TIKTOKEN = True
except ImportError:
    HAS_TIKTOKEN = False
    tiktoken = None

try:
    from tenacity import (
        retry,
        stop_after_attempt,
        wait_exponential,
        retry_if_exception_type,
    )
    HAS_TENACITY = True
except ImportError:
    HAS_TENACITY = False
    # Fallback simple sans retry
    def retry(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    stop_after_attempt = None
    wait_exponential = None
    retry_if_exception_type = None

LOG = logging.getLogger(__name__)

# Configuration depuis environnement
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
AI_MODEL = os.environ.get("AI_MODEL", "gpt-4")
AI_TEMPERATURE = float(os.environ.get("AI_TEMPERATURE", "0.7"))
AI_MAX_TOKENS = int(os.environ.get("AI_MAX_TOKENS", "500"))
AI_TIMEOUT = int(os.environ.get("AI_TIMEOUT_SECONDS", "30"))

Provider = Literal["openai", "anthropic", "simulate"]


class GenerationResult(TypedDict):
    code: str
    model: str
    provider: str
    timestamp: str
    tokens_used: int
    cost_usd: Optional[float]
    metadata: Dict[str, any]


class GenerationError(Exception):
    """Exception levée lors d'une erreur de génération."""
    pass


# Prompts optimisés par langage
PROMPTS_BY_LANGUAGE = {
    "python": (
        "Write a complete, production-ready Python {description}. "
        "Include type hints (typing module), comprehensive error handling (try/except), "
        "docstrings (Google style), and follow security best practices "
        "(no hardcoded secrets, input validation, avoid eval/exec). "
        "Return only the code without explanations."
    ),
    "javascript": (
        "Write a complete, secure JavaScript {description}. "
        "Use modern ES6+ syntax (const/let, arrow functions), async/await for asynchronous code, "
        "proper error handling (try/catch), and follow security best practices "
        "(input sanitization, no eval, CSP-compliant). "
        "Return only the code without explanations."
    ),
    "typescript": (
        "Write a complete, type-safe TypeScript {description}. "
        "Use strict type annotations, interfaces, async/await, proper error handling, "
        "and follow security best practices (input validation, avoid any type). "
        "Return only the code without explanations."
    ),
    "java": (
        "Write a complete, secure Java {description}. "
        "Follow OWASP Top 10 guidelines, include proper exception handling (try-catch-finally), "
        "use Java 17+ features when appropriate, add JavaDoc comments, "
        "and implement input validation. "
        "Return only the code without explanations."
    ),
    "csharp": (
        "Write a complete, secure C# {description}. "
        "Use modern C# 12 features, proper exception handling (try-catch-finally), "
        "XML documentation comments, async/await for I/O operations, "
        "and follow security best practices (parameterized queries, input validation). "
        "Return only the code without explanations."
    ),
}


def get_available_providers() -> list[Provider]:
    """Retourne la liste des providers disponibles basée sur les clés API."""
    providers: list[Provider] = ["simulate"]  # Toujours disponible
    if OPENAI_API_KEY and HAS_OPENAI:
        providers.insert(0, "openai")
    if ANTHROPIC_API_KEY and HAS_ANTHROPIC:
        providers.insert(1 if "openai" in providers else 0, "anthropic")
    return providers


def _build_prompt(description: str, language: str) -> str:
    """Construit le prompt optimisé pour le langage cible."""
    template = PROMPTS_BY_LANGUAGE.get(
        language.lower(),
        "Write a complete {description} in {language}. Follow security best practices."
    )
    return template.format(description=description, language=language)


def _estimate_cost(model: str, tokens: int) -> Optional[float]:
    """Estime le coût en USD basé sur le modèle et les tokens."""
    # Prix approximatifs (à jour février 2024)
    PRICING = {
        "gpt-4": {"input": 0.03 / 1000, "output": 0.06 / 1000},
        "gpt-4-turbo": {"input": 0.01 / 1000, "output": 0.03 / 1000},
        "gpt-3.5-turbo": {"input": 0.0005 / 1000, "output": 0.0015 / 1000},
        "claude-3-opus": {"input": 0.015 / 1000, "output": 0.075 / 1000},
        "claude-3-5-sonnet": {"input": 0.003 / 1000, "output": 0.015 / 1000},
        "claude-3-haiku": {"input": 0.00025 / 1000, "output": 0.00125 / 1000},
    }
    
    for model_key, pricing in PRICING.items():
        if model_key in model.lower():
            # Approximation : tokens/2 input + tokens/2 output
            return (tokens / 2) * pricing["input"] + (tokens / 2) * pricing["output"]
    return None


def _count_tokens(text: str, model: str = "gpt-4") -> int:
    """Compte approximatif des tokens (utilise tiktoken si disponible)."""
    if HAS_TIKTOKEN:
        try:
            encoding = tiktoken.encoding_for_model(model)
            return len(encoding.encode(text))
        except Exception:
            pass
    # Fallback : approximation 1 token ≈ 4 caractères
    return len(text) // 4


if HAS_TENACITY:
    retry_decorator = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
    )
else:
    def retry_decorator(func):
        return func


@retry_decorator
async def _generate_openai(
    description: str,
    language: str,
    model: str = AI_MODEL,
    temperature: float = AI_TEMPERATURE,
    max_tokens: int = AI_MAX_TOKENS,
) -> GenerationResult:
    """Génère du code via l'API OpenAI."""
    if not HAS_OPENAI:
        raise GenerationError("openai package not installed. Run: pip install openai")
    if not OPENAI_API_KEY:
        raise GenerationError("OPENAI_API_KEY environment variable not set")

    client = AsyncOpenAI(api_key=OPENAI_API_KEY, timeout=AI_TIMEOUT)
    prompt = _build_prompt(description, language)
    
    LOG.info(f"Generating code with OpenAI model={model}, language={language}")
    start_time = time.time()
    
    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior software engineer writing secure, production-grade code."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        
        code = response.choices[0].message.content.strip()
        tokens = response.usage.total_tokens if response.usage else _count_tokens(code, model)
        cost = _estimate_cost(model, tokens)
        duration = time.time() - start_time
        
        LOG.info(f"OpenAI generation completed: {tokens} tokens, ${cost:.4f}, {duration:.2f}s")
        
        return {
            "code": code,
            "model": model,
            "provider": "openai",
            "timestamp": dt.datetime.utcnow().isoformat() + "Z",
            "tokens_used": tokens,
            "cost_usd": cost,
            "metadata": {
                "description": description,
                "language": language,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "duration_seconds": duration,
                "finish_reason": response.choices[0].finish_reason,
            },
        }
    except Exception as e:
        LOG.error(f"OpenAI generation failed: {e}")
        raise GenerationError(f"OpenAI API error: {e}") from e


if HAS_TENACITY:
    retry_decorator_anthropic = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
    )
else:
    def retry_decorator_anthropic(func):
        return func


@retry_decorator_anthropic
async def _generate_anthropic(
    description: str,
    language: str,
    model: str = "claude-3-5-sonnet-20241022",
    temperature: float = AI_TEMPERATURE,
    max_tokens: int = AI_MAX_TOKENS,
) -> GenerationResult:
    """Génère du code via l'API Anthropic Claude."""
    if not HAS_ANTHROPIC:
        raise GenerationError("anthropic package not installed. Run: pip install anthropic")
    if not ANTHROPIC_API_KEY:
        raise GenerationError("ANTHROPIC_API_KEY environment variable not set")

    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY, timeout=AI_TIMEOUT)
    prompt = _build_prompt(description, language)
    
    LOG.info(f"Generating code with Anthropic model={model}, language={language}")
    start_time = time.time()
    
    try:
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        
        code = response.content[0].text.strip()
        tokens = response.usage.input_tokens + response.usage.output_tokens
        cost = _estimate_cost(model, tokens)
        duration = time.time() - start_time
        
        LOG.info(f"Anthropic generation completed: {tokens} tokens, ${cost:.4f}, {duration:.2f}s")
        
        return {
            "code": code,
            "model": model,
            "provider": "anthropic",
            "timestamp": dt.datetime.utcnow().isoformat() + "Z",
            "tokens_used": tokens,
            "cost_usd": cost,
            "metadata": {
                "description": description,
                "language": language,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "duration_seconds": duration,
                "stop_reason": response.stop_reason,
            },
        }
    except Exception as e:
        LOG.error(f"Anthropic generation failed: {e}")
        raise GenerationError(f"Anthropic API error: {e}") from e


def _generate_simulated(
    description: str,
    language: str,
    **kwargs
) -> GenerationResult:
    """Génération simulée avec templates (fallback)."""
    import random
    
    templates = {
        "python": f'''def generated_function():
    """
    Generated code for: {description}
    This is a SIMULATED code generation for demonstration purposes.
    """
    try:
        # TODO: Implement {description}
        result = perform_operation()
        return result
    except Exception as e:
        raise RuntimeError(f"Error in {description}: {{e}}")
''',
        "javascript": f'''// Generated code for: {description}
async function generatedFunction() {{
    try {{
        // TODO: Implement {description}
        const result = await performOperation();
        return result;
    }} catch (error) {{
        throw new Error(`Error in {description}: ${{error.message}}`);
    }}
}}
''',
        "typescript": f'''// Generated code for: {description}
async function generatedFunction(): Promise<any> {{
    try {{
        // TODO: Implement {description}
        const result = await performOperation();
        return result;
    }} catch (error) {{
        throw new Error(`Error in {description}: ${{error.message}}`);
    }}
}}
''',
        "java": f'''// Generated code for: {description}
public class GeneratedClass {{
    public static void run() {{
        // TODO: Implement {description}
        System.out.println("Generated code for: {description}");
    }}
}}
''',
        "csharp": f'''// Generated code for: {description}
using System;

public static class GeneratedClass {{
    public static void Run() {{
        // TODO: Implement {description}
        Console.WriteLine("Generated code for: {description}");
    }}
}}
''',
    }
    
    code = templates.get(language.lower(), f"// SIMULATED: {description}\n// Language: {language}")
    tokens = _count_tokens(code)
    
    return {
        "code": code,
        "model": "simulated-template-v1",
        "provider": "simulate",
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        "tokens_used": tokens,
        "cost_usd": 0.0,
        "metadata": {
            "description": description,
            "language": language,
            "warning": "This is a simulated generation. Set OPENAI_API_KEY or ANTHROPIC_API_KEY for real AI generation.",
        },
    }


async def generate_code_with_ai(
    description: str,
    language: str,
    provider: Optional[Provider] = None,
    model: Optional[str] = None,
    temperature: float = AI_TEMPERATURE,
    max_tokens: int = AI_MAX_TOKENS,
) -> GenerationResult:
    """
    Génère du code via API IA avec auto-détection du provider.
    
    Args:
        description: Description du code à générer
        language: Langage cible (python, javascript, etc.)
        provider: Provider explicite ou None pour auto-détection
        model: Modèle spécifique ou None pour utiliser la config par défaut
        temperature: Température de génération (0.0-1.0)
        max_tokens: Nombre max de tokens
    
    Returns:
        GenerationResult avec code, métadonnées, tokens, coût
    
    Raises:
        GenerationError: Si la génération échoue
    """
    # Auto-détection du provider
    if provider is None:
        available = get_available_providers()
        provider = available[0]  # Premier disponible (priorité: openai > anthropic > simulate)
        LOG.info(f"Auto-detected provider: {provider}")
    
    # Génération selon le provider
    try:
        if provider == "openai":
            return await _generate_openai(
                description, language, model or AI_MODEL, temperature, max_tokens
            )
        elif provider == "anthropic":
            return await _generate_anthropic(
                description, language, model or "claude-3-5-sonnet-20241022", temperature, max_tokens
            )
        elif provider == "simulate":
            return _generate_simulated(description, language)
        else:
            raise GenerationError(f"Unknown provider: {provider}")
    except GenerationError:
        raise
    except Exception as e:
        LOG.error(f"Unexpected error during generation: {e}")
        raise GenerationError(f"Generation failed: {e}") from e

