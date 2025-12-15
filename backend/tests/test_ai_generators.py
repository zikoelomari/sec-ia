"""Tests pour les générateurs IA."""
from __future__ import annotations

import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# Importer le module à tester
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.generators.ai_code_generator import (
    generate_code_with_ai,
    get_available_providers,
    GenerationError,
    _build_prompt,
    _estimate_cost,
    _count_tokens,
)


class TestAvailableProviders:
    """Tests pour la détection des providers disponibles."""
    
    def test_no_api_keys(self, monkeypatch):
        """Quand aucune clé API n'est définie, seul 'simulate' est disponible."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        
        providers = get_available_providers()
        assert providers == ["simulate"]
    
    def test_openai_configured(self, monkeypatch):
        """Quand OPENAI_API_KEY est défini, openai est premier."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        
        providers = get_available_providers()
        assert "openai" in providers
        assert providers[0] == "openai"
    
    def test_both_configured(self, monkeypatch):
        """Quand les deux clés sont définies, openai est prioritaire."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        
        providers = get_available_providers()
        assert "openai" in providers
        assert "anthropic" in providers


class TestPromptBuilding:
    """Tests pour la construction des prompts."""
    
    def test_python_prompt(self):
        """Test prompt Python."""
        prompt = _build_prompt("user authentication", "python")
        assert "production-ready Python" in prompt
        assert "type hints" in prompt
        assert "user authentication" in prompt
    
    def test_javascript_prompt(self):
        """Test prompt JavaScript."""
        prompt = _build_prompt("REST API client", "javascript")
        assert "JavaScript" in prompt
        assert "ES6+" in prompt
        assert "REST API client" in prompt


class TestCostEstimation:
    """Tests pour l'estimation des coûts."""
    
    def test_gpt4_cost(self):
        """Test estimation coût GPT-4."""
        cost = _estimate_cost("gpt-4", 1000)
        assert cost is not None
        assert cost > 0
        assert cost < 1  # 1000 tokens ne doit pas coûter 1$
    
    def test_claude_cost(self):
        """Test estimation coût Claude."""
        cost = _estimate_cost("claude-3-5-sonnet-20241022", 1000)
        assert cost is not None
        assert cost > 0
    
    def test_unknown_model(self):
        """Test modèle inconnu retourne None."""
        cost = _estimate_cost("unknown-model", 1000)
        assert cost is None


class TestTokenCounting:
    """Tests pour le comptage de tokens."""
    
    def test_count_basic(self):
        """Test comptage basique (fallback)."""
        text = "print('hello world')"
        tokens = _count_tokens(text)
        assert tokens > 0
        assert tokens < 100


@pytest.mark.asyncio
class TestSimulatedGeneration:
    """Tests pour la génération simulée."""
    
    async def test_simulate_python(self):
        """Test génération simulée Python."""
        result = await generate_code_with_ai(
            description="user login",
            language="python",
            provider="simulate"
        )
        
        assert result["provider"] == "simulate"
        assert result["model"] == "simulated-template-v1"
        assert "user login" in result["code"]
        assert result["cost_usd"] == 0.0
        assert result["tokens_used"] > 0
    
    async def test_simulate_javascript(self):
        """Test génération simulée JavaScript."""
        result = await generate_code_with_ai(
            description="form validation",
            language="javascript",
            provider="simulate"
        )
        
        assert result["provider"] == "simulate"
        assert "form validation" in result["code"]


@pytest.mark.asyncio
class TestOpenAIGeneration:
    """Tests pour la génération OpenAI (avec mocks)."""
    
    async def test_openai_success(self, monkeypatch):
        """Test génération OpenAI réussie (mock)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        
        # Mock de l'API OpenAI
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="def hello(): pass"), finish_reason="stop")]
        mock_response.usage = MagicMock(total_tokens=50)
        
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        
        with patch("backend.generators.ai_code_generator.AsyncOpenAI", return_value=mock_client):
            result = await generate_code_with_ai(
                description="hello function",
                language="python",
                provider="openai"
            )
            
            assert result["provider"] == "openai"
            assert result["code"] == "def hello(): pass"
            assert result["tokens_used"] == 50
    
    async def test_openai_no_key(self, monkeypatch):
        """Test échec si pas de clé OpenAI."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        
        with pytest.raises(GenerationError, match="OPENAI_API_KEY"):
            await generate_code_with_ai(
                description="test",
                language="python",
                provider="openai"
            )


@pytest.mark.asyncio
class TestAnthropicGeneration:
    """Tests pour la génération Anthropic (avec mocks)."""
    
    async def test_anthropic_success(self, monkeypatch):
        """Test génération Anthropic réussie (mock)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        
        # Mock de l'API Anthropic
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="function hello() {}")]
        mock_response.usage = MagicMock(input_tokens=20, output_tokens=30)
        mock_response.stop_reason = "end_turn"
        
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        
        with patch("backend.generators.ai_code_generator.AsyncAnthropic", return_value=mock_client):
            result = await generate_code_with_ai(
                description="hello function",
                language="javascript",
                provider="anthropic"
            )
            
            assert result["provider"] == "anthropic"
            assert result["code"] == "function hello() {}"
            assert result["tokens_used"] == 50  # 20 + 30


@pytest.mark.asyncio
class TestAutoDetection:
    """Tests pour l'auto-détection du provider."""
    
    async def test_auto_detect_simulate(self, monkeypatch):
        """Sans clé API, auto-détection choisit simulate."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        
        result = await generate_code_with_ai(
            description="test",
            language="python",
            provider=None  # Auto-détection
        )
        
        assert result["provider"] == "simulate"

