"""
VulnGuard AI - Test Configuration
Pytest fixtures and configuration
"""
import pytest
import asyncio
from typing import Generator


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    """Mock settings for tests"""
    monkeypatch.setenv("AI_ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("GUARDRAIL_TIER1_AUTO_APPROVE", "false")
