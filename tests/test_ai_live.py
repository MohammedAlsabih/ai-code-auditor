"""Live AI smoke — OPT-IN ONLY. Nothing here runs by default:
`AUDITOR_LIVE_AI_TEST=1` plus the provider's own key/server is required, so
CI and normal local runs make zero paid or networked calls. Ollama is probed
only if a local server is up AND already has a model; it is never pulled,
and its absence never fails the suite."""
import os

import pytest

from auditor.ai import Provider, create_client

LIVE = os.environ.get("AUDITOR_LIVE_AI_TEST") == "1"

pytestmark = pytest.mark.skipif(
    not LIVE, reason="live AI smoke is opt-in (AUDITOR_LIVE_AI_TEST=1)")


@pytest.mark.parametrize("provider,key_env", [
    (Provider.OPENAI, "OPENAI_API_KEY"),
    (Provider.ANTHROPIC, "ANTHROPIC_API_KEY"),
    (Provider.XAI, "XAI_API_KEY"),
])
def test_live_remote_provider(provider, key_env):
    if not os.environ.get(key_env):
        pytest.skip(f"{key_env} not set")
    client = create_client(provider)
    models = client.list_models()
    if not models:
        pytest.skip("provider reported no models")
    result = client.test_connection(models[0].id)
    assert result.ok, result.status


def test_live_ollama_if_running_with_a_model():
    client = create_client(Provider.OLLAMA)
    try:
        models = client.list_models()
    except Exception:
        pytest.skip("no local Ollama server")   # absence is a legal state
    if not models:
        pytest.skip("Ollama has no local model (never pulled automatically)")
    result = client.test_connection(models[0].id)
    assert result.ok, result.status
