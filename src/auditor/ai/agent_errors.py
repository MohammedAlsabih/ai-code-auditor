"""Typed, pre-wire failures of the W3-E5 experimental agent audit runtime.

They live in their own dependency-free module because BOTH sides need them
statically: `auditor.ai.audit_agent` (which raises them) imports
`auditor.ai.audit`, so `auditor.ai.audit` — whose runner must list them in its
explicit caught-error allowlist — cannot import audit_agent back without a
cycle. Keeping them here makes the runner's allowlist a plain, checkable tuple
instead of a lazily-resolved one, which is what preserves the no-silent-failure
rule: a unit fails with `agent_audit_disabled` / `agent_runtime_missing`, never
as an anonymous `internal_error`.

Nothing here imports anything — not the optional [agent] extra, not FastAPI —
so every install shape can import it.
"""
from __future__ import annotations

# the server-env master switch for the experimental engine
AGENT_AUDIT_ENV = "AUDITOR_AI_AGENT_AUDIT"

# the optional extra that carries the agent runtime: `pip install .[agent]`
AGENT_RUNTIME_PKG = "pydantic_ai"
AGENT_RUNTIME_HINT = ('the experimental agent runtime is not installed; '
                      'install it with: pip install "ai-code-auditor[agent]"')


class AgentAuditDisabledError(Exception):
    """The experimental agent audit engine is not enabled. Raised BEFORE any
    model construction or network I/O; the message is fixed and safe."""

    code = "agent_audit_disabled"

    def __init__(self) -> None:
        super().__init__(
            "the experimental agent audit engine is off; set "
            f"{AGENT_AUDIT_ENV}=confirm on the server to enable it")


class AgentRuntimeMissingError(Exception):
    """The [agent] extra is not installed. Distinct from
    AgentAuditDisabledError (which means the operator has not switched the
    engine on): this one is a packaging state, and the message names the exact
    install command."""

    code = "agent_runtime_missing"

    def __init__(self) -> None:
        super().__init__(AGENT_RUNTIME_HINT)
