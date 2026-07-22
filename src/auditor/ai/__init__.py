"""AI provider layer (W3-A): provider registry, model listing, and a fixed
connection probe. NOTHING here reads findings, reports, or source code — this
package is deliberately independent of the report schema, and W3-A sends no
repository content to any model."""
from auditor.ai.contract import (
    ERROR_CODES,
    PROBE_PROMPT,
    AIError,
    ConnectionResult,
    ModelInfo,
    Provider,
    ProviderConfig,
)
from auditor.ai.providers import (
    PROVIDER_SPECS,
    create_client,
    provider_metadata,
    resolve_config,
)

__all__ = [
    "ERROR_CODES",
    "PROBE_PROMPT",
    "AIError",
    "ConnectionResult",
    "ModelInfo",
    "Provider",
    "ProviderConfig",
    "PROVIDER_SPECS",
    "create_client",
    "provider_metadata",
    "resolve_config",
]
