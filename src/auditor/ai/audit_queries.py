"""W3-E: the versioned catalog of independent AI-audit queries.

The user NEVER writes a prompt. They pick a profile; the profile selects
queries from THIS catalog; every query declares — explicitly and immutably —
what it looks for, which languages it applies to, how candidate files are
retrieved, and its context/output budgets. The texts are code constants:
nothing here is editable from the browser, the CLI, or the API.

The goal of every query is catching mistakes COMMON IN AI-GENERATED OR
AI-MODIFIED code — not proving that the author was an AI.
"""
from __future__ import annotations

from dataclasses import dataclass

CATALOG_VERSION = 1
PROFILES = ("security", "correctness", "ai_code_risks", "all")

# languages the index recognizes (project languages of real reports)
AUDIT_LANGUAGES = ("python", "typescript", "csharp", "java")


@dataclass(frozen=True)
class AuditQuery:
    id: str                       # stable, never reused
    title: str
    objective: str                # what the model is asked to look for
    profiles: tuple[str, ...]     # which profiles include it ("all" implied)
    languages: tuple[str, ...]    # supported languages
    path_hints: tuple[str, ...]   # path/filename retrieval hints (lowercase)
    symbol_hints: tuple[str, ...]  # content retrieval hints (case-sensitive-ish)
    needs_manifest: bool          # include the project manifest excerpt
    query_version: int
    max_context_files: int        # source files per unit (hard cap)
    max_context_bytes: int        # source bytes per unit (hard cap)


_ALL = AUDIT_LANGUAGES

AUDIT_QUERIES: tuple[AuditQuery, ...] = (
    AuditQuery(
        id="AI001", title="Authorization and tenant-boundary mistakes",
        objective=(
            "Find endpoints, handlers, or data access where an authorization "
            "or tenant check is missing, inconsistent with sibling code, or "
            "applied after the sensitive action. Look for IDs taken from the "
            "request and used without ownership verification."),
        profiles=("security",), languages=_ALL,
        path_hints=("auth", "controller", "api", "route", "middleware",
                    "endpoint", "handler"),
        symbol_hints=("Authorize", "authorize", "permission", "role",
                      "tenant", "claims", "IsAdmin", "RequireAuth",
                      "owner_id", "user_id", "TenantId", "current_user"),
        needs_manifest=False, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
    AuditQuery(
        id="AI002", title="Untrusted input reaching execution/data/network sinks",
        objective=(
            "Find request/user/file input that reaches SQL, command "
            "execution, dynamic evaluation, path construction, HTML "
            "rendering, or outbound requests without visible validation, "
            "parameterization, or encoding on THIS path."),
        profiles=("security",), languages=_ALL,
        path_hints=("api", "controller", "handler", "service", "repo",
                    "query", "db"),
        symbol_hints=("execute", "query", "subprocess", "eval(", "exec(",
                      "os.system", "Popen", "innerHTML", "FromSql",
                      "ExecuteSql", "raw(", "sql", "request.", "params",
                      "body"),
        needs_manifest=False, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
    AuditQuery(
        id="AI003", title="Credential, configuration, and environment misuse",
        objective=(
            "Find committed literal credentials, secrets logged or echoed, "
            "config values read with unsafe fallbacks, environment mix-ups "
            "(prod vs dev), or keys exposed to clients."),
        profiles=("security",), languages=_ALL,
        path_hints=("config", "settings", "env", "startup", "program",
                    "di", "dependencyinjection"),
        symbol_hints=("password", "secret", "api_key", "apikey", "token",
                      "ConnectionString", "getenv", "environ", "process.env",
                      "NEXT_PUBLIC"),
        needs_manifest=True, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
    AuditQuery(
        id="AI004", title="Transaction, concurrency, idempotency, and race mistakes",
        objective=(
            "Find multi-step state changes without a transaction, check-then-"
            "act races, fire-and-forget async work, missing idempotency on "
            "retryable operations, and shared mutable state without locking."),
        profiles=("correctness",), languages=_ALL,
        path_hints=("service", "worker", "job", "background", "queue",
                    "payment", "billing", "order"),
        symbol_hints=("transaction", "Transaction", "lock", "Interlocked",
                      "async", "await", "Task.Run", "thread", "retry",
                      "idempot", "SaveChanges", "commit", "rollback"),
        needs_manifest=False, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
    AuditQuery(
        id="AI005", title="Swallowed failures and incomplete error handling",
        objective=(
            "Find failures that vanish: broad catches that continue, error "
            "paths returning success, partial cleanup after exceptions, and "
            "logging that replaces handling where the caller needed the "
            "failure."),
        profiles=("correctness",), languages=_ALL,
        path_hints=("service", "client", "worker", "util", "helper"),
        symbol_hints=("catch", "except", "finally", "ignore", "swallow",
                      "log.error", "logger.error", "console.error", "pass"),
        needs_manifest=False, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
    AuditQuery(
        id="AI006", title="API validation and contract mismatches",
        objective=(
            "Find request models accepted without validation, responses "
            "whose shape disagrees with the client/other endpoints, nullable "
            "vs required mismatches, and status codes inconsistent with the "
            "body."),
        profiles=("correctness",), languages=_ALL,
        path_hints=("api", "dto", "model", "contract", "schema",
                    "controller", "routes"),
        symbol_hints=("validate", "Required", "required", "BindProperty",
                      "FromBody", "zod", "pydantic", "BaseModel",
                      "ModelState", "schema"),
        needs_manifest=False, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
    AuditQuery(
        id="AI007", title="Fabricated, stale, or inconsistent dependency usage",
        objective=(
            "Compare imports/usages with the declared manifest: find "
            "packages or APIs that are not declared, belong to another "
            "ecosystem's idiom, use non-existent members, or mix versions "
            "and styles inconsistently."),
        profiles=("ai_code_risks",), languages=_ALL,
        path_hints=("import", "using", "require", "package", "deps"),
        symbol_hints=("import ", "using ", "require(", "from ", "Include="),
        needs_manifest=True, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
    AuditQuery(
        id="AI008", title="Incomplete implementations and copy/paste inconsistencies",
        objective=(
            "Find stubs presented as done: TODO/FIXME left in live paths, "
            "NotImplemented placeholders, copy/pasted blocks where one copy "
            "was updated and another was not, and names that contradict "
            "behavior."),
        profiles=("ai_code_risks",), languages=_ALL,
        path_hints=("service", "handler", "component", "page", "util"),
        symbol_hints=("TODO", "FIXME", "HACK", "XXX", "NotImplemented",
                      "placeholder", "stub", "throw new NotImplementedException",
                      "raise NotImplementedError"),
        needs_manifest=False, query_version=1,
        max_context_files=3, max_context_bytes=12 * 1024),
)

_BY_ID = {q.id: q for q in AUDIT_QUERIES}


def query_by_id(query_id: str) -> AuditQuery | None:
    return _BY_ID.get(query_id)


def queries_for_profile(profile: str) -> tuple[AuditQuery, ...]:
    """The deterministic query set for a profile. Unknown profile → ()."""
    if profile not in PROFILES:
        return ()
    if profile == "all":
        return AUDIT_QUERIES
    return tuple(q for q in AUDIT_QUERIES if profile in q.profiles)
