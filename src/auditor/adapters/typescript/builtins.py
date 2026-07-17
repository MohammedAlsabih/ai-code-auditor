# Bare-specifier builtins only. `test`/`sea`/`sqlite` are deliberately ABSENT:
# they are node:-scheme-only on every Node version (nodejs.org docs), and npm
# packages named test/sea/sqlite exist — listing them here masked real registry
# checks. `sys`/`constants` ARE real (deprecated) builtins on node <= 24.
NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads",
    "zlib",
})
