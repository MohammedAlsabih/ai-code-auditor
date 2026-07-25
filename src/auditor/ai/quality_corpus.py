"""W3-E4B1: a fixed, deterministic multi-file quality corpus for AI001-AI008
in TWO pre-registered splits. `development` is the W3-E4A set the earlier
measurements ran on; `holdout` is a NEW, never-measured set (one positive, one
negative, one abstention per query) whose snippets and wording deliberately do
not repeat the development set — so a prompt/contract change tuned on
development can be judged on cases it has never seen.

Every case is human-labelled BEFORE any model runs with a written `reason`
and, for positives, an exact `target` (file + line span the detection must
cite). Sources carry NO answer-leaking comments or file names, NO real
repository names, and NO valid secrets. Negative controls (parameterized SQL,
DOMPurify, an authorized route across files, an explicit transaction, wrap-
and-rethrow, schema validation, a declared dependency, a marker-as-data lint
tool) exist AS SOURCE, independent of any report's static findings.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from auditor.ai.audit_queries import query_by_id

CORPUS_VERSION = 3

EXPECT_POSITIVE = "positive"
EXPECT_NEGATIVE = "negative"
EXPECT_ABSTAIN = "abstain"

SPLIT_DEVELOPMENT = "development"
SPLIT_HOLDOUT = "holdout"


@dataclass(frozen=True)
class CorpusFile:
    rel: str                        # project-relative posix path
    text: str
    language: str                   # csharp|python|typescript (source) or ""
    role: str = "source"            # source|manifest

    def project_root(self, default: str) -> str:
        """The project root this file belongs to: the first path segment when
        the rel is nested under a project dir, else the case default."""
        return self.rel.split("/")[0] if "/" in self.rel else default


@dataclass(frozen=True)
class Target:
    """Where a positive case's real issue lives — the detection must cite this
    file with a line range that overlaps [line_start, line_end]."""
    file: str                       # PROJECT-relative rel
    line_start: int
    line_end: int


@dataclass(frozen=True)
class CorpusCase:
    case_id: str
    query_id: str
    kind: str                       # EXPECT_POSITIVE|NEGATIVE|ABSTAIN
    project: str                    # project root the audit runs on
    files: tuple[CorpusFile, ...]
    reason: str
    target: Target | None = None    # required iff positive
    split: str = SPLIT_DEVELOPMENT  # development|holdout — fixed at
    #                                 registration, part of the corpus digest

    @property
    def category(self) -> str:
        q = query_by_id(self.query_id)
        assert q is not None
        return q.category

    @property
    def project_roots(self) -> list[tuple[str, str]]:
        roots: dict[str, str] = {}
        for f in self.files:
            if f.role == "source" and f.language:
                roots.setdefault(f.project_root(self.project), f.language)
        # ensure the audited project is present
        roots.setdefault(self.project,
                         next((f.language for f in self.files
                               if f.role == "source" and f.language),
                              "python"))
        return sorted(roots.items())


def _src(rel, text, lang):
    return CorpusFile(rel, text, lang, "source")


def _man(rel, text):
    return CorpusFile(rel, text, "", "manifest")


# All credentials below are obvious placeholders, never valid.
_CASES: tuple[CorpusCase, ...] = (
    # ---- AI001 authorization -------------------------------------------------
    CorpusCase(
        "AI001-pos", "AI001", EXPECT_POSITIVE, "api",
        (_src("api/OrdersController.cs",
              "public class OrdersController {\n"
              "  [HttpGet(\"{id}\")]\n"
              "  public Order Get(int id) {\n"
              "    return _db.Orders.Find(id);\n"
              "  }\n}\n", "csharp"),),
        "the endpoint fetches a record by a request id and returns it with no "
        "ownership or tenant scoping and no authorization attribute.",
        target=Target("api/OrdersController.cs", 3, 5)),
    CorpusCase(
        "AI001-neg", "AI001", EXPECT_NEGATIVE, "web",
        (_src("web/app/api/pay/route.ts",
              "import { backend } from '@/lib/proxy';\n"
              "export async function POST(req: Request) {\n"
              "  return backend('/api/payments', req);\n"
              "}\n", "typescript"),
         _src("web/lib/proxy.ts",
              "export async function backend(path: string, req: Request) {\n"
              "  return fetch('http://api' + path, { method: req.method });\n"
              "}\n", "typescript"),
         _src("web/middleware.ts",
              "export function middleware(req) {\n"
              "  const t = req.cookies.get('session');\n"
              "  if (!t) return redirectToLogin();\n"
              "  return next();\n"
              "}\n", "typescript"),
         _src("api/Endpoints.cs",
              "app.MapPost(\"/api/payments\", Handler)"
              ".RequireAuthorization();\n", "csharp")),
        "the route proxies to a backend endpoint that calls "
        "RequireAuthorization(), and project middleware enforces a session "
        "cookie — authorization is present across files."),
    CorpusCase(
        "AI001-abstain", "AI001", EXPECT_ABSTAIN, "web",
        (_src("web/app/api/x/route.ts",
              "import { backend } from '@/lib/proxy';\n"
              "export async function POST(req: Request) {\n"
              "  return backend('/api/unknown', req);\n"
              "}\n", "typescript"),),
        "the proxy and the backend endpoint for '/api/unknown' are not in the "
        "index (unresolved facts) — authorization cannot be judged."),
    # ---- AI002 input_handling ------------------------------------------------
    CorpusCase(
        "AI002-pos", "AI002", EXPECT_POSITIVE, "svc",
        (_src("svc/search.py",
              "def search(request):\n"
              "    term = request.args['q']\n"
              "    return db.execute('SELECT * FROM items WHERE name = ' "
              "+ term)\n", "python"),),
        "request input is concatenated into a SQL string with no "
        "parameterization on this path.",
        target=Target("svc/search.py", 2, 3)),
    CorpusCase(
        "AI002-neg-sql", "AI002", EXPECT_NEGATIVE, "svc",
        (_src("svc/param_search.py",
              "def search(request):\n"
              "    term = request.args['q']\n"
              "    return db.execute('SELECT * FROM items WHERE name = %s', "
              "[term])\n", "python"),),
        "the query is parameterized (placeholder + bound args); the input "
        "never becomes SQL text."),
    CorpusCase(
        "AI002-neg-dompurify", "AI002", EXPECT_NEGATIVE, "web",
        (_src("web/render.ts",
              "import DOMPurify from 'dompurify';\n"
              "export function render(raw: string, el: HTMLElement) {\n"
              "  el.innerHTML = DOMPurify.sanitize(raw);\n"
              "}\n", "typescript"),),
        "untrusted HTML is sanitized with a real DOMPurify import before "
        "innerHTML."),
    # ---- AI003 credentials ---------------------------------------------------
    CorpusCase(
        "AI003-pos", "AI003", EXPECT_POSITIVE, "api",
        (_src("api/DbContextFactory.cs",
              "class AppDbContextFactory {\n"
              "  DbContext Create() {\n"
              "    var o = new Options();\n"
              "    o.UseNpgsql(\"Host=localhost;Username=postgres;"
              "Password=hunter2placeholder\");\n"
              "    return new AppDbContext(o);\n"
              "  }\n}\n", "csharp"),),
        "a literal connection string with an inline Password= is committed in "
        "a DbContext factory.",
        target=Target("api/DbContextFactory.cs", 4, 4)),
    CorpusCase(
        "AI003-neg", "AI003", EXPECT_NEGATIVE, "api",
        (_src("api/EnvConfig.cs",
              "class EnvConfig {\n"
              "  string Conn() => "
              "Environment.GetEnvironmentVariable(\"DB_CONN\");\n"
              "}\n", "csharp"),),
        "the connection string is read from an environment variable, not "
        "committed as a literal."),
    CorpusCase(
        "AI003-abstain", "AI003", EXPECT_ABSTAIN, "api",
        (_src("api/Partial.cs",
              "class Partial {\n"
              "  string Conn() => _settings.ConnectionString;\n"
              "}\n", "csharp"),),
        "whether _settings.ConnectionString is a literal or env-backed is not "
        "visible here."),
    # ---- AI004 concurrency ---------------------------------------------------
    CorpusCase(
        "AI004-pos", "AI004", EXPECT_POSITIVE, "svc",
        (_src("svc/Checkout.cs",
              "void Checkout(Order o) {\n"
              "    _db.Orders.Add(o);\n"
              "    _db.SaveChanges();\n"
              "    _payments.Charge(o.Total);\n"
              "    _db.Orders.MarkPaid(o.Id);\n"
              "    _db.SaveChanges();\n"
              "}\n", "csharp"),),
        "TWO separate SaveChanges commits straddle an external charge with no "
        "surrounding transaction/outbox — a crash after the first commit or "
        "the charge leaves order and payment state inconsistent.",
        target=Target("svc/Checkout.cs", 2, 6)),
    CorpusCase(
        "AI004-neg", "AI004", EXPECT_NEGATIVE, "svc",
        (_src("svc/TxCheckout.cs",
              "void Checkout(Order o) {\n"
              "    using var tx = _db.Database.BeginTransaction();\n"
              "    _db.Orders.Add(o); _db.Orders.MarkPaid(o.Id);\n"
              "    _db.SaveChanges(); tx.Commit();\n"
              "}\n", "csharp"),),
        "the multi-step change is wrapped in one explicit transaction and "
        "committed atomically."),
    CorpusCase(
        "AI004-abstain", "AI004", EXPECT_ABSTAIN, "svc",
        (_src("svc/Frag4.cs",
              "void Do(Order o) {\n"
              "    _svc.ApplyTransaction(o);\n"
              "}\n", "csharp"),),
        "the transactional behavior is inside _svc.ApplyTransaction, which is "
        "not in context."),
    # ---- AI005 error_handling ------------------------------------------------
    CorpusCase(
        "AI005-pos", "AI005", EXPECT_POSITIVE, "svc",
        (_src("svc/worker.py",
              "def run(job):\n"
              "    try:\n"
              "        process(job)\n"
              "    except Exception:\n"
              "        pass\n"
              "    return 'ok'\n", "python"),),
        "a broad except discards the failure and the function returns success, "
        "so the caller cannot tell the job failed.",
        target=Target("svc/worker.py", 4, 6)),
    CorpusCase(
        "AI005-neg", "AI005", EXPECT_NEGATIVE, "svc",
        (_src("svc/reraise_worker.py",
              "def run(job):\n"
              "    try:\n"
              "        process(job)\n"
              "    except Exception:\n"
              "        logger.exception('failed')\n"
              "        raise\n", "python"),),
        "the handler logs and re-raises; the failure propagates."),
    CorpusCase(
        "AI005-abstain", "AI005", EXPECT_ABSTAIN, "svc",
        (_src("svc/frag5.py",
              "def run(job):\n"
              "    try:\n"
              "        return _runner.execute(job)\n"
              "    except Exception:\n"
              "        return _runner.fallback(job)\n", "python"),),
        "whether _runner.fallback properly handles the failure or hides it is "
        "not visible here — cannot judge the error handling."),
    # ---- AI006 api_contract --------------------------------------------------
    CorpusCase(
        "AI006-pos", "AI006", EXPECT_POSITIVE, "svc",
        (_src("svc/create.py",
              "def create(request):\n"
              "    data = request.json\n"
              "    total = data['price'] * data['qty']\n"
              "    return persist(data['name'], total)\n", "python"),),
        "request-body fields (price, qty, name) are read and used directly "
        "with no validation of presence or type in this handler.",
        target=Target("svc/create.py", 2, 4)),
    CorpusCase(
        "AI006-neg", "AI006", EXPECT_NEGATIVE, "svc",
        (_src("svc/validated_create.py",
              "class Body(BaseModel):\n"
              "    name: str\n"
              "    price: float\n"
              "    qty: int\n"
              "def create(request):\n"
              "    body = Body.model_validate(request.json)\n"
              "    return persist(body.name, body.price * body.qty)\n",
              "python"),),
        "the body is validated against a pydantic model before use."),
    CorpusCase(
        "AI006-abstain", "AI006", EXPECT_ABSTAIN, "svc",
        (_src("svc/frag6.py",
              "def create(request):\n"
              "    return _api.persist(request.json)\n", "python"),),
        "validation, if any, happens inside _api.persist, not in context."),
    # ---- AI007 dependency_integration ----------------------------------------
    CorpusCase(
        "AI007-pos", "AI007", EXPECT_POSITIVE, "web",
        (_src("web/client.ts",
              "import { Client } from 'acme-widgets';\n"
              "const c = new Client();\n"
              "export const go = () => c.start();\n", "typescript"),
         _man("web/package.json",
              "{\n  \"name\": \"web\",\n  \"dependencies\": {\n"
              "    \"react\": \"18.2.0\",\n    \"dompurify\": \"3.0.0\"\n"
              "  }\n}\n")),
        "the code imports 'acme-widgets' but the manifest declares only react "
        "and dompurify — the dependency is undeclared (manifest proves it).",
        target=Target("web/client.ts", 1, 1)),
    CorpusCase(
        "AI007-neg", "AI007", EXPECT_NEGATIVE, "web",
        (_src("web/declared_client.ts",
              "import DOMPurify from 'dompurify';\n"
              "export const load = (s: string) => DOMPurify.sanitize(s);\n",
              "typescript"),
         _man("web/package.json",
              "{\n  \"name\": \"web\",\n  \"dependencies\": {\n"
              "    \"dompurify\": \"3.0.0\"\n  }\n}\n")),
        "the imported package (dompurify) is declared in the manifest and used "
        "with a real member."),
    CorpusCase(
        "AI007-out-of-scope", "AI007", EXPECT_NEGATIVE, "svc",
        (_src("svc/handler.py",
              "def handler(request):\n"
              "    uid = request.args['id']\n"
              "    return db.execute('SELECT * FROM t WHERE id=' + uid)\n",
              "python"),),
        "this file has a SQL-injection shape (an AI002 concern) but NO "
        "dependency problem — an AI007 audit must NOT report it; a dependency "
        "claim here would be out-of-scope."),
    CorpusCase(
        "AI007-abstain", "AI007", EXPECT_ABSTAIN, "api",
        (_src("api/Extensions.cs",
              "using Company.Shared.Telemetry;\n"
              "public static class Extensions {\n"
              "  public static void AddX(this IServiceCollection s) { }\n"
              "}\n", "csharp"),),
        "whether Company.Shared.Telemetry maps to a declared package needs a "
        "manifest, which is not in this snippet."),
    # ---- AI008 incomplete_code -----------------------------------------------
    CorpusCase(
        "AI008-pos", "AI008", EXPECT_POSITIVE, "svc",
        (_src("svc/Payments.cs",
              "public decimal Charge(Order o) {\n"
              "    throw new NotImplementedException();\n"
              "}\n", "csharp"),),
        "a live charging method is a NotImplemented stub.",
        target=Target("svc/Payments.cs", 2, 2)),
    CorpusCase(
        "AI008-neg", "AI008", EXPECT_NEGATIVE, "svc",
        (_src("svc/Linter.cs",
              "public bool HasMarker(string line) {\n"
              "    return line.Contains(\"TODO\") || line.Contains(\"FIXME\");\n"
              "}\n", "csharp"),),
        "a lint helper matches the literal tokens TODO and FIXME as string "
        "data it scans for; the tokens are values under comparison, not an "
        "unfinished stub or placeholder in a live path."),
    CorpusCase(
        "AI008-abstain", "AI008", EXPECT_ABSTAIN, "svc",
        (_src("svc/Frag8.cs",
              "public decimal Charge(Order o) {\n"
              "    // TODO: confirm _billing.Charge covers refunds\n"
              "    return _billing.Charge(o);\n"
              "}\n", "csharp"),),
        "completeness depends on _billing.Charge, not in context; the TODO is "
        "a question about an external call, not a visible stub."),
)


# ---- W3-E4B1: the pre-registered HOLDOUT split -------------------------------------
# One positive, one negative, one abstention per query. Snippets, file names,
# and phrasing are deliberately DIFFERENT from the development split above, so
# behaviour changes tuned on development are judged on unseen material.
def _hold(case_id, query_id, kind, project, files, reason, target=None):
    return CorpusCase(case_id, query_id, kind, project, files, reason,
                      target=target, split=SPLIT_HOLDOUT)


_HOLDOUT: tuple[CorpusCase, ...] = (
    # ---- AI001 authorization -------------------------------------------------
    _hold(
        "AI001-hold-pos", "AI001", EXPECT_POSITIVE, "web2",
        (_src("web2/app/api/records/route.ts",
              "import { store } from '@/lib/store';\n"
              "export async function DELETE(req: Request) {\n"
              "  const id = new URL(req.url).searchParams.get('id');\n"
              "  await store.remove('records', id);\n"
              "  return new Response(null, { status: 204 });\n"
              "}\n", "typescript"),
         _src("web2/lib/store.ts",
              "export const store = {\n"
              "  async remove(table: string, id: string | null) {\n"
              "    return db.exec('delete', table, id);\n"
              "  },\n"
              "};\n", "typescript"),
         _src("web2/middleware.ts",
              "export function middleware(req) {\n"
              "  const { pathname } = new URL(req.url);\n"
              "  if (pathname.startsWith('/admin')) {\n"
              "    const t = req.cookies.get('opsession');\n"
              "    if (!t) return redirectToLogin();\n"
              "  }\n"
              "  return next();\n"
              "}\n", "typescript")),
        "a destructive DELETE route removes a record by a request id; the "
        "project middleware only gates /admin paths, so /api/records is "
        "reachable with no session or ownership check — all the context "
        "needed to see the gap is in the payload.",
        target=Target("web2/app/api/records/route.ts", 2, 5)),
    _hold(
        "AI001-hold-neg", "AI001", EXPECT_NEGATIVE, "billing",
        (_src("billing/InvoiceEndpoints.cs",
              "app.MapGet(\"/api/invoices/{id}\", async (int id, "
              "ClaimsPrincipal user, Db db) => {\n"
              "    var uid = user.FindFirst(\"sub\")!.Value;\n"
              "    return await db.Invoices\n"
              "        .Where(i => i.Id == id && i.OwnerId == uid)\n"
              "        .FirstAsync();\n"
              "}).RequireAuthorization();\n", "csharp"),),
        "the endpoint requires authorization and additionally scopes the "
        "query to the caller's own OwnerId claim — both the gate and the "
        "ownership filter are visible."),
    _hold(
        "AI001-hold-abstain", "AI001", EXPECT_ABSTAIN, "portal",
        (_src("portal/app/api/export/route.ts",
              "import { assertAccess } from '@/lib/access';\n"
              "export async function POST(req: Request) {\n"
              "  await assertAccess(req);\n"
              "  return runExport(req);\n"
              "}\n", "typescript"),),
        "the route delegates its gate to assertAccess, whose module is not "
        "in the index (unresolved import) — whether it actually enforces "
        "anything cannot be judged from this payload."),
    # ---- AI002 input_handling ------------------------------------------------
    _hold(
        "AI002-hold-pos", "AI002", EXPECT_POSITIVE, "svc2",
        (_src("svc2/handlers/export.py",
              "import os\n"
              "def export(request):\n"
              "    name = request.args['file']\n"
              "    os.system('zip archive.zip ' + name)\n"
              "    return 'queued'\n", "python"),),
        "a request-supplied file name is concatenated into a shell command "
        "with no quoting or validation on this path.",
        target=Target("svc2/handlers/export.py", 3, 4)),
    _hold(
        "AI002-hold-neg", "AI002", EXPECT_NEGATIVE, "svc2",
        (_src("svc2/repo/lookup.py",
              "def lookup(session, request):\n"
              "    term = request.args['q']\n"
              "    return session.query(Item)"
              ".filter(Item.name == term).all()\n", "python"),),
        "the request value is bound through an ORM equality filter; it never "
        "becomes query text."),
    _hold(
        "AI002-hold-abstain", "AI002", EXPECT_ABSTAIN, "svc2",
        (_src("svc2/api/find.py",
              "def find(request):\n"
              "    term = request.args['q']\n"
              "    return _repo.match(term)\n", "python"),),
        "the sink is inside _repo.match, which is not in context — whether "
        "the term is parameterized there cannot be judged."),
    # ---- AI003 credentials ---------------------------------------------------
    _hold(
        "AI003-hold-pos", "AI003", EXPECT_POSITIVE, "cfg",
        (_src("cfg/settings.py",
              "DB_HOST = 'db.internal'\n"
              "DB_USER = 'svc'\n"
              "DB_PASSWORD = 'pl4ceholder-not-real'\n"
              "def dsn():\n"
              "    return f'host={DB_HOST} user={DB_USER} "
              "password={DB_PASSWORD}'\n", "python"),),
        "a literal database password is committed in a settings module and "
        "fed into the DSN.",
        target=Target("cfg/settings.py", 3, 3)),
    _hold(
        "AI003-hold-neg", "AI003", EXPECT_NEGATIVE, "app2",
        (_src("app2/config/db.ts",
              "export const dbToken = process.env.DB_TOKEN;\n"
              "export function connect() {\n"
              "  return open({ auth: dbToken });\n"
              "}\n", "typescript"),),
        "the credential is read from the environment at runtime; no literal "
        "value is committed."),
    _hold(
        "AI003-hold-abstain", "AI003", EXPECT_ABSTAIN, "api2",
        (_src("api2/Startup/DbSetup.cs",
              "class DbSetup {\n"
              "  string Resolve() => Registry.Get(\"ConnectionString\");\n"
              "}\n", "csharp"),),
        "whether Registry.Get returns an env-backed value or a committed "
        "literal is decided elsewhere, outside this payload."),
    # ---- AI004 concurrency ---------------------------------------------------
    _hold(
        "AI004-hold-pos", "AI004", EXPECT_POSITIVE, "orders",
        (_src("orders/Dispatcher.cs",
              "public class Dispatcher {\n"
              "  public void Send(Order o) {\n"
              "    Task.Run(() => _mail.Notify(o));\n"
              "    o.Status = \"sent\";\n"
              "    _db.SaveChanges();\n"
              "  }\n}\n", "csharp"),),
        "the notification is fire-and-forget (an unobserved Task.Run whose "
        "failure is lost) while the order is committed as sent — the state "
        "and the side effect can diverge.",
        target=Target("orders/Dispatcher.cs", 3, 5)),
    _hold(
        "AI004-hold-neg", "AI004", EXPECT_NEGATIVE, "jobs",
        (_src("jobs/counter.py",
              "import threading\n"
              "class Counter:\n"
              "    def __init__(self):\n"
              "        self._lock = threading.Lock()\n"
              "        self.value = 0\n"
              "    def bump(self):\n"
              "        with self._lock:\n"
              "            self.value += 1\n", "python"),),
        "the shared mutable counter is only touched under an explicit lock."),
    _hold(
        "AI004-hold-abstain", "AI004", EXPECT_ABSTAIN, "billing2",
        (_src("billing2/Poster.cs",
              "public class Poster {\n"
              "  public async Task Post(Entry e) {\n"
              "    await _ledger.ApplyAsync(e);\n"
              "  }\n}\n", "csharp"),),
        "atomicity lives inside _ledger.ApplyAsync, which is not in context."),
    # ---- AI005 error_handling ------------------------------------------------
    _hold(
        "AI005-hold-pos", "AI005", EXPECT_POSITIVE, "client",
        (_src("client/sync.ts",
              "export async function sync(item: Item) {\n"
              "  try {\n"
              "    await push(item);\n"
              "  } catch (err) {\n"
              "    console.error(err);\n"
              "  }\n"
              "  return { ok: true };\n"
              "}\n", "typescript"),),
        "the catch only logs and the function still returns ok:true, so the "
        "caller can never observe the failed push.",
        target=Target("client/sync.ts", 4, 7)),
    _hold(
        "AI005-hold-neg", "AI005", EXPECT_NEGATIVE, "svc3",
        (_src("svc3/Store.cs",
              "public class Store {\n"
              "  public void Save(Doc d) {\n"
              "    try { _io.Write(d); }\n"
              "    catch (IOException e) {\n"
              "      throw new StorageException(\"write failed\", e);\n"
              "    }\n"
              "  }\n}\n", "csharp"),),
        "the handler wraps the failure with context and rethrows a typed "
        "exception; the caller still sees it."),
    _hold(
        "AI005-hold-abstain", "AI005", EXPECT_ABSTAIN, "worker2",
        (_src("worker2/run.py",
              "def run(job):\n"
              "    try:\n"
              "        return process(job)\n"
              "    except TransferError:\n"
              "        return _pipeline.reroute(job)\n", "python"),),
        "whether _pipeline.reroute preserves or hides the failure is not "
        "visible in this payload."),
    # ---- AI006 api_contract --------------------------------------------------
    _hold(
        "AI006-hold-pos", "AI006", EXPECT_POSITIVE, "shop",
        (_src("shop/routes/orders.ts",
              "app.post('/orders', (req, res) => {\n"
              "  const b = req.body;\n"
              "  res.json(save(b.sku, b.qty * b.price));\n"
              "});\n", "typescript"),),
        "body fields (sku, qty, price) are read and multiplied straight off "
        "req.body with no presence or type validation in this handler.",
        target=Target("shop/routes/orders.ts", 2, 3)),
    _hold(
        "AI006-hold-neg", "AI006", EXPECT_NEGATIVE, "shop",
        (_src("shop/routes/checkout.ts",
              "import { z } from 'zod';\n"
              "const Body = z.object({ sku: z.string(), "
              "qty: z.number().int().positive() });\n"
              "export async function handle(req: Request) {\n"
              "  const b = Body.parse(await req.json());\n"
              "  return charge(b.sku, b.qty);\n"
              "}\n", "typescript"),),
        "the body is parsed against an explicit zod schema before any use."),
    _hold(
        "AI006-hold-abstain", "AI006", EXPECT_ABSTAIN, "intake",
        (_src("intake/app.py",
              "def create(request):\n"
              "    payload = request.get_json()\n"
              "    return _svc.submit(payload)\n", "python"),),
        "validation, if any, would live in _svc.submit, which is not in "
        "context."),
    # ---- AI007 dependency_integration ----------------------------------------
    _hold(
        "AI007-hold-pos", "AI007", EXPECT_POSITIVE, "tool",
        (_src("tool/report.py",
              "import flask\n"
              "import quickchart_gen\n"
              "def render(data):\n"
              "    return quickchart_gen.make(data)\n", "python"),
         _man("tool/requirements.txt",
              "flask==3.0.0\nrequests==2.32.0\n")),
        "the code imports quickchart_gen but the requirements manifest "
        "declares only flask and requests — the dependency is undeclared and "
        "the manifest in the payload proves it.",
        target=Target("tool/report.py", 2, 2)),
    _hold(
        "AI007-hold-neg", "AI007", EXPECT_NEGATIVE, "tool",
        (_src("tool/fetch.py",
              "import requests\n"
              "def get(url):\n"
              "    return requests.get(url, timeout=5)\n", "python"),
         _man("tool/requirements.txt",
              "flask==3.0.0\nrequests==2.32.0\n")),
        "the imported package is declared in the manifest and used through a "
        "real, existing member."),
    _hold(
        "AI007-hold-abstain", "AI007", EXPECT_ABSTAIN, "metrics",
        (_src("metrics/push.py",
              "from vendorkit.metrics import push_gauge\n"
              "def emit(name, value):\n"
              "    push_gauge(name, value)\n", "python"),),
        "there is no manifest in this project's payload, so whether "
        "vendorkit is declared cannot be checked."),
    # ---- AI008 incomplete_code -----------------------------------------------
    _hold(
        "AI008-hold-pos", "AI008", EXPECT_POSITIVE, "pay",
        (_src("pay/refunds.py",
              "def refund(order):\n"
              "    raise NotImplementedError('refund flow')\n", "python"),),
        "a live refund path is an explicit NotImplementedError stub.",
        target=Target("pay/refunds.py", 2, 2)),
    _hold(
        "AI008-hold-neg", "AI008", EXPECT_NEGATIVE, "lint",
        (_src("lint/test_scan.py",
              "def test_scan_reports_markers():\n"
              "    found = scan_line('total = 1  # TODO recheck rounding')\n"
              "    assert found == ['TODO']\n", "python"),),
        "the TODO token appears only as string DATA inside a test asserting "
        "what a scanner reports — it is tool input, not an unfinished path."),
    _hold(
        "AI008-hold-abstain", "AI008", EXPECT_ABSTAIN, "ui",
        (_src("ui/uploader.ts",
              "export function flushQueue(q: Item[]) {\n"
              "  // TODO: confirm client.flush batches correctly under retry\n"
              "  return client.flush(q);\n"
              "}\n", "typescript"),),
        "completeness depends on client.flush, which is not in context; the "
        "TODO questions an external call, it does not mark a visible stub."),
)


def cases(split: str | None = SPLIT_DEVELOPMENT) -> tuple[CorpusCase, ...]:
    """The pre-registered corpus. Default is the DEVELOPMENT split (the set
    every earlier measurement ran on); pass SPLIT_HOLDOUT for the holdout set
    or None for both."""
    if split is None:
        return _CASES + _HOLDOUT
    if split == SPLIT_HOLDOUT:
        return _HOLDOUT
    return _CASES


def holdout_cases() -> tuple[CorpusCase, ...]:
    return _HOLDOUT


def corpus_digest(corpus: tuple[CorpusCase, ...] | None = None) -> str:
    """A stable digest over the ACTUAL corpus passed (defaults to the
    development split). Two different corpora never share a digest; the split
    label is part of each case's identity."""
    corpus = corpus if corpus is not None else _CASES
    blob = json.dumps(
        [[c.case_id, c.query_id, c.kind, c.project, c.split,
          [[f.rel, f.text, f.language, f.role] for f in c.files],
          c.reason,
          None if c.target is None else
          [c.target.file, c.target.line_start, c.target.line_end]]
         for c in corpus],
        ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class CasePlan:
    case_id: str
    query_id: str
    category: str
    kind: str
    reason: str
    project: str
    unit_id: str
    context_digest: str
    input_bytes: int
    sent_files: list[str] = field(default_factory=list)
    sent_spans: dict[str, list[list[int]]] = field(default_factory=dict)
    target: list | None = None       # [file, line_start, line_end] or None
    split: str = SPLIT_DEVELOPMENT   # which pre-registered split the case is in
