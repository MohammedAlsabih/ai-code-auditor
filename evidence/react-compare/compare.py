"""Join eslint-results.json + prototype-results.json into a comparison table.

Category mapping (like-for-like):
  placement: react-hooks/rules-of-hooks  <->  R001/R002/R003
  deps:      react-hooks/exhaustive-deps <->  R004/R005
Per file+category: agree-flag | agree-clean | prototype-FP | prototype-FN
(ESLint is treated as ground truth for FP/FN labels.)
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
PLACEMENT = {"R001", "R002", "R003"}
DEPS = {"R004", "R005"}


def load() -> tuple[dict, dict]:
    eslint = {}
    for f in json.loads((HERE / "eslint-results.json").read_text(encoding="utf-8")):
        name = f["filePath"].replace("\\", "/").split("/")[-1]
        eslint[name] = [
            {"ruleId": m["ruleId"], "severity": m["severity"], "line": m["line"],
             "message": m["message"]}
            for m in f["messages"]
        ]
    proto_raw = json.loads((HERE / "prototype-results.json").read_text(encoding="utf-8"))
    proto = {name: r["findings"] for name, r in proto_raw["results"].items()}
    return eslint, proto


def main() -> None:
    eslint, proto = load()
    rows, fp, fn = [], [], []
    for name in sorted(set(eslint) | set(proto)):
        es = eslint.get(name, [])
        pr = proto.get(name, [])
        es_place = [m for m in es if m["ruleId"] == "react-hooks/rules-of-hooks"]
        es_deps = [m for m in es if m["ruleId"] == "react-hooks/exhaustive-deps"]
        pr_place = [f for f in pr if f["rule_id"] in PLACEMENT]
        pr_deps = [f for f in pr if f["rule_id"] in DEPS]
        verdicts = []
        for cat, e, p in (("placement", es_place, pr_place), ("deps", es_deps, pr_deps)):
            if e and p:
                verdicts.append(f"agree-flag[{cat}]")
            elif not e and not p:
                pass  # agree-clean, silent
            elif p and not e:
                verdicts.append(f"prototype-FP[{cat}]")
                fp.append((name, cat, [x["rule_id"] for x in p]))
            else:
                verdicts.append(f"prototype-FN[{cat}]")
                fn.append((name, cat, [x["ruleId"] for x in e]))
        es_str = "; ".join(f"{'ERROR' if m['severity'] == 2 else 'WARN'} {m['ruleId'].split('/')[-1]} L{m['line']}"
                           for m in es) or "clean"
        pr_str = "; ".join(f"{f['rule_id']} L{f['line']}" for f in pr) or "clean"
        verdict = " + ".join(verdicts) if verdicts else "agree-clean"
        rows.append((name, es_str, pr_str, verdict))

    w0 = max(len(r[0]) for r in rows)
    lines = ["| file | ESLint verdict | prototype verdict | classification |",
             "|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} |")
    lines.append("")
    lines.append(f"TOTALS: files={len(rows)}  prototype-FP={len(fp)}  prototype-FN={len(fn)}")
    lines.append(f"FP list: {fp}")
    lines.append(f"FN list: {fn}")
    out = "\n".join(lines)
    (HERE / "comparison.md").write_text(out, encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
