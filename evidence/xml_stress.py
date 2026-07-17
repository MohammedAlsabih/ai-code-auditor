"""Hypothesis 4: expat BLAP limits != general resource safety.
Deep/large/malformed XML with TIME + PEAK-MEMORY + NODE-COUNT measurement
(fourth round: the 38MB/x14 amplification figure must be reproducible, not a claim).
Rerun: python xml_stress.py   (stdlib only)
Reference (re-measured with THIS script, CPython 3.12.4 / expat 2.6.2 / Win 11):
  deep-50k parsed ~0.09s peak~14MB · wide 2.7MB -> 300001 nodes, peak~38MB (x14) ·
  entity bomb -> ParseError "limit on input amplification factor ... breached".
  (An earlier 48MB deep figure was a measurement-methodology artifact.)"""
import time
import tracemalloc
import xml.etree.ElementTree as ET

results = []

# 1) deep nesting (50k levels, small bytes)
deep = "<a>" * 50_000 + "</a>" * 50_000
tracemalloc.start()
t = time.perf_counter()
try:
    ET.fromstring(deep)
    _, peak = tracemalloc.get_traced_memory()
    results.append(("deep-50k", f"parsed peak_mem={peak/1e6:.0f}MB",
                    f"{time.perf_counter()-t:.2f}s"))
except Exception as e:
    results.append(("deep-50k", type(e).__name__, f"{time.perf_counter()-t:.2f}s"))
tracemalloc.stop()

# 2) wide: 300k nodes (~2.7MB) — just above the 2MB manifest cap
wide = "<r>" + "<d><g>com.x</g><a>y</a></d>" * 100_000 + "</r>"
tracemalloc.start()
t = time.perf_counter()
try:
    root = ET.fromstring(wide)
    n = sum(1 for _ in root.iter())
    _, peak = tracemalloc.get_traced_memory()
    results.append(("wide-100k-deps",
                    f"parsed nodes={n} peak_mem={peak/1e6:.0f}MB (x{peak/len(wide):.0f} of input)",
                    f"{time.perf_counter()-t:.2f}s len={len(wide)/1e6:.1f}MB"))
except Exception as e:
    results.append(("wide-100k-deps", type(e).__name__, f"{time.perf_counter()-t:.2f}s"))
tracemalloc.stop()

# 3) internal entity amplification (billion-laughs, small: 10 levels x10)
bomb = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a0 "x">'
        + "".join(f'<!ENTITY a{i+1} "{"&a%d;" % i * 10}">' for i in range(9))
        + "]><r>&a9;</r>")
t = time.perf_counter()
try:
    ET.fromstring(bomb)
    results.append(("entity-bomb-10^9", "parsed (NO protection!)", f"{time.perf_counter()-t:.2f}s"))
except Exception as e:
    results.append(("entity-bomb-10^9", f"{type(e).__name__}: {e}", f"{time.perf_counter()-t:.2f}s"))

# 4) malformed
t = time.perf_counter()
try:
    ET.fromstring("<a><b></a>")
    results.append(("malformed", "parsed?!", ""))
except Exception as e:
    results.append(("malformed", f"{type(e).__name__} (caught)", f"{time.perf_counter()-t:.3f}s"))

for r in results:
    print(" | ".join(r))
