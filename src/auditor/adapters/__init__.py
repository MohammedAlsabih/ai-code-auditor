from __future__ import annotations

from auditor.adapters.dotnet.adapter import DotnetAdapter
from auditor.adapters.java.adapter import JavaAdapter
from auditor.adapters.python.adapter import PythonAdapter
from auditor.adapters.typescript.adapter import TypeScriptAdapter


def default_adapters():
    return [PythonAdapter(), TypeScriptAdapter(), JavaAdapter(), DotnetAdapter()]
