"""
GhostStrike AI Engine — Tools Package
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from .shell_executor      import ShellExecutor,      TOOL_SCHEMA as SHELL_SCHEMA
from .code_runner         import CodeRunner,          TOOL_SCHEMA as CODE_SCHEMA
from .module_runner  import GhostStrikeRunner,   TOOL_SCHEMA as GHOST_SCHEMA
from .shodan_censys        import ShodanCensysProbe,  TOOL_SCHEMA as SHODAN_SCHEMA
from .network_capture     import NetworkCapture,      TOOL_SCHEMA as CAPTURE_SCHEMA
from .js_analyzer         import JsAnalyzer,          TOOL_SCHEMA as JS_SCHEMA
from .http_analyzer       import HttpAnalyzer,        TOOL_SCHEMA as HTTP_SCHEMA
# NOTE: webshell_toolkit.py is referenced by the original PhantomOps source this
# package was ported from, but was never actually present anywhere in that
# source tree -- a pre-existing gap in the code being ported, not something
# dropped during this port. Omitted rather than stubbed with a fake
# implementation of unknown scope.
from .c2_listener         import C2Listener,          TOOL_SCHEMA as C2_SCHEMA
from .osint_orchestrator  import OsintOrchestrator,   TOOL_SCHEMA as OSINT_SCHEMA
from .reasoning_engine    import ReasoningEngine,     TOOL_SCHEMA as REASON_SCHEMA

__all__ = [
    "ShellExecutor",    "SHELL_SCHEMA",
    "CodeRunner",       "CODE_SCHEMA",
    "GhostStrikeRunner","GHOST_SCHEMA",
    "ShodanCensysProbe","SHODAN_SCHEMA",
    "NetworkCapture",   "CAPTURE_SCHEMA",
    "JsAnalyzer",       "JS_SCHEMA",
    "HttpAnalyzer",     "HTTP_SCHEMA",
    "C2Listener",       "C2_SCHEMA",
    "OsintOrchestrator","OSINT_SCHEMA",
    "ReasoningEngine",  "REASON_SCHEMA",
]
