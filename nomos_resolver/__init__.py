"""
nomos-spec014-resolver
~~~~~~~~~~~~~~~~~~~~~~

Clean-room reference implementation of NOMOS-SPEC-014 Resolution (Draft 0.3.0).
Provides RFC 3339 temporal validity, graph cycle detection, witnessed demands,
three-valued Kleene scope evaluations, and iterative memoized resolution.
"""

from .resolver import (
    resolve,
    OptimizedIterativeResolutionEngine,
    RecursiveResolutionEngine,
    ScopeEvaluator,
    parse_rfc3339,
)
from .condition import eval_when_detail, T, F, U

__version__ = "0.3.0"
__all__ = [
    "resolve",
    "OptimizedIterativeResolutionEngine",
    "RecursiveResolutionEngine",
    "ScopeEvaluator",
    "parse_rfc3339",
    "eval_when_detail",
    "T",
    "F",
    "U",
]
