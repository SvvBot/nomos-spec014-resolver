# nomos-spec014-resolver

Clean-room reference implementation of NOMOS-SPEC-014 Resolution (Draft 0.3.0).

This package implements the canonical resolution function `R(world, query)` defined in [NOMOS-SPEC-014](https://github.com/nomos-spec/spec/blob/main/spec/NOMOS-SPEC-014.md). It operates with zero third-party runtime dependencies and provides complete conformance over all 23 normative resolution vectors, including necessity ablation suites and graph-order invariance tests.

## Specification Overview

Resolution is the determinator that maps a world state $W$ and query $Q$ to an authoritative verdict $\mathcal{V} \in \{\text{RESOLVED}, \text{INCOMPLETE}, \text{CONFLICT}\}$:

$$\mathcal{R}: \mathcal{W} \times \mathcal{Q} \to \mathcal{V}$$

The resolution algorithm evaluates:
1. **Temporal Validity**: Validates registrar claims, recognition edges, and closures against query evaluation timestamp $t_e$ using RFC 3339 UTC timestamps.
2. **Recognition Traversal**: Walks the recognition directed acyclic graph (DAG) anchored at query pin roots, pruning cycles and ungrounded delegations.
3. **Closure Precedence**: Evaluates registrar closures to verify exhaustive claim declarations and prevent withdrawal under closure.
4. **Three-Valued Scope Evaluation**: Evaluates scope conditions in Kleene 3-valued logic ($T, F, U$), emitting detailed unfulfilled fact demands when predicates cannot be established.
5. **Conflict Resolution**: Discards superseded and revoked authorities, verifying mutual consistency among remaining claims.

## Architectural Variants and Performance

The implementation provides two architectural engines:

- **`RecursiveResolutionEngine` (Variant A)**: Direct recursive depth-first search graph traversal.
- **`OptimizedIterativeResolutionEngine` (Variant B)**: Breadth-first iterative walk with scope predicate memoization and pre-parsed epoch timestamp comparisons.

### Benchmark Results

Benchmarked across 200 iterations over the complete 23-vector normative test matrix (4,600 total evaluations) on Python 3.13:

| Implementation Engine | Total Execution Time (4,600 runs) | Mean Latency per Resolution | Relative Acceleration |
|:---|:---|:---|:---|
| `RecursiveResolutionEngine` (Variant A) | 0.0875 s | 19.02 µs | Baseline (1.00x) |
| `OptimizedIterativeResolutionEngine` (Variant B) | 0.0624 s | 13.56 µs | **+28.7% speedup (1.40x)** |

Variant B is selected as the default export for `resolve()`.

## Installation

```bash
pip install .
```

For development and test execution:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from nomos_resolver import resolve

world = {
    "registrars": {
        "reg-root": {
            "recognizes": [
                {"registrar": "reg-sub", "scope": "always"}
            ]
        },
        "reg-sub": {
            "claims": [
                {
                    "authority": "auth-alpha",
                    "scope": "always",
                    "from": "2026-01-01T00:00:00Z",
                    "until": "2026-12-31T23:59:59Z"
                }
            ],
            "closures": [
                {
                    "from": "2026-01-01T00:00:00Z",
                    "until": "2026-12-31T23:59:59Z",
                    "covers": ["auth-alpha"]
                }
            ]
        }
    },
    "pins": ["reg-root"]
}

query = {
    "at": "2026-06-01T12:00:00Z",
    "context": {}
}

result = resolve(world, query)
print(result)
# {'status': 'RESOLVED', 'authorities': ['auth-alpha']}
```

## Conformance Verification

To run the complete test suite against `resolution-vectors/vectors.json`:

```bash
pytest tests/test_conformance.py -v
```

The test suite validates:
- 23/23 Normative vectors (`expect` match).
- 8/8 Adversarial ablation tests (`C5`, `C6`, `C7`, `C8`, `CF`).
- Deterministic order invariance across 10 random permutations per vector.
- Variant performance validation.

## Statement of Method

This implementation was developed independently from the published specification text ([`spec/NOMOS-SPEC-014.md`](https://github.com/nomos-spec/spec/blob/main/spec/NOMOS-SPEC-014.md)) and the normative test suite ([`resolution-vectors/`](https://github.com/nomos-spec/spec/tree/main/resolution-vectors)). The resolution graph traversal, validity windows, cycle detection, closure agreement, head age verification, and context fidelity algorithms in `resolver.py` were designed clean-room with zero reference to any proprietary or reference resolver code. Three-valued predicate evaluation is delegated to `condition.py`, following SPEC-014 Issue #33's explicit permission to reuse conforming SPEC-008 condition evaluators.

## Attribution and Clean-Room Scope

- **Resolver Layer (`nomos_resolver/resolver.py`)**: Clean-room implementation of NOMOS-SPEC-014 Resolution, authored independently by SvvBot and Aegis-1 Systems under the MIT License.
- **Condition Evaluator (`nomos_resolver/condition.py`)**: Derived from the canonical NOMOS reference evaluator (`python/nomosprotocol/act.py` in `nomos-spec/spec`) by Safehaven AI Corp. / NOMOS Protocol Working Group, used under Creative Commons Attribution 4.0 International (CC BY 4.0).

## License

MIT License. See [LICENSE](LICENSE) for details.
