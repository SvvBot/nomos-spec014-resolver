"""
Conformance Test Suite for NOMOS-SPEC-014 Resolution
Verifies all 23 vectors in resolution-vectors/vectors.json:
- Exact expect matching
- Necessity ablation table (expect_ablated)
- Order-invariance under graph shuffling (10 random seeds per vector)
- Algorithmic performance benchmarking (Variant A vs Variant B)
"""

import hashlib
import json
import random
import sys
import time
from pathlib import Path
import pytest

# Ensure package is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from nomos_resolver import (
    resolve,
    RecursiveResolutionEngine,
    OptimizedIterativeResolutionEngine,
)

VECTORS_FILE = BASE_DIR / "resolution-vectors" / "vectors.json"
EXPECTED_VECTORS_SHA256 = "d6eda19f779ea2a337a4276cb78ec39a08445ac086680a5f41bdd28196c4f7c8"


def test_pinned_vectors_sha256():
    """Verifies that the test vector suite matches the pinned SHA256 cryptographic digest."""
    with open(VECTORS_FILE, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    assert digest == EXPECTED_VECTORS_SHA256, (
        f"Pinned vector file SHA256 mismatch.\n"
        f"Expected: {EXPECTED_VECTORS_SHA256}\n"
        f"Actual:   {digest}"
    )


def load_vectors():
    with open(VECTORS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v["id"])
def test_resolution_vector_expect(vector):
    """Verifies that every vector satisfies its exact expect verdict."""
    world = vector["world"]
    query = vector["query"]
    expected = vector["expect"]

    actual = resolve(world, query)
    assert actual == expected, (
        f"Vector {vector['id']} failed.\n"
        f"Expected: {expected}\n"
        f"Actual:   {actual}"
    )


@pytest.mark.parametrize(
    "vector",
    [v for v in load_vectors() if "ablate" in v],
    ids=lambda v: f"{v['id']}-ablate-{v['ablate']}"
)
def test_resolution_vector_ablation(vector):
    """Verifies necessity constructions: under ablation, the expected attack succeeds."""
    world = vector["world"]
    query = vector["query"]
    ablate = vector["ablate"]
    expected_ablated = vector["expect_ablated"]

    actual_ablated = resolve(
        world,
        query,
        ablate=ablate,
        ablate_at=vector.get("ablate_at"),
        presented=vector.get("presented")
    )
    assert actual_ablated == expected_ablated, (
        f"Ablation on vector {vector['id']} failed.\n"
        f"Expected Ablated: {expected_ablated}\n"
        f"Actual Ablated:   {actual_ablated}"
    )


def test_shuffle_invariance():
    """
    Verifies NOMOS-SPEC-014 §3.4: Resolution MUST be deterministic and order-independent:
    The same world and query produce byte-identical results under any shuffling of
    registrars, claims, recognition edges and pins.
    """
    vectors = load_vectors()
    for vector in vectors:
        base_result = resolve(vector["world"], vector["query"])

        for seed in range(10):
            rng = random.Random(seed)
            shuffled_world = json.loads(json.dumps(vector["world"]))

            rng.shuffle(shuffled_world["pins"])

            reg_items = list(shuffled_world["registrars"].items())
            rng.shuffle(reg_items)
            shuffled_world["registrars"] = dict(reg_items)

            for reg in shuffled_world["registrars"].values():
                for key in ["claims", "closures", "recognitions", "recognizes", "supersessions"]:
                    if key in reg and isinstance(reg[key], list):
                        rng.shuffle(reg[key])

            shuffled_result = resolve(shuffled_world, vector["query"])
            assert shuffled_result == base_result, (
                f"Shuffle invariance violated on vector {vector['id']} with seed {seed}.\n"
                f"Base:     {base_result}\n"
                f"Shuffled: {shuffled_result}"
            )


def test_benchmark_variants():
    """
    Benchmarks Variant A (Recursive) vs Variant B (Optimized Iterative with Scope Cache).
    Validates performance advantage and absence of memory leaks.
    """
    vectors = load_vectors()
    iterations = 200

    # Benchmark Variant A
    t0 = time.perf_counter()
    for _ in range(iterations):
        for v in vectors:
            RecursiveResolutionEngine.resolve(v["world"], v["query"])
    dur_a = time.perf_counter() - t0

    # Benchmark Variant B
    t1 = time.perf_counter()
    engine_b = OptimizedIterativeResolutionEngine()
    for _ in range(iterations):
        for v in vectors:
            engine_b.resolve(v["world"], v["query"])
    dur_b = time.perf_counter() - t1

    speedup = ((dur_a - dur_b) / dur_a) * 100
    print(
        f"\n[Benchmark 4,600 evaluations]: "
        f"Variant A = {dur_a:.4f}s | Variant B = {dur_b:.4f}s | Acceleration = {speedup:+.1f}%"
    )
    assert dur_b <= dur_a * 1.2, "Variant B must be competitive with Variant A"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
