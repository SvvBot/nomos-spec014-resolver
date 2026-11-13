# Resolution vectors (NOMOS-SPEC-014, Draft 0.3.0)

The conformance vectors for [NOMOS-SPEC-014](../spec/NOMOS-SPEC-014.md): which authorities
govern an act in a context at a time, with evidence that the enumeration is complete relative
to the relying party's pinned registrars.

`vectors.json` holds 23 vectors. Each is a **world** (registrar records and pins), a **query**
(`context` + `at`), and the expected result:

- `expect` — what a conforming resolver answers;
- vectors with an `ablate` field also carry `expect_ablated` — what an implementation missing
  exactly that condition answers, i.e. the attack succeeding.

The eight attack vectors are NOMOS-SPEC-014 §8's necessity constructions, each built from
genuine artifacts alone. The C7 ablation judges membership at the vector's `ablate_at`, a stale
instant, while closures are still judged at the query time:

| Vector | Condition it proves necessary |
| --- | --- |
| `attack-applicability-hiding` | C5 — the set comes from pinned logs, never the carrier |
| `attack-jurisdiction-squatting` | C6 — a claim binds only within the certified scope (prevents wrongful refusal; an added authority never causes a wrongful commit) |
| `attack-zombie-authority` | C7 — membership is judged at `t`, not at a stale instant |
| `attack-starved-resolver` | C8 — an unreachable pinned registrar yields INCOMPLETE |
| `attack-stale-closure` | C8 — a stale closure yields INCOMPLETE |
| `attack-withdrawal-under-closure` | C8 — a closure must agree with the registrar's own log |
| `attack-stale-view` | C8 — a copy of a log older than the relying party's bound yields INCOMPLETE |
| `attack-misdescribed-act` | CF — a witness-required context field without its attestation is UNDECIDED, never FALSE: an unverified value cannot remove law |

A conforming resolver MUST produce every `expect`, MUST NOT produce any `expect_ablated`
outside an explicit test-only ablation mode, and MUST answer byte-identically under any
shuffling of registrars, claims, recognition edges and pins.

Queries MAY carry `witnessed` (field → attested witness classes); claims MAY carry
`witness_required` (field → class). The CF ablation reads witness-required fields as if bare
values counted.

The reference implementation (TypeScript, in the NOMOS platform) runs all 20 pre-CF vectors, the
necessity table (each attack succeeds under exactly its own ablation and under no other), and
the shuffle check in CI. The resolver is also mechanized step by step in Lean 4:
[`papers/resolution/lean/`](../papers/resolution/lean/). **An independent implementation that passes this file is the condition
for NOMOS-SPEC-014 leaving Draft** — see [IMPLEMENTING.md](../IMPLEMENTING.md). We invite one.
