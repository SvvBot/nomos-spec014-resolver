"""
NOMOS-SPEC-014: Resolution Reference Implementation
Implements clean-room Resolution function R(world, query) according to NOMOS-SPEC-014 (Draft 0.3.0).

Provides two architectural implementations:
- Variant A: RecursiveResolutionEngine (Recursive graph traversal, un-memoized)
- Variant B: OptimizedIterativeResolutionEngine (Iterative BFS, Scope Cache, Epoch Fast-Path)
"""

import datetime
from typing import Dict, Any, List, Set, Tuple, Optional
from .condition import eval_when_detail, T, F, U


def parse_rfc3339(ts_str: str) -> datetime.datetime:
    """Parses RFC 3339 timestamp with UTC normalization."""
    normalized = ts_str.replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


class ScopeEvaluator:
    """Evaluates scope predicates with three-valued logic and unparseable scope handling."""

    @staticmethod
    def eval_scope(
        scope_str: str,
        context: Dict[str, Any],
        witnessed: Optional[Dict[str, List[str]]] = None,
        witness_required: Optional[Dict[str, str]] = None,
        ablate_cf: bool = False
    ) -> Tuple[str, Set[str], List[Dict[str, str]]]:
        if not scope_str or scope_str == "always":
            return T, set(), []

        unwitnessed_demands = []
        effective_context = dict(context)

        # Context Fidelity (CF): If field is witness-required, check attestation
        if witness_required and not ablate_cf:
            for field, req_class in witness_required.items():
                is_attested = False
                if witnessed and field in witnessed:
                    classes = witnessed.get(field) or []
                    if req_class in classes:
                        is_attested = True
                if not is_attested:
                    if field in effective_context:
                        del effective_context[field]
                    unwitnessed_demands.append({"fact": field, "class": req_class})

        try:
            verdict, open_facts = eval_when_detail(scope_str, effective_context, decided_absent=("action_type",))
            if unwitnessed_demands:
                for demand in unwitnessed_demands:
                    open_facts.add(demand["fact"])
                verdict = U
            return verdict, open_facts, unwitnessed_demands
        except Exception:
            return U, {"__scope_unparseable__"}, []


# ==============================================================================
# Variant A: Recursive Graph Resolution Engine
# ==============================================================================
class RecursiveResolutionEngine:
    """
    Variant A: Traditional recursive depth-first resolution walk.
    """

    @classmethod
    def resolve(
        cls,
        world: Dict[str, Any],
        query: Dict[str, Any],
        ablate: Optional[str] = None,
        ablate_at: Optional[str] = None,
        presented: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        pins = world.get("pins", [])
        registrars = world.get("registrars", {})
        query_at_str = query.get("at", "2026-11-11T00:00:00Z")
        query_at = parse_rfc3339(query_at_str)
        context = query.get("context", {})
        witnessed = query.get("witnessed")
        max_head_age_seconds = world.get("max_head_age_seconds")

        pres = presented or world.get("presented")
        if ablate == "C5" and pres is not None:
            return {"status": "RESOLVED", "authorities": sorted(pres)}

        eval_at = query_at
        ab_at_str = ablate_at or world.get("ablate_at")
        if ablate == "C7" and ab_at_str:
            eval_at = parse_rfc3339(ab_at_str)

        missing_context_facts: Set[str] = set()
        unwitnessed_list: List[Dict[str, str]] = []
        unreachable_registrars: Set[str] = set()
        stale_closures: Set[str] = set()
        stale_heads: Set[str] = set()
        closure_disagreements: List[Dict[str, str]] = []

        reached_registrars: Dict[str, Dict[str, Any]] = {}
        visited_nodes: Set[str] = set()

        def walk(r_id: str):
            if r_id in visited_nodes:
                return
            visited_nodes.add(r_id)

            if r_id not in registrars:
                if ablate != "C8":
                    unreachable_registrars.add(r_id)
                return

            reg = registrars[r_id]
            reached_registrars[r_id] = reg

            edges = reg.get("recognitions", []) or reg.get("recognizes", [])
            for edge in edges:
                target_id = edge.get("to") or edge.get("registrar") or edge.get("id")
                edge_scope = edge.get("scope", "always")
                verdict, open_facts, _ = ScopeEvaluator.eval_scope(edge_scope, context)
                if verdict == T:
                    walk(target_id)
                elif verdict == U:
                    missing_context_facts.update(open_facts)

        for pin in pins:
            walk(pin)

        surviving_claims: Dict[str, List[Dict[str, Any]]] = {}
        exclusive_claims_by_reg: Dict[str, List[str]] = {}

        for r_id, reg in reached_registrars.items():
            surviving_claims[r_id] = []

            head_at_str = reg.get("head_at")
            if max_head_age_seconds is not None and ablate != "C8":
                if not head_at_str:
                    stale_heads.add(r_id)
                else:
                    head_dt = parse_rfc3339(head_at_str)
                    if (query_at - head_dt).total_seconds() > max_head_age_seconds:
                        stale_heads.add(r_id)

            cert_scope = reg.get("certified_scope", "always")
            cert_verdict = T
            if ablate != "C6":
                cert_verdict, open_facts, _ = ScopeEvaluator.eval_scope(cert_scope, context)
                if cert_verdict == U:
                    missing_context_facts.update(open_facts)

            revoked_set = set(reg.get("revoked", []))
            superseded_auths = set()
            for s in reg.get("supersessions", []):
                s_from_dt = parse_rfc3339(s.get("from", "1970-01-01T00:00:00Z"))
                if eval_at >= s_from_dt:
                    superseded_auths.add(s.get("superseded"))

            claims_true_on_context = []
            for claim in reg.get("claims", []):
                auth = claim.get("authority")
                if auth in revoked_set or auth in superseded_auths:
                    continue

                from_str = claim.get("from") or claim.get("at")
                if from_str and eval_at < parse_rfc3339(from_str):
                    continue
                until_str = claim.get("until")
                if until_str and eval_at >= parse_rfc3339(until_str):
                    continue

                surviving_claims[r_id].append(claim)

                if cert_verdict == T:
                    claim_scope = claim.get("scope", "always")
                    c_verdict, c_open, c_unwit = ScopeEvaluator.eval_scope(
                        claim_scope,
                        context,
                        witnessed=witnessed,
                        witness_required=claim.get("witness_required"),
                        ablate_cf=(ablate == "CF")
                    )
                    if c_verdict == T:
                        claims_true_on_context.append(claim)
                        if claim.get("exclusive"):
                            exclusive_claims_by_reg.setdefault(r_id, []).append(auth)
                    elif c_verdict == U:
                        missing_context_facts.update(c_open)
                        if c_unwit:
                            unwitnessed_list.extend(c_unwit)

            covering_closures = []
            for closure in reg.get("closures", []):
                c_at_str = closure.get("at")
                c_at = parse_rfc3339(c_at_str)
                if c_at > query_at:
                    continue
                max_days = closure.get("max_age_days", 90)
                if ablate != "C8" and (query_at - c_at).total_seconds() > max_days * 86400:
                    continue

                cl_scope = closure.get("scope", "always")
                cl_verdict, cl_open, _ = ScopeEvaluator.eval_scope(cl_scope, context)
                if cl_verdict == T:
                    covering_closures.append(closure)
                elif cl_verdict == U:
                    missing_context_facts.update(cl_open)

            if not covering_closures and ablate != "C8":
                stale_closures.add(r_id)

            if ablate != "C8" and covering_closures:
                surviving_auth_names = {c.get("authority") for c in surviving_claims[r_id]}
                true_claim_names = {c.get("authority") for c in claims_true_on_context}

                closed_authorities_union = set()
                for cl in covering_closures:
                    for auth in cl.get("authorities", []):
                        closed_authorities_union.add(auth)
                        if auth not in surviving_auth_names:
                            closure_disagreements.append({
                                "registrar": r_id,
                                "authority": auth,
                                "reason": "closed_but_not_claimed"
                            })

                for auth in true_claim_names:
                    if auth not in closed_authorities_union:
                        closure_disagreements.append({
                            "registrar": r_id,
                            "authority": auth,
                            "reason": "claimed_but_not_closed"
                        })

        if (
            missing_context_facts
            or unreachable_registrars
            or stale_closures
            or stale_heads
            or closure_disagreements
            or unwitnessed_list
        ):
            res = {"status": "INCOMPLETE"}
            if missing_context_facts:
                res["missing_context_facts"] = sorted(list(missing_context_facts))
            if unreachable_registrars:
                res["unreachable_registrars"] = sorted(list(unreachable_registrars))
            if stale_closures:
                res["stale_closures"] = sorted(list(stale_closures))
            if stale_heads:
                res["stale_heads"] = sorted(list(stale_heads))
            if closure_disagreements:
                unique_disagreements = []
                seen_cd = set()
                for cd in closure_disagreements:
                    k = (cd["registrar"], cd["authority"], cd["reason"])
                    if k not in seen_cd:
                        seen_cd.add(k)
                        unique_disagreements.append(cd)
                unique_disagreements.sort(key=lambda x: (x["registrar"], x["authority"], x["reason"]))
                res["closure_disagreements"] = unique_disagreements
            if unwitnessed_list:
                unique_unw = []
                seen_u = set()
                for u in unwitnessed_list:
                    k = (u["fact"], u["class"])
                    if k not in seen_u:
                        seen_u.add(k)
                        unique_unw.append(u)
                unique_unw.sort(key=lambda x: (x["fact"], x["class"]))
                res["unwitnessed"] = unique_unw
            return res

        regs_with_exclusive = [r for r, auths in exclusive_claims_by_reg.items() if auths]
        if len(regs_with_exclusive) >= 2:
            all_conflicts = set()
            for r in regs_with_exclusive:
                all_conflicts.update(exclusive_claims_by_reg[r])
            return {
                "status": "CONFLICT",
                "conflict_authorities": sorted(list(all_conflicts))
            }

        final_authorities = set()
        for r_id, reg in reached_registrars.items():
            cert_scope = reg.get("certified_scope", "always")
            if ablate != "C6":
                c_verdict, _, _ = ScopeEvaluator.eval_scope(cert_scope, context)
                if c_verdict != T:
                    continue

            for claim in reg.get("claims", []):
                auth = claim.get("authority")
                if auth in set(reg.get("revoked", [])):
                    continue
                from_str = claim.get("from") or claim.get("at")
                if from_str and eval_at < parse_rfc3339(from_str):
                    continue
                until_str = claim.get("until")
                if until_str and eval_at >= parse_rfc3339(until_str):
                    continue

                is_sup = False
                for s in reg.get("supersessions", []):
                    if s.get("superseded") == auth and eval_at >= parse_rfc3339(s.get("from", "1970-01-01T00:00:00Z")):
                        is_sup = True
                        break
                if is_sup:
                    continue

                claim_scope = claim.get("scope", "always")
                cl_verdict, _, _ = ScopeEvaluator.eval_scope(
                    claim_scope,
                    context,
                    witnessed=witnessed,
                    witness_required=claim.get("witness_required"),
                    ablate_cf=(ablate == "CF")
                )
                if cl_verdict == T:
                    final_authorities.add(auth)

        return {
            "status": "RESOLVED",
            "authorities": sorted(list(final_authorities))
        }


# ==============================================================================
# Variant B: Optimized Iterative Resolution Engine with Scope Memoization Cache
# ==============================================================================
class OptimizedIterativeResolutionEngine:
    """
    Variant B: Iterative BFS traversal with Memoized Scope Evaluation Cache.
    Accelerates multi-predicate evaluation across dense registrar graphs.
    """

    def __init__(self):
        self._cache = {}

    def _eval_scope_cached(
        self,
        scope_str: str,
        context: Dict[str, Any],
        witnessed: Optional[Dict[str, List[str]]] = None,
        witness_required: Optional[Dict[str, str]] = None,
        ablate_cf: bool = False
    ) -> Tuple[str, Set[str], List[Dict[str, str]]]:
        cache_key = (
            scope_str,
            tuple(sorted(context.items())),
            tuple(sorted((k, tuple(v)) for k, v in (witnessed or {}).items())),
            tuple(sorted((witness_required or {}).items())),
            ablate_cf
        )
        if cache_key in self._cache:
            verdict, open_facts, unwitnessed = self._cache[cache_key]
            return verdict, set(open_facts), [dict(d) for d in unwitnessed]

        res = ScopeEvaluator.eval_scope(scope_str, context, witnessed, witness_required, ablate_cf)
        self._cache[cache_key] = (res[0], set(res[1]), [dict(d) for d in res[2]])
        return res

    def resolve(
        self,
        world: Dict[str, Any],
        query: Dict[str, Any],
        ablate: Optional[str] = None,
        ablate_at: Optional[str] = None,
        presented: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        pins = world.get("pins", [])
        registrars = world.get("registrars", {})
        query_at_str = query.get("at", "2026-11-11T00:00:00Z")
        query_at = parse_rfc3339(query_at_str)
        context = query.get("context", {})
        witnessed = query.get("witnessed")
        max_head_age_seconds = world.get("max_head_age_seconds")

        pres = presented or world.get("presented")
        if ablate == "C5" and pres is not None:
            return {"status": "RESOLVED", "authorities": sorted(pres)}

        eval_at = query_at
        ab_at_str = ablate_at or world.get("ablate_at")
        if ablate == "C7" and ab_at_str:
            eval_at = parse_rfc3339(ab_at_str)

        missing_context_facts: Set[str] = set()
        unwitnessed_list: List[Dict[str, str]] = []
        unreachable_registrars: Set[str] = set()
        stale_closures: Set[str] = set()
        stale_heads: Set[str] = set()
        closure_disagreements: List[Dict[str, str]] = []

        reached_registrars: Dict[str, Dict[str, Any]] = {}
        visited: Set[str] = set()
        queue: List[str] = list(pins)

        # Iterative BFS graph traversal
        while queue:
            r_id = queue.pop(0)
            if r_id in visited:
                continue
            visited.add(r_id)

            if r_id not in registrars:
                if ablate != "C8":
                    unreachable_registrars.add(r_id)
                continue

            reg = registrars[r_id]
            reached_registrars[r_id] = reg

            edges = reg.get("recognitions", []) or reg.get("recognizes", [])
            for edge in edges:
                target_id = edge.get("to") or edge.get("registrar") or edge.get("id")
                edge_scope = edge.get("scope", "always")
                verdict, open_facts, _ = self._eval_scope_cached(edge_scope, context)
                if verdict == T:
                    if target_id not in visited:
                        queue.append(target_id)
                elif verdict == U:
                    missing_context_facts.update(open_facts)

        surviving_claims: Dict[str, List[Dict[str, Any]]] = {}
        exclusive_claims_by_reg: Dict[str, List[str]] = {}

        for r_id, reg in reached_registrars.items():
            surviving_claims[r_id] = []

            head_at_str = reg.get("head_at")
            if max_head_age_seconds is not None and ablate != "C8":
                if not head_at_str:
                    stale_heads.add(r_id)
                else:
                    head_dt = parse_rfc3339(head_at_str)
                    if (query_at - head_dt).total_seconds() > max_head_age_seconds:
                        stale_heads.add(r_id)

            cert_scope = reg.get("certified_scope", "always")
            cert_verdict = T
            if ablate != "C6":
                cert_verdict, open_facts, _ = self._eval_scope_cached(cert_scope, context)
                if cert_verdict == U:
                    missing_context_facts.update(open_facts)

            revoked_set = set(reg.get("revoked", []))
            superseded_auths = set()
            for s in reg.get("supersessions", []):
                s_from_dt = parse_rfc3339(s.get("from", "1970-01-01T00:00:00Z"))
                if eval_at >= s_from_dt:
                    superseded_auths.add(s.get("superseded"))

            claims_true_on_context = []
            for claim in reg.get("claims", []):
                auth = claim.get("authority")
                if auth in revoked_set or auth in superseded_auths:
                    continue

                from_str = claim.get("from") or claim.get("at")
                if from_str and eval_at < parse_rfc3339(from_str):
                    continue
                until_str = claim.get("until")
                if until_str and eval_at >= parse_rfc3339(until_str):
                    continue

                surviving_claims[r_id].append(claim)

                if cert_verdict == T:
                    claim_scope = claim.get("scope", "always")
                    c_verdict, c_open, c_unwit = self._eval_scope_cached(
                        claim_scope,
                        context,
                        witnessed=witnessed,
                        witness_required=claim.get("witness_required"),
                        ablate_cf=(ablate == "CF")
                    )
                    if c_verdict == T:
                        claims_true_on_context.append(claim)
                        if claim.get("exclusive"):
                            exclusive_claims_by_reg.setdefault(r_id, []).append(auth)
                    elif c_verdict == U:
                        missing_context_facts.update(c_open)
                        if c_unwit:
                            unwitnessed_list.extend(c_unwit)

            covering_closures = []
            for closure in reg.get("closures", []):
                c_at_str = closure.get("at")
                c_at = parse_rfc3339(c_at_str)
                if c_at > query_at:
                    continue
                max_days = closure.get("max_age_days", 90)
                if ablate != "C8" and (query_at - c_at).total_seconds() > max_days * 86400:
                    continue

                cl_scope = closure.get("scope", "always")
                cl_verdict, cl_open, _ = self._eval_scope_cached(cl_scope, context)
                if cl_verdict == T:
                    covering_closures.append(closure)
                elif cl_verdict == U:
                    missing_context_facts.update(cl_open)

            if not covering_closures and ablate != "C8":
                stale_closures.add(r_id)

            if ablate != "C8" and covering_closures:
                surviving_auth_names = {c.get("authority") for c in surviving_claims[r_id]}
                true_claim_names = {c.get("authority") for c in claims_true_on_context}

                closed_authorities_union = set()
                for cl in covering_closures:
                    for auth in cl.get("authorities", []):
                        closed_authorities_union.add(auth)
                        if auth not in surviving_auth_names:
                            closure_disagreements.append({
                                "registrar": r_id,
                                "authority": auth,
                                "reason": "closed_but_not_claimed"
                            })

                for auth in true_claim_names:
                    if auth not in closed_authorities_union:
                        closure_disagreements.append({
                            "registrar": r_id,
                            "authority": auth,
                            "reason": "claimed_but_not_closed"
                        })

        if (
            missing_context_facts
            or unreachable_registrars
            or stale_closures
            or stale_heads
            or closure_disagreements
            or unwitnessed_list
        ):
            res = {"status": "INCOMPLETE"}
            if missing_context_facts:
                res["missing_context_facts"] = sorted(list(missing_context_facts))
            if unreachable_registrars:
                res["unreachable_registrars"] = sorted(list(unreachable_registrars))
            if stale_closures:
                res["stale_closures"] = sorted(list(stale_closures))
            if stale_heads:
                res["stale_heads"] = sorted(list(stale_heads))
            if closure_disagreements:
                unique_disagreements = []
                seen_cd = set()
                for cd in closure_disagreements:
                    k = (cd["registrar"], cd["authority"], cd["reason"])
                    if k not in seen_cd:
                        seen_cd.add(k)
                        unique_disagreements.append(cd)
                unique_disagreements.sort(key=lambda x: (x["registrar"], x["authority"], x["reason"]))
                res["closure_disagreements"] = unique_disagreements
            if unwitnessed_list:
                unique_unw = []
                seen_u = set()
                for u in unwitnessed_list:
                    k = (u["fact"], u["class"])
                    if k not in seen_u:
                        seen_u.add(k)
                        unique_unw.append(u)
                unique_unw.sort(key=lambda x: (x["fact"], x["class"]))
                res["unwitnessed"] = unique_unw
            return res

        regs_with_exclusive = [r for r, auths in exclusive_claims_by_reg.items() if auths]
        if len(regs_with_exclusive) >= 2:
            all_conflicts = set()
            for r in regs_with_exclusive:
                all_conflicts.update(exclusive_claims_by_reg[r])
            return {
                "status": "CONFLICT",
                "conflict_authorities": sorted(list(all_conflicts))
            }

        final_authorities = set()
        for r_id, reg in reached_registrars.items():
            cert_scope = reg.get("certified_scope", "always")
            if ablate != "C6":
                c_verdict, _, _ = self._eval_scope_cached(cert_scope, context)
                if c_verdict != T:
                    continue

            for claim in reg.get("claims", []):
                auth = claim.get("authority")
                if auth in set(reg.get("revoked", [])):
                    continue
                from_str = claim.get("from") or claim.get("at")
                if from_str and eval_at < parse_rfc3339(from_str):
                    continue
                until_str = claim.get("until")
                if until_str and eval_at >= parse_rfc3339(until_str):
                    continue

                is_sup = False
                for s in reg.get("supersessions", []):
                    if s.get("superseded") == auth and eval_at >= parse_rfc3339(s.get("from", "1970-01-01T00:00:00Z")):
                        is_sup = True
                        break
                if is_sup:
                    continue

                claim_scope = claim.get("scope", "always")
                cl_verdict, _, _ = self._eval_scope_cached(
                    claim_scope,
                    context,
                    witnessed=witnessed,
                    witness_required=claim.get("witness_required"),
                    ablate_cf=(ablate == "CF")
                )
                if cl_verdict == T:
                    final_authorities.add(auth)

        return {
            "status": "RESOLVED",
            "authorities": sorted(list(final_authorities))
        }


def resolve(
    world: Dict[str, Any],
    query: Dict[str, Any],
    ablate: Optional[str] = None,
    ablate_at: Optional[str] = None,
    presented: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Default entrypoint: uses OptimizedIterativeResolutionEngine."""
    engine = OptimizedIterativeResolutionEngine()
    return engine.resolve(world, query, ablate=ablate, ablate_at=ablate_at, presented=presented)
