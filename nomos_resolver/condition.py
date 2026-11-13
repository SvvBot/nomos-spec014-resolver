"""
NOMOS-SPEC-008 Scope Condition Grammar Evaluator
Three-valued Kleene logic evaluator for NOMOS conditions.
Zero-dependency, Python standard library only.
"""

import re
import json
from typing import Any, Tuple, Set, List, Optional

T, F, U = "TRUE", "FALSE", "UNDECIDED"
_TOK = re.compile(r'\s*(?:(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(?P<str>"[^"]*")|(?P<op>==|!=|>=|<=|>|<|\(|\)|,)|(?P<id>[A-Za-z_][\w.]*))')


def _tokens(s: str) -> list:
    pos, out = 0, []
    while pos < len(s):
        if s[pos:].strip() == "":
            break
        m = _TOK.match(s, pos)
        if not m or m.end() == pos:
            raise ValueError(f"cannot parse at {pos}: {s[pos:pos+20]!r}")
        kind = m.lastgroup
        val = m.group(kind)
        pos = m.end()
        out.append((kind, val))
    return out


def _lookup(facts: dict, path: str):
    cur: Any = facts
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _tri(b) -> str:
    return T if b else F


def _and(a, b):
    return F if F in (a, b) else (U if U in (a, b) else T)


def _or(a, b):
    return T if T in (a, b) else (U if U in (a, b) else F)


def _not(a):
    return {T: F, F: T, U: U}[a]


class _Absent:
    pass


ABSENT = _Absent()


def _kind(x) -> str:
    """The JSON type of a present value. Booleans are not numbers."""
    if isinstance(x, bool):
        return "boolean"
    if isinstance(x, (int, float)):
        return "number"
    if isinstance(x, str):
        return "string"
    if isinstance(x, dict):
        return "object"
    if isinstance(x, list):
        return "array"
    return "other"


def jcs(obj: Any) -> str:
    """RFC 8785 JSON Canonicalization Scheme."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


class _Parser:
    def __init__(self, toks, facts, decided_absent=()):
        self.t, self.i, self.f, self.da = toks, 0, facts, decided_absent
        self.undecided_by: Set[str] = set()

    def _u(self, *ops) -> str:
        self.undecided_by.update(o[1] for o in ops if isinstance(o, tuple))
        return U

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expr(self):
        v = self.andx()
        while self.peek() == ("id", "or"):
            self.take()
            v = _or(v, self.andx())
        return v

    def andx(self):
        v = self.unary()
        while self.peek() == ("id", "and"):
            self.take()
            v = _and(v, self.unary())
        return v

    def unary(self):
        if self.peek() == ("id", "not"):
            self.take()
            return _not(self.unary())
        return self.primary()

    def operand(self):
        k, v = self.take()
        if k == "num":
            return float(v) if any(c in v for c in ".eE") else int(v)
        if k == "str":
            return v[1:-1]
        if k == "id":
            if v == "true":
                return True
            if v == "false":
                return False
            if v == "always":
                return True
            return ("FIELD", v)
        raise ValueError(f"unexpected {v!r}")

    def val(self, x):
        if not isinstance(x, tuple):
            return x
        got = _lookup(self.f, x[1])
        return ABSENT if got is None else got

    def primary(self) -> str:
        k, v = self.peek()
        if (k, v) == ("op", "("):
            self.take()
            r = self.expr()
            self.take()
            return r
        if k == "id" and v in ("exists", "matches") and self.t[self.i + 1 : self.i + 2] == [("op", "(")]:
            self.take()
            self.take()
            f = self.operand()
            if v == "exists":
                self.take()
                if self.val(f) is not ABSENT:
                    return T
                name = f[1] if isinstance(f, tuple) else None
                return F if name is not None and (name in self.da or name.split(".")[0] in self.da) else self._u(f)
            self.take()
            pat = self.operand()
            self.take()
            x = self.val(f)
            if x is ABSENT or _kind(x) != "string":
                return self._u(f)
            return _tri(re.search(pat, x) is not None)
        left = self.operand()
        k2, op = self.peek()
        if k2 == "op" and op in ("==", "!=", ">", ">=", "<", "<="):
            self.take()
            right = self.operand()
            a, b = self.val(left), self.val(right)
            if a is ABSENT or b is ABSENT:
                return self._u(*[x for x, v in ((left, a), (right, b)) if v is ABSENT])
            ka, kb = _kind(a), _kind(b)
            if ka != kb or ka == "other" or (op not in ("==", "!=") and ka not in ("number", "string")):
                return self._u(left, right)
            if ka in ("object", "array"):
                eq = jcs(a) == jcs(b)
                return _tri(eq if op == "==" else not eq)
            return _tri({"==": a == b, "!=": a != b, ">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op])
        if (k2, op) in (("id", "in"), ("id", "contains"), ("id", "between")):
            self.take()
            right = self.operand()
            rhs = self.val(right)
            a = self.val(left)
            if a is ABSENT or rhs is ABSENT:
                return self._u(*[x for x, v in ((left, a), (right, rhs)) if v is ABSENT])
            if op == "between":
                if _kind(a) != "number":
                    return self._u(left)
                lo, hi = (float(p) for p in str(rhs).split(","))
                return _tri(lo <= a <= hi)
            if _kind(a) not in ("string", "number", "boolean"):
                return self._u(left)
            if op == "in":
                return _tri(str(a) in [p.strip() for p in str(rhs).split(",")])
            return _tri(str(rhs).lower() in str(a).lower())
        x = self.val(left)
        return self._u(left) if x is ABSENT or _kind(x) != "boolean" else _tri(x)


def eval_when_detail(expr: str, facts: dict, decided_absent=()) -> Tuple[str, Set[str]]:
    p = _Parser(_tokens(expr), facts, decided_absent)
    r = p.expr()
    if p.i != len(p.t):
        raise ValueError(f"trailing tokens in {expr!r}")
    return r, p.undecided_by


def eval_when(expr: str, facts: dict, decided_absent=()) -> str:
    return eval_when_detail(expr, facts, decided_absent)[0]
