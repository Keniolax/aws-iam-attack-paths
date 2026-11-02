"""Check every policy in ../policies.

This runs with no AWS account and no network. It reads each JSON file and
looks for the one mistake that every finding in this repo shares: an Allow
statement that hands out more than it should. A ".fixed." policy must be
tight. A ".vuln." policy must still be loose, so the check can tell the two
apart and cannot quietly pass on everything.
"""

import json
import pathlib

POLICY_DIR = pathlib.Path(__file__).resolve().parent.parent / "policies"

# Actions that let a caller raise their own rights. A tight policy keeps
# these off, or pins them to one named resource, never "*".
PRIVESC_ACTIONS = {
    "iam:setdefaultpolicyversion",
    "iam:createpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
}


def load(path):
    with open(path) as handle:
        return json.load(handle)


def statements(doc):
    block = doc.get("Statement", [])
    return block if isinstance(block, list) else [block]


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def policy_files():
    return sorted(POLICY_DIR.glob("*.json"))


def fixed_files():
    return [p for p in policy_files() if ".fixed." in p.name or ".scp." in p.name]


def vuln_files():
    return [p for p in policy_files() if ".vuln." in p.name]


def is_full_admin(stmt):
    """Allow *:* on everything."""
    if stmt.get("Effect") != "Allow":
        return False
    actions = [a.lower() for a in as_list(stmt.get("Action"))]
    resources = as_list(stmt.get("Resource"))
    return "*" in actions and "*" in resources


def allowed_privesc(stmt):
    """An Allow for a privesc action that is not pinned to a named resource."""
    if stmt.get("Effect") != "Allow":
        return []
    actions = [a.lower() for a in as_list(stmt.get("Action"))]
    resources = as_list(stmt.get("Resource"))
    if resources == ["*"] or "*" in actions:
        return [a for a in actions if a in PRIVESC_ACTIONS or a == "*"]
    return []


def test_every_policy_is_valid_json():
    assert policy_files(), "no policy files found"
    for path in policy_files():
        load(path)  # raises if the file is not valid JSON


def test_fixed_policies_grant_no_full_admin():
    for path in fixed_files():
        for stmt in statements(load(path)):
            assert not is_full_admin(stmt), f"{path.name} still allows *:*"


def test_fixed_policies_have_no_loose_privesc():
    for path in fixed_files():
        for stmt in statements(load(path)):
            loose = allowed_privesc(stmt)
            assert not loose, f"{path.name} still allows loose {loose}"


def wildcard_resource_on_allow(stmt):
    """An Allow that reaches every resource of a kind, e.g. every REST API."""
    if stmt.get("Effect") != "Allow":
        return False
    return any("*" in r for r in as_list(stmt.get("Resource")))


def test_vuln_policies_are_actually_loose():
    # Proves the checks above can fail: each vuln file must trip at least one
    # rule. If a vuln file ever looks clean, the linter is broken.
    for path in vuln_files():
        stmts = statements(load(path))
        loose = any(
            is_full_admin(s) or allowed_privesc(s) or wildcard_resource_on_allow(s)
            for s in stmts
        )
        assert loose, f"{path.name} does not look dangerous; check the linter"
