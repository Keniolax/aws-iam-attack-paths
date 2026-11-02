# aws-iam-attack-paths

Week 9 of the security engineer bootcamp: AWS identity attack paths, found by
hand and then closed.

I worked three training targets — flaws.cloud, flaws2.cloud, and the CloudGoat
`iam_privesc_by_rollback` scenario — and for each finding wrote the
least-privilege policy that shuts it. The write-up is `walkthrough.md`: each
level, its root cause, and the fix. The policies are in `policies/`, as the
JSON that AWS actually applies. A test proves the fixes work.

## What is here

- `walkthrough.md` — the findings, level by level, with the fix for each.
- `policies/` — one policy per finding. A `.vuln.json` is the broken policy as
  found; a `.fixed.json` (or `.scp.json`) is the least-privilege replacement.
- `tests/test_policies.py` — a linter over the policy JSON. No AWS account
  needed.
- `simulate/evidence/` — output from `aws iam simulate-custom-policy` showing
  the escalation allowed under the broken policy and denied under the fix.

## How to run

The test needs no AWS account and no network:

```
pip install pytest
python -m pytest tests/ -q
```

It checks that every policy is valid JSON, that no fixed policy grants full
admin or a loose privilege-escalation action, and that each `.vuln.json` still
trips the linter — so the linter cannot pass on everything by accident. GitHub
Actions runs it on every push (`.github/workflows/ci.yml`).

To reproduce the policy simulation (this one needs AWS keys):

```
aws iam simulate-custom-policy \
  --policy-input-list "$(python3 -c 'import json;print(json.dumps(json.load(open("policies/cloudgoat-rollback.vuln.json"))))')" \
  --action-names iam:SetDefaultPolicyVersion iam:ListUsers s3:ListAllMyBuckets \
  --resource-arns '*'
```

Swap in `cloudgoat-rollback.fixed.json` to see the escalation turn to
`implicitDeny`.

## What I learned

- Read a policy by its real reach, not its name. `iam:SetDefaultPolicyVersion`
  reads like a small admin chore. It is a full privilege escalation, because a
  policy keeps old versions and one of them can be admin.
- The same server-side request forgery bug appears twice: once against the EC2
  metadata service (flaws.cloud level 5) and once against the ECS task
  metadata service (flaws2 level 3). Both hand out role keys to any local
  request. IMDSv2 and a short metadata hop limit close the first; not shipping
  an open proxy closes both.
- Most findings are the same mistake in different services: a grant wider than
  the job needs. A public bucket, a public snapshot, an open registry, a role
  that can list a bucket it never reads. Least privilege is one rule applied
  everywhere.
- Deleting a secret does not un-leak it. The git history and the image layers
  still hold it. Rotate first, clean up second.
