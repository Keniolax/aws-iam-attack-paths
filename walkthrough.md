# flaws.cloud, flaws2.cloud, and CloudGoat: what broke and the policy that fixes it

Three training targets, worked by hand. Each step below gives the flaw, how I
reached it, the root cause, and the least-privilege policy that closes it. The
policy files are in `policies/`. Secrets that the games handed out are never
printed here or committed; where a game gave me keys I used a separate named
AWS CLI profile and threw it away after.

The deep notes (mechanism, MITRE and CIS references, lessons) live in the
bootcamp study book, not in this repo.

## flaws.cloud

A set of six S3-and-IAM puzzles. Each solved level names the next.

### Level 1 — a public bucket you can list

`aws s3 ls s3://flaws.cloud/ --no-sign-request` lists the bucket with no
credentials. The listing shows a hidden page that names level 2.

Root cause: the bucket grants `List` to Everyone (the `AllUsers` group ACL).

Fix: turn on S3 Block Public Access for the account and the bucket, and attach
`policies/flaws-l1l2-s3-bucket-policy.fixed.json`. That bucket policy denies
every S3 action unless the caller is in the bucket's own account. A bucket that
serves a public website should serve it through CloudFront, not an open bucket.

### Level 2 — public to "any AWS user"

The level 2 bucket refuses an unsigned request but answers when I sign it with
my own account's keys. Any AWS account works.

Root cause: the ACL grants `List` to the `AuthenticatedUsers` group. People read
that as "logged-in users of my account". It means every AWS account in the
world.

Fix: the same bucket policy as level 1. Never use the `AuthenticatedUsers`
grant.

### Level 3 — keys committed to git

The bucket is listable and holds a `.git` folder. I synced it to an empty
directory and read its history with hooks turned off. The first commit added an
`access_keys.txt`; a later commit removed it. The keys still work. They belong
to an IAM user named `backup` in the flaws account.

Root cause: a secret was committed to git, and the whole repository sat in a
public bucket. Deleting the file in a later commit does not remove it from
history.

Fix: rotate the leaked key at once, keep secrets out of git, and block public
access to the bucket (level 1 policy). Give a `backup` user only the actions it
needs, not the broad rights these keys turned out to have.

### Level 4 — a public EBS snapshot (hands-on)

Level 4 points at a web page on an EC2 instance, protected by a password. The
page says a snapshot of that instance's disk was made public.

I did this for real instead of reading the answer:

1. Found the snapshot with the level 3 keys:
   `aws ec2 describe-snapshots --owner-ids 975426262029`. One snapshot,
   `snap-0b49342abd1bdcb89`, 8 GiB.
2. Confirmed it is public:
   `describe-snapshot-attribute ... --attribute createVolumePermission`
   returns `{"Group": "all"}`.
3. In my own account (us-west-2) I launched one small instance with an SSM
   role and no inbound ports, made a volume from the public snapshot in the
   same Availability Zone, attached it, and mounted it read-only through SSM
   (the agent proxy cannot carry SSH).
4. On the disk, `/home/ubuntu/setupNginx.sh` runs `htpasswd` to set the web
   page password. I read the password straight from that file.
5. Tore everything down the same step: detached and deleted the volume,
   terminated the instance, deleted the security group, the instance profile,
   and the role. Confirmed with `describe-instances` and `describe-volumes` in
   us-west-2 and us-east-1 that nothing was left.

Root cause: an EBS snapshot was shared with "all". Anyone can build a volume
from it and read the disk, including the web password.

Fix: keep snapshots private. The guardrail in
`policies/flaws-l4-snapshot-guardrail.scp.json` denies
`ec2:ModifySnapshotAttribute` and `ec2:ModifyImageAttribute` whenever the change
would add the `all` group, so no one in the account can make a snapshot or AMI
public by mistake.

### Level 5 — an open proxy reads the instance's role keys

The next host runs a simple web proxy: `GET /proxy/<url>` makes the server fetch
`<url>` and return it. I pointed it at the instance metadata service:
`/proxy/http://169.254.169.254/latest/meta-data/iam/security-credentials/`. That
named the role, and one more request returned the role's temporary keys. With
those keys I listed the level 6 bucket.

Root cause: a server-side request forgery (SSRF) hole, plus version 1 of the
metadata service (IMDSv1), which hands out role keys to any local request. The
role also had more S3 access than the app needed.

Fix: require IMDSv2 on the instance (a token-based metadata service), which
blocks this simple SSRF read. Give the instance only the access it needs:
`policies/flaws-l5-ec2-role.fixed.json` allows `s3:GetObject` on one named
bucket and nothing else.

### Level 6 — read access that maps a hidden API

Level 6 gives you keys for an IAM user with two policies: the AWS-managed
`SecurityAudit` policy and a small custom one. Reading them cold:

- `SecurityAudit` lets you read configuration across services, including
  `lambda:GetPolicy`.
- The custom `list_apigateways` policy
  (`policies/flaws-l6-apigateway.vuln.json`) allows `apigateway:GET` on
  `arn:aws:apigateway:us-west-2::/restapis/*`. In plain words: read every REST
  API in that region.

I listed the one Lambda function, read its resource policy, and saw which API
Gateway was allowed to call it and on which path. Reading the API gave the
stage name. Calling the API returned the final page.

Root cause: broad read access. On its own each grant looks harmless, but
together they let an outsider map a private Lambda and its API and then call it.

Fix: scope the read. `policies/flaws-l6-apigateway.fixed.json` allows
`apigateway:GET` on one API's ARN, not every API in the region. Replace the
placeholder with the real API id.

## flaws2.cloud — attacker path

A serverless app. The attacker path runs through a Lambda and a container.

### Level 1 — a Lambda that prints its own environment

The page checks a numeric code. The check runs only in the browser JavaScript.
The form calls an API: `.../default/level1?code=1234`. I sent a non-number,
`?code=a`. The Lambda crashed and returned its full environment in the error,
including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
`AWS_SESSION_TOKEN`. Lambda keeps its role keys in those variables. I loaded
them into a named profile and listed the level 1 bucket, which named level 2.

Root cause: two faults. The function dumps its environment on error, and the
input check is only client-side. The role also had `s3:ListBucket`, which the
function did not need.

Fix: do not print the environment in an error. Validate input in the function.
Give the function role only what it uses:
`policies/flaws2-l1-lambda-role.fixed.json` allows the function to write its own
log stream and nothing else.

### Level 2 — an open container registry

Level 2 says the container image sits in an ECR repository named `level2` with
open permissions. From my own account I read the repository across accounts:
`describe-images`, then `batch-get-image`, then `get-download-url-for-layer`.
Reading the image config and layers showed how it was built, including:

```
htpasswd -b -c /etc/nginx/.htpasswd flaws2 <password-baked-into-the-image>
```

So the container's web password was baked into the image (I read the real
value from the layer; it is not repeated here). That the cross-account
read worked at all is the proof the repository policy is open.

Root cause: an ECR repository policy that lets any authenticated AWS account
pull, and a password built into the image layers.

Fix: restrict the repository.
`policies/flaws2-l2-ecr-repo-policy.fixed.json` allows pull actions only from
the owning account. Keep passwords out of images; pass them at run time from a
secrets store.

### Level 3 — SSRF from inside the container (mechanism)

The live container was down while I worked (the host returned 503 and then
stopped answering), so I could not run this step against it. Instead I read the
real code from the image I pulled in level 2.

`/var/www/html/proxy.py` is an open proxy:

```python
self.path = self.path[1:]
response = urllib.urlopen(self.path)
```

It fetches any URL you give it. The nginx config routes `/proxy/<url>` to it.
An ECS task reads its role keys from the task metadata address
`169.254.170.2` under the path in `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. So
the intended attack is `/proxy/http://169.254.170.2/<that-path>`, which returns
the task role's keys, then uses them against the next bucket.

Root cause: the same SSRF pattern as flaws.cloud level 5, now against the ECS
task metadata service, plus a task role with more access than the task needs.

Fix: do not ship an open proxy. Give the task role only the access it needs:
`policies/flaws2-l3-ecs-task-role.fixed.json` allows `s3:GetObject` on one named
bucket. Set the task's metadata hop limit and egress so a hijacked process
cannot reach the wider network.

## CloudGoat — iam_privesc_by_rollback

I deployed this scenario in my own account, attacked it, and destroyed it the
same session. It builds only IAM resources (a user, a policy, an access key),
so it is free to keep. I read the Terraform first and confirmed there was no
EC2, no NAT gateway, and nothing else that bills.

Start: an IAM user, `raynor`, with one policy
(`policies/cloudgoat-rollback.vuln.json`). Reading it cold, it allows:

- `iam:Get*` and `iam:List*` on everything — read IAM.
- `iam:SetDefaultPolicyVersion` on everything — pick which saved version of any
  policy is the live one.

Attack:

1. As `raynor`, an admin-only action failed:
   `aws s3api list-buckets` returned `AccessDenied`.
2. `list-policy-versions` on raynor's own policy showed five saved versions.
3. `get-policy-version` on each showed version `v3` is `Allow *:* on *` — full
   admin.
4. `aws iam set-default-policy-version --version-id v3` made that version live.
5. The same `s3api list-buckets` now worked, and `iam create-user` worked. I
   deleted the test user at once.

Root cause: `iam:SetDefaultPolicyVersion` is a privilege-escalation action. A
policy can keep old versions. One of them was full admin. The right to switch
the live version is the right to become whatever any old version allowed.

Fix: `policies/cloudgoat-rollback.fixed.json` keeps the read access
(`iam:Get*`, `iam:List*`) and drops `iam:SetDefaultPolicyVersion`. If a role
truly must manage versions of one specific, non-privileged policy, pin the
`Resource` to that policy's ARN, never `*`.

Proof, with no account needed at review time, is in `simulate/evidence/`:

- `rollback-vuln.txt`: under the start policy, `iam:SetDefaultPolicyVersion` is
  `allowed`.
- `rollback-fixed.txt`: under the fixed policy, the same action is
  `implicitDeny`, while `iam:ListUsers` stays `allowed`.

Both came from `aws iam simulate-custom-policy`.

## What I could not do here

- **flaws2 level 3, live.** The hosted container was down (503, then no
  answer). I documented the attack from the image's real code instead.
- **flaws2 defender path.** It needs a second, separate AWS account and a
  sign-up to get cross-account access to the attack logs. That needs the user's
  own account and browser, so it is left for a later session.
