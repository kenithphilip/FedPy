# Scope Seed & Tagging Convention (Stage 2)

> **Why seeds exist.** PCI scope is driven by where cardholder data (CHD) / sensitive
> authentication data (SAD) is **stored, processed, or transmitted** — a property of application
> behaviour and data content that **cannot** be read from AWS configuration. This tool therefore
> does **not** originate scope. You declare the resources/networks that handle CHD (the *seeds*);
> the tool expands from them, proves connectivity, flags candidates, and validates segmentation.
>
> **Without seeds the tool will not assert anything is in-scope** — it can only FLAG candidates and
> will print a loud banner saying so.

---

## 1. The three ways to declare seeds

You can use any combination. **Precedence when they conflict: explicit config > tags > CLI flags.**
(A resource named in the config wins over a contradicting tag; a tag wins over a CLI flag.)

### 1.1 Seeds config file (most authoritative)
A YAML or JSON file passed with `--seeds <file>`. Declares seed **resources** (by ARN or native
id) and seed **networks** (by VPC / subnet / CIDR), plus an explicit **out-of-scope** assertion
list used for the segmentation inverse check.

```yaml
# seeds.example.yaml
cde_resources:           # things that store/process/transmit CHD
  - arn:aws:rds:us-east-1:111122223333:cluster:payments-aurora
  - my-cardholder-bucket                       # bare S3 bucket name ok
  - i-0abc123def456                            # instance id
  - arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/pay-alb/abc

cde_networks:            # networks where CHD flows
  vpcs:    [vpc-0cde111]
  subnets: [subnet-0cde222]
  cidrs:   ["10.20.0.0/16"]

connected_declared:      # OPTIONAL: humans already know these are connected-to
  - i-0bastion999

out_of_scope_declared:   # things asserted isolated — the tool inverse-checks these
  - arn:aws:s3:::marketing-public-assets
  - vpc-0devsandbox
```

### 1.2 Tag convention (authoritative on the resource itself)
Tag the resources directly. The tool reads tags already captured in `inventory.json` (and the
scope tags Stage 1 stored under `iam_policy_data.scope_tags`). Recognised keys (case-insensitive):

| Tag | Values | Meaning |
|-----|--------|---------|
| `pci:cde` | `true` / `false` | `true` → treat as a **CDE seed**. |
| `pci:scope` | `cde` \| `connected` \| `out` | `cde` → CDE seed; `connected` → declared connected-to; `out` → **human out-of-scope assertion** (inverse-checked, not removed from analysis). |
| `data-classification` | `chd` \| `sad` \| `none` | `chd`/`sad` → treat as a **CDE seed** (it holds account data). `none` on a data store **suppresses** the "candidate CHD location" heuristic (a human has classified it as holding no account data). |

> `pci:scope=out` does **not** delete a resource from the graph. It marks it for the segmentation
> inverse check: *does a permitted path back to the CDE exist despite the out-of-scope claim?* If
> one does, it's a **finding**.

### 1.3 CLI flags (ad hoc, lowest precedence)
For quick additions without editing a file:

```
--seed-arn   <arn>        (repeatable)   declare a CDE seed resource
--seed-vpc   <vpc-id>     (repeatable)   declare a CDE seed network (VPC)
--seed-subnet <subnet-id> (repeatable)   declare a CDE seed network (subnet)
--seed-cidr  <cidr>       (repeatable)   declare a CDE seed network (CIDR)
--out-of-scope <arn|id>   (repeatable)   assert isolated → inverse-checked
```

---

## 2. Precedence, precisely

For a given resource, the tool resolves its **declared** status in this order and stops at the
first hit:

1. **Explicit config** — present in `cde_resources` / `cde_networks` / `connected_declared` /
   `out_of_scope_declared`.
2. **Tags** — `pci:cde=true`, `pci:scope=…`, or `data-classification=chd|sad`.
3. **CLI flags** — `--seed-*` / `--out-of-scope`.

If config says `cde` and a tag says `out`, **config wins** (the resource is a CDE seed) and the
conflict is recorded in the resource's basis note so the QSA can see the disagreement.

---

## 3. What each declaration does to classification

| Declaration | Resulting category | Confidence |
|-------------|--------------------|------------|
| CDE seed (config / `pci:cde=true` / `pci:scope=cde` / `data-classification=chd\|sad` / `--seed-*`) | `CDE` | `DETERMINED` |
| `connected_declared` / `pci:scope=connected` | `connected-to` | `DETERMINED` (human-declared) |
| `out_of_scope_declared` / `pci:scope=out` / `--out-of-scope` | analysed; stays its computed category, but flagged for the **inverse check** | per analysis |
| (nothing, but reachable from a seed) | `connected-to` | `DETERMINED` (proven path) |
| (nothing, but IAM can act on a seed) | `security-impacting` | `DETERMINED` (grant statement) |
| (nothing, only a heuristic signal) | `connected-to`/`CDE` **candidate** | `CANDIDATE` |
| (nothing at all) | `out-of-scope` (if inverse check finds no path) or `undetermined` | as computed |

---

## 4. No-seed mode (important)

If **no seeds** are supplied by any mechanism, the tool runs in **flag-only mode**:
- It will **never** output a category of `CDE` or a `DETERMINED` connected-to.
- Every resource is `undetermined` or a heuristic `CANDIDATE`.
- The Cover/Scope sheets and stdout print a prominent banner:
  *"NO SEEDS PROVIDED — no in-scope determination was made; only candidates are flagged. Declare
  seeds (see docs/scope-seed-and-tagging-convention.md) for a real scope analysis."*

---

## 5. Worked example

```bash
# 1. tag your CHD store
#    (done in AWS, out of band): RDS cluster gets pci:cde=true, data-classification=chd

# 2. or declare in a file
pci-inventory scope --seeds seeds.yaml

# 3. or ad hoc
pci-inventory scope --seed-arn arn:aws:rds:us-east-1:111122223333:cluster:payments-aurora \
                    --out-of-scope vpc-0devsandbox
```

Output: `output/inventory-scoped.json` plus the Scope Classification / Reachability Paths /
Segmentation Findings / IAM-to-CDE Access workbook sheets.

---

## 6. Caveats (also printed in output)

- The tool **assists and proves connectivity; the human and the QSA make the final scope
  determination.**
- **Isolation evidence ≠ proof of absence of CHD.** "No path to the CDE" proves the resource is
  isolated, not that it is CHD-free. CHD presence is a data-content question outside this tool.
  Out-of-scope-by-absence is recorded as **CANDIDATE** confidence (UNDETERMINED when network data
  was lossy) — never a positive proof.
- IAM analysis is a **static over-approximation** (no SCP / permission-boundary / condition-key /
  explicit-Deny resolution) — it flags candidate access with the granting statement, not effective
  access.
- A resource may be in scope for **more than one reason** (e.g. connected-to *and*
  security-impacting); the primary category is the highest-ranked, with the full set shown.
- **Segmentation findings** cover all out-of-scope resources (declared + tool-derived) across
  network paths AND IAM relationships; absence of findings is **not** proof of complete
  segmentation — penetration testing (Req 11.4.x) is still required.
