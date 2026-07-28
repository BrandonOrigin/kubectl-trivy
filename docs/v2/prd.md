# PRD: `kubectl trivy analyze` — AI-Assisted Vulnerability Triage

**Status:** Draft — pending refinement after "Building with the Claude API" course
**Owner:** Brandon
**Created:** 2026-07-28
**Context:** Platform 101 → Building with the Claude API, Project 1

---

## 1. Background

This is Project 1 for the "Building with the Claude API" course. The assignment calls for
a properly-built API analysis tool: structured tool-use output instead of prose parsing,
prompt caching for large context, streaming, and Batch API for bulk sweeps — with a
token/cost table as the artifact (cost per analysis before vs. after caching and model
routing).

`kubectl-trivy` (this repo) already does the hard part of sourcing real data: it discovers
every container image running in a namespace and pulls raw Trivy vulnerability-scan JSON
per image (see `docs/spec.md`). Today that JSON is reduced to per-severity counts via
`jq`-style parsing and printed as a table. This PRD scopes a `kubectl trivy analyze`
subcommand that replaces the counting step with an LLM triage pass — turning "214 findings,
18 HIGH" into "2 things you actually need to patch this week" — and produces the token/cost
comparison the course project asks for, grounded in a real workload instead of synthetic
data.

**This PRD is a v2 draft.** It is expected to be refined after the course material on
structured outputs, caching, and batch is covered — see the companion refinement issue.

---

## 2. Problem Statement

The existing `kubectl trivy` output aggregates by severity only. A cluster scan routinely
returns hundreds of findings per image; severity alone doesn't tell an operator which of
those findings are actually reachable, already fixed upstream, or safe to defer. Humans
end up re-deriving that judgment by hand, per finding, every scan. There's also no answer
to "what would this cost to run against our whole fleet, on every deploy?" — the question
FDEs are asked constantly and rarely have a real number for.

## 3. Goals

- Replace severity-count aggregation with per-finding AI triage: exploitability in context,
  fix availability, and a recommended action.
- Structured tool-use output — the model fills a typed schema, not prose the CLI re-parses.
- Two-tier model routing: Haiku 4.5 for bulk triage, Opus 5 escalation for ambiguous /
  high-severity calls.
- Prompt caching across the shared triage policy + system prompt, since it's identical
  across every image in a sweep.
- Batch API for whole-namespace/whole-cluster sweeps (non-interactive, latency-insensitive).
- Streaming for the single-image interactive explain path.
- Produce a real, reproducible token/cost table: naive vs. +routing vs. +caching vs. +batch.

## 4. Non-Goals

- Auto-remediation (opening PRs, patching images, restarting workloads). Analysis only.
- Persisting scan history / trend tracking across runs (no database — matches the existing
  tool's non-goals in `docs/spec.md`).
- Replacing Trivy's scan engine or vulnerability database. This layer only triages Trivy's
  existing output.
- A hosted/multi-tenant service. This is a CLI plugin, same as v1.

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  kubectl trivy scan -n <ns>  (existing Go, unchanged)            │
│    getImages()  →  trivy image --server ... --format json        │
│    per-image raw Trivy scan JSON                                 │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  vuln JSON blobs, one per image
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  kubectl trivy analyze  (new subcommand, same binary)             │
│                                                                     │
│  1. Batch submit: one Messages Batch request per image, using     │
│     tool-use instead of jq/regex parsing                          │
│  2. Model routing: Haiku 4.5 triage → Opus 5 escalation           │
│  3. Prompt caching: cache_control on the shared system prompt +   │
│     triage policy, identical across every image in the sweep      │
│  4. Streaming: single-image interactive "explain this CVE" path   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.1 Structured tool-use instead of prose/jq parsing

Every finding in a Trivy report is triaged via a single tool call, not free text:

```json
{
  "name": "triage_vulnerability",
  "description": "Record a triage verdict for one CVE found in a container image scan",
  "input_schema": {
    "type": "object",
    "properties": {
      "cve_id": {"type": "string"},
      "severity": {"type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]},
      "exploitable_in_context": {"type": "boolean"},
      "fix_available": {"type": "boolean"},
      "recommended_action": {
        "type": "string",
        "enum": ["patch_now", "schedule", "accept_risk", "needs_human_review"]
      },
      "reasoning": {"type": "string"}
    },
    "required": ["cve_id", "severity", "exploitable_in_context", "fix_available", "recommended_action"]
  }
}
```

`strict: true` on the tool definition so `tool_use.input` always validates. The model
receives the raw (trimmed) Trivy finding plus whatever cluster context is available (pod
exposure, Service type, network policy) — not asked to write prose that gets re-parsed.

### 5.2 Model routing — Haiku triage, Opus escalation

- **Pass 1 (Haiku 4.5):** every finding across every image gets a `triage_vulnerability`
  call. This is the bulk of volume — typically 80-95% of CVEs in a real scan are
  LOW/MEDIUM with no real ambiguity.
- **Escalation trigger:** any finding where Haiku returns `recommended_action:
  "needs_human_review"`, or CRITICAL/HIGH severity with `exploitable_in_context: true`,
  is re-run through Opus 5 with fuller context for the "hard call."
- This is the routing decision the course project explicitly asks to demonstrate, and it's
  the primary cost lever in the results table below.

### 5.3 Prompt caching

The system prompt (triage instructions, the tool schema, the org's risk policy) and any
shared cluster context (network policies, exposure posture) are identical across every
image in one sweep. `cache_control` goes on the last block of that shared prefix; the
varying per-image Trivy finding goes in the user turn, uncached. A cluster sweep is
dozens-to-hundreds of images hitting the same cached prefix within minutes — a strong
cache-hit scenario. First request pays the ~1.25x write premium; everything after reads at
~0.1x.

### 5.4 Batch API for whole-cluster sweeps

One `messages.batches.create()` request per sweep, one entry per finding (or per image,
batched), `custom_id` keyed to image digest + CVE ID. Poll `processing_status`, stream
results keyed by `custom_id` (batch results are not ordered). Batch pricing is ~50% off
standard rates — a second multiplier on top of caching, both shown in the cost table.

### 5.5 Streaming

Reserved for the interactive path (`kubectl trivy analyze --detail <image>` /
`explain <cve-id>`) where a user wants a live explanation of one finding. Not used for the
batch sweep, which is async by nature.

---

## 6. Expected Output

### 6.1 Default summary — reprioritized by actionability, not raw severity counts

```
$ kubectl trivy analyze -n production

Found 12 pods in namespace production (8 unique images)
Remote Trivy Server: trivy.internal:8080
Scanning... done (8 images, 1,847 total findings)
Triage: Haiku 4.5 (1,847 findings) → Opus 5 escalation (23 findings)

┌──────────────────────┬─────────────┬──────────┬────────────────────────────────────────┐
│ IMAGE                │ ACTION      │ CRITICAL │ TOP FINDING                             │
├──────────────────────┼─────────────┼──────────┼────────────────────────────────────────┤
│ web-api:2.4.1        │ PATCH_NOW   │ 2        │ CVE-2024-XXXX openssl — exploitable,    │
│                       │             │          │ internet-facing                         │
│ auth-service:1.9.0    │ SCHEDULE    │ 0        │ CVE-2023-XXXX — fix available, no       │
│                       │             │          │ known exploit path yet                  │
│ nginx:1.19.1          │ ACCEPT_RISK │ 0        │ CVE-2022-XXXX — no network path in       │
│                       │             │          │ this deployment                         │
│ redis:6.0-alpine      │ CLEAN       │ 0        │ —                                        │
└──────────────────────┴─────────────┴──────────┴────────────────────────────────────────┘

2 images need immediate action · 3 scheduled · 3 clean

kubectl trivy analyze -n production --detail web-api:2.4.1   (full reasoning per CVE)
kubectl trivy analyze -n production -o json                  (structured output)
kubectl trivy analyze -n production --cost-report             (token/cost breakdown)
```

### 6.2 `--detail <image>` — per-CVE reasoning from the tool-use output

```
IMAGE: web-api:2.4.1   PODS: web-api-7d9f, web-api-8a2c
FINDINGS: 214 total (2 critical, 18 high, 96 medium, 98 low)

┌ CVE-2024-XXXX — openssl 3.0.2  [CRITICAL] ────────────────────────────────┐
│ Triaged by: opus-5 (escalated from haiku)                                 │
│ Action: PATCH_NOW · Exploitable in context: true                          │
│ Fix available: yes → 3.0.13                                               │
│ Reasoning: web-api-svc is an internet-facing LoadBalancer exposing the    │
│ vulnerable TLS renegotiation path. Fix is a minor-version bump.           │
└─────────────────────────────────────────────────────────────────────────┘

┌ CVE-2023-YYYY — libxml2 2.9.10  [HIGH] ───────────────────────────────────┐
│ Triaged by: haiku-4.5                                                     │
│ Action: ACCEPT_RISK · Exploitable in context: false                       │
│ Fix available: yes → 2.9.14                                               │
│ Reasoning: Parsing path only reachable via internal admin CLI, no         │
│ Service exposes it, no untrusted input reaches it.                       │
└─────────────────────────────────────────────────────────────────────────┘

... 212 more findings (196 auto-accepted at haiku confidence)
```

### 6.3 `-o json` — structured tool-use payload underlying both views above

```json
{
  "image": "web-api:2.4.1",
  "pods": ["web-api-7d9f", "web-api-8a2c"],
  "summary": {"critical": 2, "high": 18, "medium": 96, "low": 98},
  "findings": [
    {
      "cve_id": "CVE-2024-XXXX",
      "package": "openssl",
      "installed_version": "3.0.2",
      "severity": "CRITICAL",
      "triaged_by": "opus-5",
      "escalated": true,
      "exploitable_in_context": true,
      "fix_available": true,
      "fixed_version": "3.0.13",
      "recommended_action": "patch_now",
      "reasoning": "web-api-svc is an internet-facing LoadBalancer...",
      "tokens": {"input": 1820, "output": 340, "cached": 1600}
    }
  ]
}
```

### 6.4 `--cost-report` — the course deliverable

```
COST REPORT — production namespace (8 images, 1,847 findings)

                        Naive (Opus, no cache)  +Haiku routing  +Caching  +Batch API
Cost/image                     $0.076              $0.019        $0.006     $0.003
Cost/100-image cluster          $7.60               $1.90         $0.60      $0.30

Escalated to Opus: 23/1,847 findings (1.2%)
Cache hit rate: 84.7% (input tokens)
Batch discount: 50%

Total this run: $0.024  (vs $0.61 naive — 25x reduction)
```

---

## 7. Open Design Questions

- **Actionability framing is the riskiest bet.** Sorting by `PATCH_NOW`/`SCHEDULE`/
  `ACCEPT_RISK`/`CLEAN` instead of raw severity counts is the main value-add but also the
  part most likely to need recalibration — false "accept_risk" verdicts are the failure
  mode with real consequences. Needs an eval set before this ships as default output
  (severity-sorted table stays available as a fallback / `--legacy` flag).
- **Cluster-context input** (Service exposure, NetworkPolicy, ingress) — how much of this
  do we actually fetch via `client-go` vs. leave as a stretch goal? MVP may ship with
  image-only context (no exposure awareness) and note the limitation.
- **Escalation thresholds** — the specific rule for Haiku → Opus handoff needs tuning
  against a real eval set, not just "CRITICAL/HIGH + exploitable."
- **Where does the analysis layer live** — same Go binary (new subcommand) vs. separate
  process. Current lean: same binary, Go SDK, to keep one artifact and match the existing
  tool's "no external shell dependencies" goal.

## 8. Milestones

1. Course material on structured outputs / caching / batch (in progress) → refine this PRD.
2. Tech spec + ADRs for the concrete decisions above (model routing thresholds, schema
   versioning, Go SDK vs. alternative, caching key design).
3. Baseline maintenance: bring `kubectl-trivy` up to current Go/Trivy versions (blocks
   using the current Go Anthropic SDK cleanly — see companion issue).
4. Implementation plan + build.

---

## 9. References

- `docs/spec.md` — v1 technical spec for the existing scan/table pipeline
- `docs/plan.md` — v1 refinement plan (Go/dependency upgrade, container discovery)
- Course: Platform 101 → Building with the Claude API, Project 1
