# Adversarial Review — Deployment, GitOps & Supply-Chain (offline-first)

Author: main-thread (from full-session evidence + live cluster). Axis: how PanOps is built, shipped, and kept offline-first.

## Critical

### OPS-1 — Two-repo "ConfigMap-as-code" sync is silent and unenforced (ROOT CAUSE)
- **What:** The brain (assembler/remediator/consolidation/classifier/correlator/drain3_detector/runbook_writer .py) runs from a hand-maintained 3489-line ConfigMap `assembler-cm.yaml` mounted at /scripts — NOT the image. Source of truth is `~/Git/panops/docker/assembler/src/`. There is NO generator; the two copies drift silently.
- **Failure seen this session:** the entire productised brain (webhooks, postmortem, multi-platform remediation, platform-agnostic prompts) sat undeployed for days — the ConfigMap still had the old "Kubernetes SRE assistant" code. Nobody would have known.
- **Fix (capability uplift):** Generate `assembler-cm.yaml` in CI from source (a `make configmap` / CI job that emits it and fails if the committed copy is stale — a drift gate). Better: bake the code into the assembler image and drop ConfigMap-as-code entirely (the image is already built in CI). Pick one source of truth.

### OPS-2 — No CI gate between source and deployment; images were never built
- **What:** `~/Git/panops` sat 9 commits unpushed; images were never built. Pushing exposed 5 latent bugs (py3.13, shell-quoting, correlation-rule validation, untracked intel-updater script, broken CronJob wiring) — each independently fatal. homelab manifests referenced `:latest` images that didn't exist.
- **Fix:** CI must build+test images on every change to `docker/**`; homelab should pin image digests produced by a green pipeline, not floating `:latest`. Add a `kustomize build` validation gate on the homelab repo (a stuck/duplicate resource this session wedged a Flux reconcile for 10m).

## High

### OPS-3 — Offline-first is violated in ≥4 places; no single supply-chain boundary
- **What (each reaches the public internet):**
  1. `yara-scanner-ds.yaml` init container `wget`s the `yr` binary from `github.com/VirusTotal/yara-x/releases/...` at **pod start** (runtime egress).
  2. `model-download-job.yaml` `urllib.urlretrieve`s the Qwen GGUF from `huggingface.co`.
  3. `intel-updater` CronJob runs `--online` → GitHub (SigmaHQ, elastic, YARA-Forge, ET Open, MITRE, NVD, OTel semconv) via `panops-update-intel.py:_make_request`.
  4. All Dockerfiles pull base images (Docker Hub) + pip (PyPI) at build.
- **Why it matters:** contradicts the stated "zero internet at runtime; intel via bundle only" requirement ([[feedback_panops_offline_first]]); each is a fragility + supply-chain trust hole.
- **Fix = the bundler-repo workstream (see below).**

### OPS-4 — No supply-chain integrity on fetched artifacts
- **What:** `_make_request` fetches intel packs and trusts them; yr binary + GGUF pulled with no checksum/signature verification. No provenance.
- **Fix:** pin+verify SHA256 for every external artifact; sign republished artifacts with cosign; attach SLSA provenance. Centralize in the bundler repo.

### OPS-5 — intel-updater CronJob is non-functional AND policy-violating
- **What:** `nous-updater` uses image `sigma-scanner:latest` (which lacks `panops-update-intel`) with `command:["panops-update-intel","--online",...]` (not on PATH; `--online` violates offline-first). It has never run and would fail.
- **Fix:** point at `intel-updater:latest` (entrypoint `python3 /app/panops-update-intel.py`), run in **bundle/apply** mode against an artifact pulled from the internal mirror (not `--online`). Add egress policy ONLY if online is ever explicitly chosen.

## Medium

### OPS-6 — Prefect flows broken + unregistered (redundant but lossy)
- **What:** `flows/*.py` import `from prefect.schedules import CronSchedule` (wrong for Prefect 3.7.7 → `prefect.client.schemas.schedules`); modules can't import. No `prefect deploy` step/Job exists; worker polls an empty `panops-local` pool. Dream cycle is unaffected (assembler self-schedules), but health-check (model health every 15m) and pending-synthesis (03:00 retry) are lost.
- **Fix:** fix imports; add a deployment-registration mechanism (a `prefect deploy`/`serve` Job in the agent image) or delete the flows as redundant. Decide keep-vs-drop.

### OPS-7 — Testing not gated; manual test harness
- **What:** CI `panops-test-harness` is a manual job; the pipeline goes green without it. Unit tests (test_11_productisation etc.) aren't run as a merge gate.
- **Fix:** run tests automatically in CI on `docker/**` + `tests/**` changes; block release on failure. Add a smoke test that curls `/dream`, `/health`, a webhook round-trip against an ephemeral stack.

### OPS-8 — Secrets hygiene
- **What:** template secrets committed (`panops-assembler-secrets.yaml`, winrm creds with `changeme`); confirm all real secrets use SOPS+age (user's standard) not plaintext manifests.
- **Fix:** SOPS-encrypt; add a pre-commit/CI check that rejects plaintext secret values.

### OPS-9 — No observability of PanOps itself (who watches the watcher)
- **What:** if the assembler silently stops assembling or the dream cycle fails, nothing alerts. `component_heartbeats` exists but no alert consumes it.
- **Fix:** a dead-man's-switch alert on happenings/heartbeat freshness; alert on dream_state.last_rem_run staleness (>26h); surface PanOps health in Grafana.

## Capability uplift — the bundler / supply-chain repo (the user's idea, fully designed)

**New public repo `panops-supply` (or `nous-bundler`) with GitHub Actions that runs where internet exists, and republishes everything to GHCR as versioned, signed OCI artifacts. The offline cluster pulls only from GHCR (or an internal registry mirror synced from it) — one auditable boundary.**

Concretely:
1. **Intel packs** → GHA fetches SigmaHQ/YARA-Forge/ET-Open/MITRE/NVD/OTel-semconv (the existing `panops-update-intel.py` SOURCES map), normalizes, and pushes each pack as an **OCI artifact via ORAS** (`ghcr.io/<org>/nous/<pack>:<date>`), checksummed. Runtime `intel-updater` switches to "pull OCI artifact + apply" (offline-safe, no GitHub).
2. **`yr` binary** → GHA downloads the pinned yara-x release, verifies checksum, republishes as an OCI artifact (or better: bake into the sigma/yara image so no init-container fetch at all). Kills the runtime `wget`.
3. **GGUF model** → GHA pulls from HuggingFace once, republishes as an OCI model artifact (`ghcr.io/.../qwen2.5-3b-gguf:<rev>`); model-init pulls via ORAS. Removes HuggingFace runtime dependency.
4. **Base images** → GHA mirrors pinned base images (python:3.13-slim etc.) to GHCR for a fully self-contained pull set.
5. **Signing/provenance** → cosign-sign every artifact; attach SLSA provenance; the cluster verifies signatures on pull.
6. **Versioning** → a single `bundle-manifest.json` (git-tagged) enumerates exact digests of every artifact = one reproducible "intel+deps release" the airgap operator promotes as a unit. Extends the existing `panops-bundle` manifest concept to OCI/GHCR instead of local tarballs (keep tarball export as fallback for fully-disconnected transfer).
7. **Scheduling** → weekly GHA cron produces a new dated bundle; promotion to the cluster is a deliberate, auditable step (aligns with offline-first "updates via controlled bundle").

This turns "N components each phoning home at build/runtime" into "GHA fetches once, signs, publishes; cluster pulls signed artifacts from one registry." It is the correct productisation of offline-first and supersedes the ad-hoc `--online`/`wget`/`urlretrieve` paths.
