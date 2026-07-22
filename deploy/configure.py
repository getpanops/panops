#!/usr/bin/env python3
"""
PanOps configure — reads deploy/values.yaml, generates:
  deploy/kustomize/overlays/default/
    kustomization.yaml        root overlay (base + secrets + patches)
    secrets/                  Secret manifests (gitignored)
    patches/                  Strategic merge patches for env vars, images, etc.

Usage:
  cp deploy/values.yaml.example deploy/values.yaml
  # edit values.yaml
  python3 deploy/configure.py
  kubectl apply -k deploy/kustomize/overlays/default/
"""
import os
import sys
import yaml
import textwrap

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
OVERLAY_DIR = os.path.join(SCRIPT_DIR, "kustomize", "overlays", "default")
SECRETS_DIR = os.path.join(OVERLAY_DIR, "secrets")
PATCHES_DIR = os.path.join(OVERLAY_DIR, "patches")
VALUES_FILE = os.path.join(SCRIPT_DIR, "values.yaml")

def load_values():
    if not os.path.exists(VALUES_FILE):
        print(f"ERROR: {VALUES_FILE} not found.")
        print(f"       cp deploy/values.yaml.example deploy/values.yaml")
        sys.exit(1)
    with open(VALUES_FILE) as f:
        return yaml.safe_load(f)

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    print(f"  wrote {os.path.relpath(path, SCRIPT_DIR)}")

def secret(name, namespace, string_data: dict) -> str:
    data = "\n".join(f"  {k}: {repr(v)}" for k, v in string_data.items())
    return textwrap.dedent(f"""\
        apiVersion: v1
        kind: Secret
        metadata:
          name: {name}
          namespace: {namespace}
        type: Opaque
        stringData:
        {data}
        """)

def generate_secrets(v):
    ch_pass   = v["clickhouse"]["password"]
    s3        = v["clickhouse"]["s3"]
    grafana   = v["grafana"]
    secrets   = []

    # clickhouse-password — three namespaces
    for ns in ("observability", "security", "panops"):
        write(os.path.join(SECRETS_DIR, f"clickhouse-password-{ns}.yaml"),
              secret("clickhouse-password", ns, {"password": ch_pass}))
        secrets.append(f"secrets/clickhouse-password-{ns}.yaml")

    # S3 credentials for Gigapipe / ClickHouse backup
    write(os.path.join(SECRETS_DIR, "clickhouse-s3-creds.yaml"),
          secret("clickhouse-s3-credentials", "observability", {
              "access_key_id": s3["accessKey"],
              "secret_access_key": s3["secretKey"],
              "endpoint": s3["endpoint"],
              "bucket": s3["bucket"],
          }))
    secrets.append("secrets/clickhouse-s3-creds.yaml")

    # Coroot needs ClickHouse creds too
    write(os.path.join(SECRETS_DIR, "coroot-clickhouse.yaml"),
          secret("coroot-clickhouse", "observability", {"password": ch_pass}))
    secrets.append("secrets/coroot-clickhouse.yaml")

    # Grafana admin
    write(os.path.join(SECRETS_DIR, "grafana-admin.yaml"),
          secret("grafana-admin-credentials", "observability", {
              "admin-user": "admin",
              "admin-password": grafana["adminPassword"],
          }))
    secrets.append("secrets/grafana-admin.yaml")

    # Grafana SMTP (optional)
    if grafana.get("smtp", {}).get("enabled"):
        smtp = grafana["smtp"]
        write(os.path.join(SECRETS_DIR, "grafana-smtp.yaml"),
              secret("grafana-smtp-credentials", "observability", {
                  "host": smtp["host"],
                  "user": smtp["user"],
                  "password": smtp["password"],
                  "from_address": smtp["fromAddress"],
                  "from_name": smtp["fromName"],
              }))
        secrets.append("secrets/grafana-smtp.yaml")

    # Grafana OIDC (optional)
    if grafana.get("oidc", {}).get("enabled"):
        oidc = grafana["oidc"]
        write(os.path.join(SECRETS_DIR, "grafana-oidc.yaml"),
              secret("grafana-oidc-credentials", "observability", {
                  "oauth-client-id": oidc["clientId"],
                  "oauth-client-secret": oidc["clientSecret"],
              }))
        secrets.append("secrets/grafana-oidc.yaml")

    return secrets

def generate_patches(v):
    domain   = v["domain"]
    panops_cfg = v.get("panops", {})
    images   = v.get("images", {})
    sc       = v.get("storageClass", "local-path")
    patches  = []

    # Assembler env patch
    env_patch = textwrap.dedent(f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: panops-assembler
          namespace: panops
        spec:
          template:
            spec:
              containers:
              - name: assembler
                image: {images.get('assembler', 'ghcr.io/getpanops/panops/assembler:latest')}
                env:
                - name: AUTO_REMEDIATION_MODE
                  value: "{panops_cfg.get('remediationMode', 'dry-run')}"
        """)
    write(os.path.join(PATCHES_DIR, "assembler-env.yaml"), env_patch)
    patches.append("patches/assembler-env.yaml")

    # Assembler image
    img_patch = textwrap.dedent(f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: panops-assembler
          namespace: panops
        spec:
          template:
            spec:
              containers:
              - name: assembler
                image: {images.get('assembler', 'ghcr.io/getpanops/panops/assembler:latest')}
        """)

    # HTTPRoute hostnames — one patch per route
    routes = {
        "grafana-httproute":  f"grafana.{domain}",
        "pyrra-httproute":    f"slo.{domain}",
        "coroot-httproute":   f"coroot.{domain}",
    }
    for name, hostname in routes.items():
        patch = textwrap.dedent(f"""\
            - op: replace
              path: /spec/hostnames/0
              value: {hostname}
            """)
        fname = f"httproute-{name}.yaml"
        write(os.path.join(PATCHES_DIR, fname), patch)
        patches.append((fname, name))

    # Storage class patch for model PVC
    sc_patch = textwrap.dedent(f"""\
        apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          name: panops-model-pvc
          namespace: panops
        spec:
          storageClassName: {sc}
        """)
    write(os.path.join(PATCHES_DIR, "storage-class.yaml"), sc_patch)
    patches.append("patches/storage-class.yaml")

    return patches, routes

def generate_gitignore():
    write(os.path.join(SECRETS_DIR, ".gitignore"),
          "# Generated secrets — never commit\n*.yaml\n")

def generate_overlay(secret_resources, patch_resources, route_patches):
    # Build kustomization.yaml
    secret_lines = "\n".join(f"  - {r}" for r in secret_resources)
    patch_lines = "\n".join(f"  - path: patches/{p}" for p in [
        "assembler-env.yaml",
        "storage-class.yaml",
    ])
    route_patch_lines = "\n".join(
        f"  - path: patches/httproute-{name}.yaml\n"
        f"    target:\n"
        f"      group: gateway.networking.k8s.io\n"
        f"      version: v1\n"
        f"      kind: HTTPRoute\n"
        f"      name: {name}"
        for name in route_patches
    )

    content = textwrap.dedent(f"""\
        # Generated by deploy/configure.py — do not edit by hand.
        # To update: edit deploy/values.yaml and re-run configure.py.
        apiVersion: kustomize.config.k8s.io/v1beta1
        kind: Kustomization

        resources:
          - ../../       # all operators + components
        {secret_lines}

        patches:
        {patch_lines}
        {route_patch_lines}
        """)
    write(os.path.join(OVERLAY_DIR, "kustomization.yaml"), content)

def main():
    print("PanOps configure")
    print(f"  values: {VALUES_FILE}")
    v = load_values()

    print("\nGenerating secrets...")
    secret_resources = generate_secrets(v)

    print("\nGenerating patches...")
    patch_resources, route_patches = generate_patches(v)

    generate_gitignore()
    generate_overlay(secret_resources, patch_resources, route_patches)

    print(f"""
Done. Overlay written to: deploy/kustomize/overlays/default/

To deploy:
  kubectl apply -k deploy/kustomize/overlays/default/

For Flux, update deploy/flux/kustomizations.yaml to point at:
  path: ./deploy/kustomize/overlays/default
""")

if __name__ == "__main__":
    main()
