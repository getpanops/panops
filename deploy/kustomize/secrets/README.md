# Secrets

Copy each `.example.yaml` file to the same name without `.example`, fill in your values,
and apply with `kubectl apply -f secrets/` before deploying the stack.

All secrets are gitignored. Never commit actual secret values.

Required secrets:
- clickhouse-password.yaml       (namespace: observability, security, panops)
- grafana-admin.yaml             (namespace: observability)
- grafana-smtp.yaml              (namespace: observability — optional, for email alerts)
- grafana-oidc.yaml              (namespace: observability — optional, for SSO)
- talon-config.yaml              (namespace: falco)
- clickhouse-s3-creds.yaml       (namespace: observability — for S3 backup)
