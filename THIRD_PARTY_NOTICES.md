# Third-Party Notices — panops

The panops source code is MIT-licensed — see [LICENSE](LICENSE).
This file covers third-party software that panops builds against or deploys.

---

## Python Dependencies

### pySigma
- **License:** LGPL 2.1
- **Source:** https://github.com/SigmaHQ/pySigma
- **Note:** Used unmodified via pip in the sigma-scanner image. LGPL 2.1 permits use in non-LGPL software provided the library is not statically embedded and users can substitute their own version. pip installation satisfies this requirement.

All other Python dependencies (clickhouse-driver, openai, httpx, structlog, kubernetes, mcp, pyyaml, pandas, scipy, adtk, llama-cpp-python) are MIT, BSD, or Apache 2.0 licensed.

---

## Deployed Services

panops deploys the following third-party services via Kubernetes manifests and Docker Compose.
These are separate works — their licenses do not affect the panops MIT license.

| Service | License | Source |
|---------|---------|--------|
| ClickHouse | Apache 2.0 | https://github.com/ClickHouse/ClickHouse |
| Gigapipe / qryn | AGPL 3.0 | https://github.com/metrico/qryn |
| Grafana | AGPL 3.0 | https://github.com/grafana/grafana |
| Grafana Loki | AGPL 3.0 | https://github.com/grafana/loki |
| OpenTelemetry Collector | Apache 2.0 | https://github.com/open-telemetry/opentelemetry-collector-contrib |
| Falco | Apache 2.0 | https://github.com/falcosecurity/falco |

AGPL 3.0 services are deployed unmodified. If you modify any AGPL service and deploy it as a network service, you must make those modifications available under AGPL 3.0.

---

## Intel Feed

Detection content is managed by the [nous](https://github.com/getpanops/nous) repository.
See nous/THIRD_PARTY_NOTICES.md for intel source licensing.
