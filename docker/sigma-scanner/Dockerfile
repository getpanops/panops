# pySigma-backend-clickhouse requires Python >=3.13
FROM python:3.13-slim

# yr binary must be in the build context before building.
# CI downloads it automatically (see build-images job in .github/workflows/ci.yml).
# For local builds:
#   wget https://github.com/VirusTotal/yara-x/releases/download/v1.19.0/yara-x-v1.19.0-x86_64-unknown-linux-gnu.tar.gz
#   tar -xzf yara-x-v1.19.0-x86_64-unknown-linux-gnu.tar.gz yr && mv yr docker/sigma-scanner/
COPY yr /usr/local/bin/yr
RUN chmod +x /usr/local/bin/yr && yr --version

ARG CACHE_BUST=2
RUN pip install --no-cache-dir \
    'pySigma>=1.0.0,<2' \
    'pySigma-backend-clickhouse' \
    'pySigma-pipeline-sysmon' \
    'pySigma-pipeline-windows' \
    'adtk>=0.6' \
    'pandas>=2.2,<3' \
    'scipy>=1.13,<2' \
    'pyyaml' \
    'kubernetes==32.0.1'

COPY src/ /scripts/

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/scripts/sigma-scanner.py"]
