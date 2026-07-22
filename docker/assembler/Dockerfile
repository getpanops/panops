FROM python:3.13-slim

RUN pip install --no-cache-dir \
    "scipy>=1.13,<2" \
    "numpy>=2.0,<3" \
    "fastembed>=0.5.0,<1" \
    "kubernetes==32.0.1" \
    "pywinrm>=0.4.3" \
    "bcrypt>=4.1"

COPY src/ /scripts/

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/scripts/assembler.py"]
