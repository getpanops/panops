FROM python:3.13-slim

RUN pip install --no-cache-dir drain3==0.9.11

COPY miner.py /scripts/miner.py

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/scripts/miner.py"]
