FROM python:3.13-slim
RUN pip install --no-cache-dir \
    openai>=1.30.0 \
    mcp>=1.0.0 \
    httpx>=0.27.0 \
    structlog>=24.0.0 \
    kubernetes>=29.0.0 \
    clickhouse-driver>=0.2.7
COPY requirements.txt /tmp/mem-requirements.txt
RUN pip install --no-cache-dir -r /tmp/mem-requirements.txt
WORKDIR /app
COPY src/ /app/
EXPOSE 8082
CMD ["python", "server.py"]
