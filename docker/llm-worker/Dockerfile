FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config git libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# Build with OpenBLAS acceleration
RUN CMAKE_ARGS="-DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS" \
    pip install --no-cache-dir llama-cpp-python==0.3.9

ARG CACHE_BUST=1
COPY src/ /scripts/

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/scripts/llm-infer.py"]
