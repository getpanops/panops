FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config git libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

RUN CMAKE_ARGS="-DGGML_BLAS=ON -DGGML_BLAS_VENDOR=OpenBLAS" \
    pip install --no-cache-dir "llama-cpp-python[server]==0.3.9"

ENV MODEL=/models/Qwen2.5-3B-Instruct-Q4_K_M.gguf
ENV HOST=0.0.0.0
ENV PORT=8080
ENV N_CTX=4096
ENV N_THREADS=4
ENV INTERRUPT_REQUESTS=true
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "llama_cpp.server"]
