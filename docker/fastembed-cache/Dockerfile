FROM python:3.13-slim

RUN pip install --no-cache-dir fastembed==0.4.2

# Pre-download the all-MiniLM-L6-v2 ONNX model at build time so assembler pods
# do not fetch ~90 MB from HuggingFace at startup. Files land at /fastembed-cache/.
ENV FASTEMBED_CACHE_PATH=/fastembed-cache
RUN printf '%s\n' \
    'from fastembed import TextEmbedding' \
    'import os' \
    'list(TextEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2",cache_dir=os.environ["FASTEMBED_CACHE_PATH"]).embed(["warmup"]))' \
    'print("Model cached successfully")' \
    > /tmp/warmup.py \
    && python3 /tmp/warmup.py \
    && ls -lh /fastembed-cache/
