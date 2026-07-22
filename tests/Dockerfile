FROM python:3.12-slim

RUN pip install --no-cache-dir \
    pytest==8.3.* \
    pytest-timeout==2.3.*

WORKDIR /tests
COPY . /tests/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Default: run all tests. Override CMD to run specific modules.
CMD ["pytest", "-v", "--tb=short", "--timeout=150", "--no-header", "-rN"]
