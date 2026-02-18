# Stage 1: Build dependencies
FROM python:3.11-alpine AS builder

# Install build dependencies for aioquic and other C-extensions
RUN apk add --no-cache \
    gcc \
    python3-dev \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust

WORKDIR /build
COPY app/requirements.txt .

# Install dependencies into a wheelhouse or just to the site-packages
RUN pip install --prefix=/install -r requirements.txt

# Stage 2: Final image
FROM python:3.11-alpine

# Install runtime libraries needed by the dependencies
RUN apk add --no-cache libffi openssl libgcc

WORKDIR /app

# Copy the installed packages from the builder stage
COPY --from=builder /install /usr/local

COPY app/* /app

ENTRYPOINT ["python3", "dns_latency_tester.py"]
