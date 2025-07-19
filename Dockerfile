# Multi-stage build for CluelyGuard
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libpulse-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src/ ./src/

COPY config/ ./config/

# Copy Python BAM module
COPY bam/ ./bam/

# Install Python dependencies
RUN pip3 install joblib numpy scikit-learn

# Build the Rust application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libpulse0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create cluelyguard user


# Copy built binaries
COPY --from=builder /app/target/release/cluelyguard /usr/local/bin/
COPY --from=builder /app/target/release/cluelyguard-daemon /usr/local/bin/

# Copy Python BAM module
COPY --from=builder /app/bam/ /opt/cluelyguard/bam/

# Install Python dependencies
RUN pip3 install joblib numpy scikit-learn

# Copy configuration
COPY config/default.yaml /etc/cluelyguard/default.yaml

# Set working directory
WORKDIR /opt/cluelyguard

# Switch to cluelyguard user
USER cluelyguard

# Expose API port
CMD ["cluelyguard-daemon", "--student-code", "docker-student"] 