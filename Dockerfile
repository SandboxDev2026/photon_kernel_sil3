# Photon Kernel Sandbox - Docker 构建环境
# 多阶段构建：builder 编译，runtime 运行
# 用法:
#   docker build -t photon-sandbox:latest .
#   docker run --rm photon-sandbox:latest ./build/test_enhanced
# ---- Builder 阶段 ----
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
# 安装编译依赖（含 gRPC + OpenSSL + GTest）
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    libgtest-dev \
    libgmock-dev \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# 安装 Python gRPC 工具（用于契约测试）
RUN pip3 install --no-cache-dir grpcio grpcio-tools protobuf
WORKDIR /src
# 复制源码
COPY . .
# 构建（启用 gRPC + 测试）
RUN chmod +x scripts/build.sh && \
    ./scripts/build.sh --all || \
    (echo "构建失败，尝试非 gRPC 模式..." && \
     ./scripts/build.sh --clean --test)
# ---- Runtime 阶段 ----
FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
# 运行时依赖（最小化）
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    libgcc-s1 \
    libprotobuf23 \
    libgrpc++1 \
    python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# 从 builder 复制构建产物
COPY --from=builder /src/build /app/build
COPY --from=builder /src/proto /app/proto
COPY --from=builder /src/tests /app/tests
COPY --from=builder /src/scripts /app/scripts
# 默认运行测试
CMD ["./build/test_enhanced"]
# 可用命令:
#   docker run --rm photon-sandbox ./build/metrics_server 9090
#   docker run --rm -p 3000:3000 photon-sandbox ./build/e2b_gateway 3000
#   docker run --rm photon-sandbox ./build/sandbox_server  # 需要 gRPC 构建
