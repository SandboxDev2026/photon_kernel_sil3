cmake_minimum_required(VERSION 3.14)
project(photon_kernel_sil3_v414 VERSION 4.14.0 LANGUAGES CXX)

# ============================================================
# 第十六条 SBOM：强制锁定编译器版本
# （V4.14 法案要求，先于所有编译动作执行）
# ============================================================
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 11.2.0)
        message(FATAL_ERROR "GCC >= 11.2.0 required. Current: ${CMAKE_CXX_COMPILER_VERSION}")
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14.0.0)
        message(FATAL_ERROR "Clang >= 14.0.0 required. Current: ${CMAKE_CXX_COMPILER_VERSION}")
    endif()
else()
    message(FATAL_ERROR "Unsupported compiler. Must be GCC 11.2.0+ or Clang 14.0.0+")
endif()

# ============================================================
# C++ 标准与编译选项
# ============================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror=return-type -pthread")
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)  # 审计防篡改 HMAC-SHA256

# ============================================================
# 静态分析工具版本锁定（V4.14 第十条：静态分析）
# 要求 clang-tidy >= 14.0.0；未安装时打印提示（不影响核心库构建）。
# ============================================================
find_program(CLANG_TIDY_EXE clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15 clang-tidy-14)
if(CLANG_TIDY_EXE)
  execute_process(COMMAND ${CLANG_TIDY_EXE} --version
                  OUTPUT_VARIABLE CLANG_TIDY_VERSION_STR OUTPUT_STRIP_TRAILING_WHITESPACE)
  message(STATUS "clang-tidy: ${CLANG_TIDY_VERSION_STR} (config: .clang-tidy)")
  # 版本解析（仅取主版本号）并校验 >= 14
  string(REGEX MATCH "version ([0-9]+)" _ver "${CLANG_TIDY_VERSION_STR}")
  if(_ver)
    string(REGEX REPLACE ".*version ([0-9]+).*" "\1" CLANG_TIDY_MAJOR "${CLANG_TIDY_VERSION_STR}")
    if(CLANG_TIDY_MAJOR VERSION_LESS 14)
      message(WARNING "clang-tidy ${CLANG_TIDY_MAJOR} < 14.0.0 (V4.14 第十条要求 >=14)")
    endif()
  endif()
else()
  message(STATUS "clang-tidy not found -> static analysis skip (V4.14 第十条; install clang-tidy-14)")
endif()
# ============================================================
# 第二十五条 MC/DC 覆盖率（≥95%）
# ============================================================
option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
if(ENABLE_COVERAGE)
  add_compile_options(--coverage -O0 -g)
  add_link_options(--coverage)
  find_program(LCOV_EXE lcov)
  find_program(GENHTML_EXE genhtml)
  if(LCOV_EXE AND GENHTML_EXE)
    add_custom_target(coverage
      COMMAND ${LCOV_EXE} --capture --directory . --output-file coverage.info
      COMMAND ${LCOV_EXE} --remove coverage.info -o coverage_filtered.info
            '/usr/*' '*/googletest/*' '*/tests/*'
      COMMAND ${GENHTML_EXE} coverage_filtered.info --output-directory coverage_html
      COMMAND echo "MC/DC coverage report: ${CMAKE_BINARY_DIR}/coverage_html/index.html"
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Generating MC/DC coverage report")
  else()
    message(STATUS "lcov/genhtml not found -> coverage target skipped (install lcov)")
  endif()
endif()

# 可选：gRPC 服务端/客户端
option(PHOTON_ENABLE_GRPC "Build gRPC server/client (requires gRPC + protobuf)" ON)

# ============================================================
# 核心沙盒库（不依赖 gRPC：config / policy / executor / pool）
# ============================================================
# V4.14 合规模块（跳数归零 + 增量合规）
set(V414_SOURCES
  src/safety/jump_counter.cpp
  src/incremental_compliance.cpp
)
# 法案合规引擎（《人工智能工程安全管理法案》22 条）
set(ACT_SOURCES
  src/act/act_defs.cpp
  src/act/act_audit_events.cpp
  src/act/act_risk_grade.cpp
  src/act/act_output_limiter.cpp
  src/act/act_circuit_breaker.cpp
  src/act/act_self_diagnosis.cpp
  src/act/act_governance.cpp
  src/act/act_lifecycle.cpp
  src/act/act_penalty.cpp
  src/act/act_compliance.cpp
  src/act/act_evidence.cpp
)

set(SANDBOX_SOURCES
  src/sandbox/sandbox_config.cpp
  src/sandbox/sandbox_policy.cpp
  src/sandbox/sandboxed_executor.cpp
  src/sandbox/sandbox_pool.cpp
  src/sandbox/audit_logger.cpp
  src/sandbox/audit_grpc_sink.cpp
  src/sandbox/audit_security.cpp
  src/sandbox/code_runner.cpp
  src/sandbox/prewarmed_worker.cpp
  src/sandbox/sandbox_pool_v2.cpp
  src/sandbox/sandbox_snapshot.cpp
  src/sandbox/snapshot_manager.cpp
  src/sandbox/cgroup_manager.cpp
  src/sandbox/metrics.cpp
  src/sandbox/landlock.cpp
  src/sandbox/http_server.cpp
  src/sandbox/ebpf_network.cpp
  ${V414_SOURCES}
  ${ACT_SOURCES}
)

add_library(photon_sandbox STATIC ${SANDBOX_SOURCES})
target_include_directories(photon_sandbox PUBLIC include)
target_link_libraries(photon_sandbox PUBLIC Threads::Threads OpenSSL::Crypto)

# ============================================================
# 单元测试（需 GTest；未安装时自动跳过，并打印提示）
# ============================================================
find_package(GTest QUIET)
if(GTest_FOUND)
  add_executable(test_sandbox tests/test_sandbox.cpp)
  target_link_libraries(test_sandbox photon_sandbox GTest::gtest GTest::gtest_main Threads::Threads)
  enable_testing()
  add_test(NAME SandboxTests COMMAND test_sandbox)

  # 生产级增强测试（5 项增强）
  add_executable(test_enhanced
    tests/eh_audit_logger.cpp
    tests/eh_audit_security.cpp
    tests/eh_code_runner.cpp
    tests/eh_prewarmed_worker.cpp
    tests/eh_pool_v2.cpp
    tests/eh_sandbox_snapshot.cpp
    tests/eh_v414_compliance.cpp
    tests/eh_act_compliance.cpp
    tests/eh_nuclear_optimizations.cpp
  tests/eh_ebpf_criu_quality.cpp
  )
  target_link_libraries(test_enhanced photon_sandbox GTest::gtest GTest::gtest_main Threads::Threads)
  add_test(NAME EnhancedTests COMMAND test_enhanced)

  # 延迟对比基准（无需 google/benchmark）
  add_executable(sandbox_benchmark_v2 tests/benchmark_pool_v2.cpp)
  target_link_libraries(sandbox_benchmark_v2 photon_sandbox Threads::Threads)

  # ---- Prometheus /metrics HTTP 端点 ----
  add_executable(metrics_server server/metrics_server.cpp)
  target_link_libraries(metrics_server photon_sandbox Threads::Threads)

  # ---- E2B SDK 兼容 HTTP 网关 ----
  add_executable(e2b_gateway server/e2b_gateway.cpp)
  target_link_libraries(e2b_gateway photon_sandbox Threads::Threads)
else()
  message(WARNING "GTest not found -> test_sandbox skipped. "
                  "Install with: sudo apt install libgtest-dev, then build googletest, "
                  "or pass -DGTest_DIR=<googletest-build>/lib/cmake/GTest")
endif()

# ============================================================
# 基准测试（需 google/benchmark；未安装时自动跳过）
# ============================================================
find_package(benchmark QUIET)
if(benchmark_FOUND)
  add_executable(sandbox_benchmark tests/benchmark_pool.cpp)
  target_link_libraries(sandbox_benchmark photon_sandbox benchmark::benchmark Threads::Threads)
else()
  message(STATUS "google/benchmark not found -> sandbox_benchmark skipped")
endif()

# ============================================================
# gRPC 服务端 / 客户端（需 gRPC + protobuf）
# ============================================================
if(PHOTON_ENABLE_GRPC)
  find_package(gRPC CONFIG QUIET)
  find_package(Protobuf QUIET)
  if(gRPC_FOUND AND Protobuf_FOUND)
    set(PROTO_SRCS ${CMAKE_CURRENT_BINARY_DIR}/sandbox.pb.cc)
    set(PROTO_HDRS ${CMAKE_CURRENT_BINARY_DIR}/sandbox.pb.h)
    set(GRPC_SRCS ${CMAKE_CURRENT_BINARY_DIR}/sandbox.grpc.pb.cc)
    set(GRPC_HDRS ${CMAKE_CURRENT_BINARY_DIR}/sandbox.grpc.pb.h)

    add_custom_command(
      OUTPUT ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
      COMMAND protobuf::protoc
      ARGS --grpc_out=${CMAKE_CURRENT_BINARY_DIR}
           --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
           -I${CMAKE_CURRENT_SOURCE_DIR}/proto
           --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
           ${CMAKE_CURRENT_SOURCE_DIR}/proto/sandbox.proto
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/sandbox.proto
      COMMENT "Generating gRPC code from sandbox.proto"
    )

    add_library(photon_sandbox_grpc STATIC
      src/sandbox/sandbox_service.cpp
      ${PROTO_SRCS} ${GRPC_SRCS}
    )
    target_include_directories(photon_sandbox_grpc PUBLIC include ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(photon_sandbox_grpc
      photon_sandbox
      gRPC::grpc++
      gRPC::grpc
      protobuf::libprotobuf
      Threads::Threads
    )

    add_executable(sandbox_server server/sandbox_server.cpp)
    target_link_libraries(sandbox_server photon_sandbox_grpc)

    add_executable(sandbox_client client/sandbox_client.cpp)
    target_link_libraries(sandbox_client photon_sandbox_grpc)
  else()
    message(WARNING "gRPC/Protobuf not found -> gRPC server/client skipped. "
                    "Install with: sudo apt install -y protobuf-compiler libprotobuf-dev "
                    "libgrpc++-dev protobuf-compiler-grpc")
  endif()
endif()
