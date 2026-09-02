// MicroVM 高级特性测试（借鉴 AgentENV）
// Memory Ballooning + Pause/Resume + State Fork + Layered Image
#include <gtest/gtest.h>
#include <thread>
#include <fstream>
#include "photon_kernel/sandbox/microvm_advanced.hpp"
using namespace photon_kernel::sandbox;
// ==================== Memory Ballooning 测试 ====================
TEST(MemoryBalloonTest, RegisterAndDefalte) {
    BalloonConfig config;
    config.base_memory_mb = 64;
    MemoryBalloon balloon(config);
    balloon.register_vm("vm-1", 256);
    EXPECT_EQ(balloon.current_memory_mb("vm-1"), 256u);
    EXPECT_EQ(balloon.state("vm-1"), BalloonState::INFLATED);
    // 放气到 64MB
    size_t reclaimed = balloon.deflate("vm-1", 64);
    EXPECT_GT(reclaimed, 0u);
    EXPECT_EQ(balloon.current_memory_mb("vm-1"), 64u);
    EXPECT_EQ(balloon.state("vm-1"), BalloonState::DEFLATED);
    EXPECT_GT(balloon.total_reclaimed_mb(), 0u);
    printf("  Deflated: reclaimed %zu MB, total reclaimed %zu MB\n",
           reclaimed, balloon.total_reclaimed_mb());
}
TEST(MemoryBalloonTest, InflateAfterDefalte) {
    BalloonConfig config;
    MemoryBalloon balloon(config);
    balloon.register_vm("vm-2", 256);
    balloon.deflate("vm-2", 64);
    EXPECT_EQ(balloon.state("vm-2"), BalloonState::DEFLATED);
    // 充气恢复
    size_t restored = balloon.inflate("vm-2", 256);
    EXPECT_GT(restored, 0u);
    EXPECT_EQ(balloon.current_memory_mb("vm-2"), 256u);
    EXPECT_EQ(balloon.state("vm-2"), BalloonState::INFLATED);
    printf("  Inflated: restored %zu MB\n", restored);
}
TEST(MemoryBalloonTest, ShouldDeflateOnIdle) {
    BalloonConfig config;
    config.idle_threshold_sec = 1;  // 1秒闲置就放气
    MemoryBalloon balloon(config);
    auto now = std::chrono::system_clock::now();
    auto idle_2s = now - std::chrono::seconds(2);
    EXPECT_TRUE(balloon.should_deflate("vm-x", idle_2s));
    auto active = now;
    EXPECT_FALSE(balloon.should_deflate("vm-x", active));
}
TEST(MemoryBalloonTest, UnregisterReturnsMemory) {
    BalloonConfig config;
    MemoryBalloon balloon(config);
    balloon.register_vm("vm-3", 256);
    balloon.deflate("vm-3", 64);
    size_t reclaimed_before = balloon.total_reclaimed_mb();
    balloon.unregister_vm("vm-3");
    EXPECT_LT(balloon.total_reclaimed_mb(), reclaimed_before);
    printf("  Unregister: returned memory to pool\n");
}
// ==================== VmPauser 测试 ====================
TEST(VmPauserTest, PauseAndResume) {
    PauseConfig config;
    VmPauser pauser(config);
    pauser.register_vm("vm-1");
    EXPECT_EQ(pauser.state("vm-1"), VmPauseState::RUNNING);
    // 暂停
    EXPECT_TRUE(pauser.pause("vm-1"));
    EXPECT_EQ(pauser.state("vm-1"), VmPauseState::PAUSED);
    EXPECT_GT(pauser.total_paused(), 0u);
    // 暂停持续时间（秒级精度，10ms 可能返回0）
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto duration = pauser.pause_duration("vm-1");
    EXPECT_GE(duration.count(), 0);
    // 恢复
    EXPECT_TRUE(pauser.resume("vm-1"));
    EXPECT_EQ(pauser.state("vm-1"), VmPauseState::RUNNING);
    EXPECT_GT(pauser.total_resumed(), 0u);
    printf("  Pause/Resume: paused %lld ms, total pause time %lld s\n",
           (long long)duration.count(), (long long)pauser.total_pause_time().count());
}
TEST(VmPauserTest, ShouldPauseOnIdle) {
    PauseConfig config;
    config.idle_timeout = std::chrono::seconds(1);
    VmPauser pauser(config);
    auto now = std::chrono::system_clock::now();
    auto idle = now - std::chrono::seconds(2);
    EXPECT_TRUE(pauser.should_pause("vm-x", idle));
    EXPECT_FALSE(pauser.should_pause("vm-x", now));
}
TEST(VmPauserTest, DoublePauseIsIdempotent) {
    PauseConfig config;
    VmPauser pauser(config);
    pauser.register_vm("vm-2");
    EXPECT_TRUE(pauser.pause("vm-2"));
    EXPECT_TRUE(pauser.pause("vm-2"));  // 再次暂停应该返回 true（已暂停）
    EXPECT_EQ(pauser.state("vm-2"), VmPauseState::PAUSED);
}
// ==================== VmForker 测试 ====================
TEST(VmForkerTest, ForkFromSource) {
    ForkConfig config;
    VmForker forker(config);
    auto result = forker.fork("source-vm", "fork-1");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.forked_vm_id, "fork-1");
    EXPECT_GT(result.shared_memory_mb, 0u);
    EXPECT_TRUE(forker.is_fork("fork-1"));
    EXPECT_EQ(forker.source_of("fork-1"), "source-vm");
    printf("  Fork: %s from source-vm, shared %zu MB, time %lld ms\n",
           result.forked_vm_id.c_str(), result.shared_memory_mb,
           (long long)result.fork_time.count());
}
TEST(VmForkerTest, ForkGeneratesId) {
    ForkConfig config;
    VmForker forker(config);
    auto result = forker.fork("source-vm-2");
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.forked_vm_id.empty());
    EXPECT_TRUE(result.forked_vm_id.find("fork-") == 0);
}
TEST(VmForkerTest, MaxForksPerVm) {
    ForkConfig config;
    config.max_forks_per_vm = 2;
    VmForker forker(config);
    EXPECT_TRUE(forker.fork("src", "f1").success);
    EXPECT_TRUE(forker.fork("src", "f2").success);
    // 第3个应该失败
    auto result = forker.fork("src", "f3");
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error.find("max forks"), std::string::npos);
    printf("  Max forks: 2/2, 3rd rejected\n");
}
TEST(VmForkerTest, UnregisterFork) {
    ForkConfig config;
    VmForker forker(config);
    forker.fork("src", "fork-x");
    EXPECT_TRUE(forker.is_fork("fork-x"));
    forker.unregister_fork("fork-x");
    EXPECT_FALSE(forker.is_fork("fork-x"));
}
// ==================== LayeredImageManager 测试 ====================
TEST(LayeredImageManagerTest, CreateBaseLayer) {
    LayeredImageConfig config;
    config.storage_dir = "/tmp/photon_test_layers";
    LayeredImageManager manager(config);
    // 创建测试源文件
    std::string src = "/tmp/photon_test_layer_src";
    {
        std::ofstream f(src);
        f << "base layer content";
    }
    std::string layer_id = manager.create_base_layer("base-test", src);
    EXPECT_FALSE(layer_id.empty());
    auto layer = manager.get_layer(layer_id);
    EXPECT_NE(layer, nullptr);
    EXPECT_TRUE(layer->read_only);
    EXPECT_EQ(layer->ref_count, 1);
    printf("  Base layer: %s, size %zu MB\n", layer_id.c_str(), layer->size_mb);
    std::remove(src.c_str());
}
TEST(LayeredImageManagerTest, CreateDeltaLayer) {
    LayeredImageConfig config;
    config.storage_dir = "/tmp/photon_test_layers2";
    LayeredImageManager manager(config);
    std::string base = manager.create_base_layer("base", "/tmp/nonexistent");
    std::string delta = manager.create_delta_layer(base, "delta-1");
    EXPECT_FALSE(delta.empty());
    auto layer = manager.get_layer(delta);
    EXPECT_NE(layer, nullptr);
    EXPECT_FALSE(layer->read_only);
    EXPECT_EQ(layer->parent_layer, base);
    printf("  Delta layer: %s (parent: %s)\n", delta.c_str(), base.c_str());
}
TEST(LayeredImageManagerTest, Deduplication) {
    LayeredImageConfig config;
    config.storage_dir = "/tmp/photon_test_layers3";
    config.enable_deduplication = true;
    LayeredImageManager manager(config);
    std::string src = "/tmp/photon_test_dedup_src";
    {
        std::ofstream f(src);
        f << "dedup content";
    }
    std::string layer1 = manager.create_base_layer("l1", src);
    std::string layer2 = manager.create_base_layer("l2", src);  // 相同内容
    EXPECT_EQ(layer1, layer2);  // 去重后应该返回同一个层
    auto layer = manager.get_layer(layer1);
    EXPECT_EQ(layer->ref_count, 2);  // 引用计数为2
    printf("  Deduplication: same content -> same layer, ref_count=%d\n", layer->ref_count);
    std::remove(src.c_str());
}
TEST(LayeredImageManagerTest, RemoveLayerWithRefCount) {
    LayeredImageConfig config;
    config.storage_dir = "/tmp/photon_test_layers4";
    LayeredImageManager manager(config);
    std::string src = "/tmp/photon_test_remove_src";
    {
        std::ofstream f(src);
        f << "remove test";
    }
    std::string layer = manager.create_base_layer("l", src);
    // 第一次 remove：ref_count 1->0，实际删除
    EXPECT_TRUE(manager.remove_layer(layer));
    EXPECT_EQ(manager.get_layer(layer), nullptr);
    std::remove(src.c_str());
}
TEST(LayeredImageManagerTest, MountLayers) {
    LayeredImageConfig config;
    config.storage_dir = "/tmp/photon_test_layers5";
    LayeredImageManager manager(config);
    std::string base = manager.create_base_layer("base", "/tmp/nonexistent");
    std::string delta = manager.create_delta_layer(base, "delta");
    std::string mount_point = "/tmp/photon_test_mount";
    std::string result = manager.mount_layers(base, {delta}, mount_point);
    EXPECT_FALSE(result.empty());
    printf("  Mount: %s\n", result.c_str());
}
// ==================== MicroVmAdvancedFeatures 统一测试 ====================
TEST(MicroVmAdvancedFeaturesTest, CapabilityMatrix) {
    MicroVmAdvancedFeatures::Config config;
    config.layered_image.storage_dir = "/tmp/photon_test_adv_layers";
    MicroVmAdvancedFeatures features(config);
    auto caps = features.capabilities();
    EXPECT_TRUE(caps.balloon);
    EXPECT_TRUE(caps.pause);
    EXPECT_TRUE(caps.fork);
    EXPECT_TRUE(caps.layered_image);
    printf("  Capabilities:\n%s", caps.to_string().c_str());
}
TEST(MicroVmAdvancedFeaturesTest, RegisterAndTick) {
    MicroVmAdvancedFeatures::Config config;
    config.pause.idle_timeout = std::chrono::seconds(1);
    config.balloon.idle_threshold_sec = 1;
    config.layered_image.storage_dir = "/tmp/photon_test_adv_layers2";
    MicroVmAdvancedFeatures features(config);
    features.register_vm("vm-1", 256);
    // 活动通知：应该充气+恢复
    features.notify_activity("vm-1");
    EXPECT_EQ(features.balloon().state("vm-1"), BalloonState::INFLATED);
    EXPECT_EQ(features.pauser().state("vm-1"), VmPauseState::RUNNING);
    // 闲置 tick：应该放气+暂停
    auto idle = std::chrono::system_clock::now() - std::chrono::seconds(2);
    features.tick("vm-1", idle);
    EXPECT_EQ(features.balloon().state("vm-1"), BalloonState::DEFLATED);
    EXPECT_EQ(features.pauser().state("vm-1"), VmPauseState::PAUSED);
    printf("  Tick: idle -> deflated + paused\n");
    // 活动通知：应该充气+恢复
    features.notify_activity("vm-1");
    EXPECT_EQ(features.balloon().state("vm-1"), BalloonState::INFLATED);
    EXPECT_EQ(features.pauser().state("vm-1"), VmPauseState::RUNNING);
    printf("  Activity: inflated + resumed\n");
    features.unregister_vm("vm-1");
}
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
