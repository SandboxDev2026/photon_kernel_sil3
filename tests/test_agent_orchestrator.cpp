// 多智能体编排层测试：MessageBus + Environment + AgentBase + Supervisor + TaskDAG + AgentOrchestrator
#include <gtest/gtest.h>
#include "agent/message_bus.hpp"
#include "agent/environment.hpp"
#include "agent/agent_base.hpp"
#include "agent/orchestrator.hpp"
#include "photon_kernel/sandbox/capability_token.hpp"
using namespace photon_kernel::agent;
using namespace photon_kernel::sandbox;
// ==================== MessageBus 测试 ====================
TEST(MessageBusTest, RegisterAndSend) {
    MessageBus::instance().reset();
    std::string received;
    std::string agent1 = MessageBus::instance().register_agent("agent1",
        [&](const Message& msg) { received = msg.content; });
    std::string agent2 = MessageBus::instance().register_agent("agent2", nullptr);
    Message msg;
    msg.from = agent2;
    msg.to = agent1;
    msg.type = MessageType::DIRECT;
    msg.content = "hello";
    EXPECT_TRUE(MessageBus::instance().send(msg));
    EXPECT_EQ(received, "hello");
    EXPECT_EQ(MessageBus::instance().active_agents(), 2u);
}
TEST(MessageBusTest, AuditHashChain) {
    MessageBus::instance().reset();
    std::string agent1 = MessageBus::instance().register_agent("a1", nullptr);
    std::string agent2 = MessageBus::instance().register_agent("a2", nullptr);
    Message m1, m2;
    m1.from = agent1; m1.to = agent2; m1.type = MessageType::DIRECT; m1.content = "first";
    m2.from = agent2; m2.to = agent1; m2.type = MessageType::DIRECT; m2.content = "second";
    MessageBus::instance().send(m1);
    MessageBus::instance().send(m2);
    EXPECT_EQ(MessageBus::instance().total_messages(), 2u);
}
TEST(MessageBusTest, Broadcast) {
    MessageBus::instance().reset();
    int count = 0;
    std::string a1 = MessageBus::instance().register_agent("a1", [&](const Message&){ count++; });
    std::string a2 = MessageBus::instance().register_agent("a2", [&](const Message&){ count++; });
    std::string sender = MessageBus::instance().register_agent("sender", nullptr);
    Message msg;
    msg.from = sender;
    msg.type = MessageType::BROADCAST;
    msg.content = "broadcast";
    EXPECT_TRUE(MessageBus::instance().broadcast(msg));
    EXPECT_EQ(count, 2);  // a1 和 a2 各收到一次
}
// ==================== Environment 测试 ====================
TEST(EnvironmentTest, ToolRegistration) {
    Environment::instance().reset();
    auto tools = Environment::instance().available_tools();
    EXPECT_GE(tools.size(), 3u);  // code_execution, shell, file_read
}
TEST(EnvironmentTest, PermissionDenied) {
    Environment::instance().reset();
    CapabilityTokenManager mgr("test-key");
    auto token = mgr.issue("agent-1", Capability::NONE);  // 无任何权限
    ToolCallRequest req;
    req.agent_id = "agent-1";
    req.tool_name = "code_execution";
    req.args_json = "{\"code\":\"print(1)\"}";
    auto result = Environment::instance().call_tool(req, token);
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error.find("permission denied"), std::string::npos);
    EXPECT_EQ(Environment::instance().denied_calls(), 1u);
}
TEST(EnvironmentTest, PermissionGranted) {
    Environment::instance().reset();
    CapabilityTokenManager mgr("test-key");
    auto token = mgr.issue("agent-1", Capability::EXEC | Capability::FILE_READ);
    ToolCallRequest req;
    req.agent_id = "agent-1";
    req.tool_name = "file_read";
    req.args_json = "{\"path\":\"/etc/hostname\"}";
    auto result = Environment::instance().call_tool(req, token);
    // file_read 应该有权限（FILE_READ），但文件可能不存在
    EXPECT_TRUE(result.success || result.error.find("cannot open") != std::string::npos);
}
// ==================== TaskDAG 测试 ====================
TEST(TaskDAGTest, AddAndReady) {
    TaskDAG dag;
    Task t1, t2;
    t1.id = "t1"; t1.title = "task1"; t1.status = TaskStatus::PENDING;
    t2.id = "t2"; t2.title = "task2"; t2.status = TaskStatus::PENDING;
    t2.dependencies = {"t1"};
    dag.add_task(t1);
    dag.add_task(t2);
    auto ready = dag.get_ready_tasks();
    EXPECT_EQ(ready.size(), 1u);  // 只有 t1 就绪
    EXPECT_EQ(ready[0].id, "t1");
}
TEST(TaskDAGTest, DependencyCompletion) {
    TaskDAG dag;
    Task t1, t2;
    t1.id = "t1"; t1.status = TaskStatus::PENDING;
    t2.id = "t2"; t2.status = TaskStatus::PENDING;
    t2.dependencies = {"t1"};
    dag.add_task(t1);
    dag.add_task(t2);
    EXPECT_FALSE(dag.all_completed());
    dag.complete_task("t1", "done");
    auto ready = dag.get_ready_tasks();
    EXPECT_EQ(ready.size(), 1u);  // t2 现在就绪
    EXPECT_EQ(ready[0].id, "t2");
    dag.complete_task("t2", "done");
    EXPECT_TRUE(dag.all_completed());
}
TEST(TaskDAGTest, TopologicalSort) {
    TaskDAG dag;
    Task t1, t2, t3;
    t1.id = "t1"; t1.status = TaskStatus::PENDING;
    t2.id = "t2"; t2.status = TaskStatus::PENDING; t2.dependencies = {"t1"};
    t3.id = "t3"; t3.status = TaskStatus::PENDING; t3.dependencies = {"t2"};
    dag.add_task(t1); dag.add_task(t2); dag.add_task(t3);
    std::vector<std::string> order;
    EXPECT_TRUE(dag.topological_sort(order));
    EXPECT_EQ(order.size(), 3u);
    EXPECT_EQ(order[0], "t1");
    EXPECT_EQ(order[1], "t2");
    EXPECT_EQ(order[2], "t3");
}
// ==================== AgentOrchestrator 测试 ====================
TEST(AgentOrchestratorTest, FullPipeline) {
    AgentOrchestrator orchestrator;
    CapabilityTokenManager mgr("orch-key");
    // 添加 3 个 Agent
    auto arch_token = mgr.issue("arch", Capability::EXEC | Capability::FILE_READ);
    auto dev_token = mgr.issue("dev", Capability::EXEC | Capability::FILE_READ);
    auto test_token = mgr.issue("test", Capability::EXEC | Capability::FILE_READ);
    orchestrator.add_agent("architect", AgentRole::ARCHITECT, std::move(arch_token));
    orchestrator.add_agent("developer", AgentRole::DEVELOPER, std::move(dev_token));
    orchestrator.add_agent("tester", AgentRole::TESTER, std::move(test_token));
    // 添加任务 DAG
    orchestrator.add_task("design", "设计", "设计系统架构", AgentRole::ARCHITECT);
    orchestrator.add_task("implement", "实现", "实现代码", AgentRole::DEVELOPER, {"design"});
    orchestrator.add_task("test", "测试", "编写测试", AgentRole::TESTER, {"implement"});
    // 运行
    auto result = orchestrator.run(std::chrono::seconds(30));
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.completed, 3u);
    EXPECT_EQ(result.failed, 0u);
    EXPECT_GT(result.task_results.size(), 0u);
}
TEST(AgentOrchestratorTest, GoalDecomposition) {
    AgentOrchestrator orchestrator;
    CapabilityTokenManager mgr("orch-key");
    auto token = mgr.issue("worker", Capability::EXEC | Capability::FILE_READ);
    orchestrator.add_agent("worker", AgentRole::WORKER, std::move(token));
    orchestrator.set_goal("构建一个Web应用");
    auto result = orchestrator.run(std::chrono::seconds(30));
    // Supervisor 自动拆解为 design→implement→test
    EXPECT_GE(result.completed, 1u);
}
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
