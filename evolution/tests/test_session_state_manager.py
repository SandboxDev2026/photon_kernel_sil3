"""
PhotonBox 服务器端会话状态管理 - 单元测试

覆盖：
1. 会话生命周期（创建/获取/更新/挂起/恢复/完成/删除）
2. 状态读写（get/set/update，单字段和批量）
3. 快照管理（创建/列出/恢复，滚动窗口）
4. 跨会话恢复（previous_session_id 模式，会话链）
5. 多租户隔离（租户命名空间，跨租户访问拒绝）
6. 过期清理（TTL 过期自动标记）
7. 审计日志（变更记录，操作追踪）
8. 持久化（文件存储，加载恢复）
9. 统计信息
"""

import unittest
import sys
import os
import tempfile
import time
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.session_state_manager import (
    SessionStateManager, SessionState, SessionSnapshot, SessionChangeLog,
    SessionStatus, SessionType, create_session_manager,
)


class TestSessionLifecycle(unittest.TestCase):
    """会话生命周期测试"""

    def setUp(self):
        self.manager = SessionStateManager()

    def test_create_session(self):
        """创建会话"""
        session = self.manager.create_session(
            session_type=SessionType.SANDBOX.value,
            tenant_id="tenant-a",
            initial_state={"key": "value"},
        )
        self.assertTrue(session.session_id.startswith("sess_"))
        self.assertEqual(session.session_type, "sandbox")
        self.assertEqual(session.tenant_id, "tenant-a")
        self.assertEqual(session.status, SessionStatus.ACTIVE.value)
        self.assertEqual(session.state["key"], "value")

    def test_create_session_with_ttl(self):
        """创建带 TTL 的会话"""
        session = self.manager.create_session(ttl=3600)
        self.assertIsNotNone(session.expires_at)
        self.assertGreater(session.expires_at, time.time())

    def test_create_session_without_ttl(self):
        """创建无 TTL 的会话"""
        session = self.manager.create_session()
        self.assertIsNone(session.expires_at)

    def test_get_session(self):
        """获取会话"""
        session = self.manager.create_session(tenant_id="tenant-a")
        retrieved = self.manager.get_session(session.session_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.session_id, session.session_id)

    def test_get_nonexistent_session(self):
        """获取不存在的会话"""
        self.assertIsNone(self.manager.get_session("nonexistent"))

    def test_get_session_tenant_isolation(self):
        """租户隔离：跨租户获取被拒绝"""
        session = self.manager.create_session(tenant_id="tenant-a")
        # 用错误的租户 ID 获取
        retrieved = self.manager.get_session(session.session_id, tenant_id="tenant-b")
        self.assertIsNone(retrieved)
        # 用正确的租户 ID 获取
        retrieved = self.manager.get_session(session.session_id, tenant_id="tenant-a")
        self.assertIsNotNone(retrieved)

    def test_update_state(self):
        """更新会话状态"""
        session = self.manager.create_session(initial_state={"a": 1})
        updated = self.manager.update_state(session.session_id, {"b": 2, "c": 3})
        self.assertEqual(updated.state["a"], 1)
        self.assertEqual(updated.state["b"], 2)
        self.assertEqual(updated.state["c"], 3)

    def test_set_state(self):
        """设置单个状态字段"""
        session = self.manager.create_session()
        self.manager.set_state(session.session_id, "key", "value")
        value = self.manager.get_state_value(session.session_id, "key")
        self.assertEqual(value, "value")

    def test_get_state_value_default(self):
        """获取不存在的状态字段返回默认值"""
        session = self.manager.create_session()
        value = self.manager.get_state_value(session.session_id, "nonexistent", "default")
        self.assertEqual(value, "default")

    def test_suspend_session(self):
        """挂起会话"""
        session = self.manager.create_session()
        suspended = self.manager.suspend_session(session.session_id, reason="test")
        self.assertEqual(suspended.status, SessionStatus.SUSPENDED.value)
        # 挂起时应创建快照
        snapshots = self.manager.list_snapshots(session.session_id)
        self.assertGreater(len(snapshots), 0)

    def test_resume_session(self):
        """恢复挂起的会话"""
        session = self.manager.create_session(initial_state={"key": "value"})
        self.manager.suspend_session(session.session_id)
        # 修改状态后挂起的快照应该保留原始值
        resumed = self.manager.resume_session(session.session_id)
        self.assertEqual(resumed.status, SessionStatus.ACTIVE.value)
        self.assertEqual(resumed.state["key"], "value")

    def test_complete_session(self):
        """完成会话"""
        session = self.manager.create_session()
        completed = self.manager.complete_session(
            session.session_id, final_state={"result": "success"}
        )
        self.assertEqual(completed.status, SessionStatus.COMPLETED.value)
        self.assertEqual(completed.state["result"], "success")

    def test_delete_session(self):
        """删除会话"""
        session = self.manager.create_session()
        result = self.manager.delete_session(session.session_id)
        self.assertTrue(result)
        self.assertIsNone(self.manager.get_session(session.session_id))

    def test_delete_nonexistent_session(self):
        """删除不存在的会话"""
        self.assertFalse(self.manager.delete_session("nonexistent"))

    def test_delete_session_tenant_isolation(self):
        """删除会话的租户隔离"""
        session = self.manager.create_session(tenant_id="tenant-a")
        result = self.manager.delete_session(session.session_id, tenant_id="tenant-b")
        self.assertFalse(result)
        # 会话仍然存在
        self.assertIsNotNone(self.manager.get_session(session.session_id))


class TestSnapshotManagement(unittest.TestCase):
    """快照管理测试"""

    def setUp(self):
        self.manager = SessionStateManager(max_snapshots_per_session=5)

    def test_create_snapshot(self):
        """创建快照"""
        session = self.manager.create_session(initial_state={"key": "value"})
        snapshot = self.manager.create_snapshot(session.session_id, reason="test")
        self.assertTrue(snapshot.snapshot_id.startswith("snap_"))
        self.assertEqual(snapshot.session_id, session.session_id)
        self.assertEqual(snapshot.state["key"], "value")
        self.assertEqual(snapshot.reason, "test")

    def test_list_snapshots(self):
        """列出快照"""
        session = self.manager.create_session()
        self.manager.create_snapshot(session.session_id)
        self.manager.create_snapshot(session.session_id)
        snapshots = self.manager.list_snapshots(session.session_id)
        self.assertEqual(len(snapshots), 3)  # 初始快照 + 2个手动快照

    def test_restore_snapshot(self):
        """从快照恢复"""
        session = self.manager.create_session(initial_state={"key": "v1"})
        snapshot = self.manager.create_snapshot(session.session_id)
        self.manager.set_state(session.session_id, "key", "v2")
        self.manager.restore_snapshot(session.session_id, snapshot.snapshot_id)
        restored = self.manager.get_session(session.session_id)
        self.assertEqual(restored.state["key"], "v1")

    def test_restore_nonexistent_snapshot(self):
        """恢复不存在的快照"""
        session = self.manager.create_session()
        result = self.manager.restore_snapshot(session.session_id, "nonexistent")
        self.assertIsNone(result)

    def test_snapshot_rolling_window(self):
        """快照滚动窗口（保留最近 N 个）"""
        manager = SessionStateManager(max_snapshots_per_session=3)
        session = manager.create_session()
        for i in range(10):
            manager.create_snapshot(session.session_id)
        snapshots = manager.list_snapshots(session.session_id)
        self.assertEqual(len(snapshots), 3)  # 只保留最近 3 个

    def test_restore_creates_pre_restore_snapshot(self):
        """恢复前自动创建当前状态快照"""
        session = self.manager.create_session(initial_state={"key": "v1"})
        snapshot = self.manager.create_snapshot(session.session_id)
        self.manager.set_state(session.session_id, "key", "v2")
        before_count = len(self.manager.list_snapshots(session.session_id))
        self.manager.restore_snapshot(session.session_id, snapshot.snapshot_id)
        after_count = len(self.manager.list_snapshots(session.session_id))
        self.assertEqual(after_count, before_count + 1)  # 多了一个 pre_restore 快照


class TestCrossSessionResume(unittest.TestCase):
    """跨会话恢复测试（Google Gemini Interactions API 模式）"""

    def setUp(self):
        self.manager = SessionStateManager()

    def test_resume_from_previous(self):
        """从之前的会话恢复"""
        previous = self.manager.create_session(
            initial_state={"key": "value"},
            metadata={"meta": "data"},
            tags=["tag1"],
        )
        new_session = self.manager.resume_from_previous(previous.session_id)
        self.assertIsNotNone(new_session)
        self.assertEqual(new_session.parent_session_id, previous.session_id)
        self.assertEqual(new_session.state["key"], "value")
        self.assertEqual(new_session.metadata["meta"], "data")
        self.assertIn("tag1", new_session.tags)

    def test_resume_from_previous_inherit_state_false(self):
        """不继承状态"""
        previous = self.manager.create_session(initial_state={"key": "value"})
        new_session = self.manager.resume_from_previous(
            previous.session_id, inherit_state=False
        )
        self.assertEqual(new_session.state, {})

    def test_resume_from_previous_new_type(self):
        """新会话类型覆盖"""
        previous = self.manager.create_session(session_type="sandbox")
        new_session = self.manager.resume_from_previous(
            previous.session_id, new_session_type="audit"
        )
        self.assertEqual(new_session.session_type, "audit")

    def test_resume_from_nonexistent(self):
        """从不存在的会话恢复"""
        result = self.manager.resume_from_previous("nonexistent")
        self.assertIsNone(result)

    def test_resume_from_previous_tenant_isolation(self):
        """跨会话恢复的租户隔离"""
        previous = self.manager.create_session(tenant_id="tenant-a")
        # 用错误的租户 ID 恢复
        result = self.manager.resume_from_previous(
            previous.session_id, tenant_id="tenant-b"
        )
        self.assertIsNone(result)

    def test_get_session_chain(self):
        """获取会话链"""
        session1 = self.manager.create_session()
        session2 = self.manager.resume_from_previous(session1.session_id)
        session3 = self.manager.resume_from_previous(session2.session_id)
        chain = self.manager.get_session_chain(session3.session_id)
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[0].session_id, session1.session_id)
        self.assertEqual(chain[1].session_id, session2.session_id)
        self.assertEqual(chain[2].session_id, session3.session_id)

    def test_session_chain_no_parent(self):
        """无父会话的会话链"""
        session = self.manager.create_session()
        chain = self.manager.get_session_chain(session.session_id)
        self.assertEqual(len(chain), 1)

    def test_inherited_metadata_marks_source(self):
        """继承元数据标记来源"""
        previous = self.manager.create_session()
        new_session = self.manager.resume_from_previous(previous.session_id)
        self.assertEqual(new_session.metadata["inherited_from"], previous.session_id)
        self.assertIn("inherited_at", new_session.metadata)


class TestMultiTenantIsolation(unittest.TestCase):
    """多租户隔离测试"""

    def setUp(self):
        self.manager = SessionStateManager()

    def test_list_sessions_by_tenant(self):
        """按租户列出租户"""
        self.manager.create_session(tenant_id="tenant-a")
        self.manager.create_session(tenant_id="tenant-a")
        self.manager.create_session(tenant_id="tenant-b")
        tenant_a = self.manager.list_sessions_by_tenant("tenant-a")
        tenant_b = self.manager.list_sessions_by_tenant("tenant-b")
        self.assertEqual(len(tenant_a), 2)
        self.assertEqual(len(tenant_b), 1)

    def test_list_sessions_by_tenant_status_filter(self):
        """按状态过滤租户会话"""
        self.manager.create_session(tenant_id="tenant-a")
        suspended = self.manager.create_session(tenant_id="tenant-a")
        self.manager.suspend_session(suspended.session_id)
        active = self.manager.list_sessions_by_tenant(
            "tenant-a", status_filter=SessionStatus.ACTIVE.value
        )
        suspended_list = self.manager.list_sessions_by_tenant(
            "tenant-a", status_filter=SessionStatus.SUSPENDED.value
        )
        self.assertEqual(len(active), 1)
        self.assertEqual(len(suspended_list), 1)

    def test_list_sessions_by_tenant_type_filter(self):
        """按类型过滤租户会话"""
        self.manager.create_session(tenant_id="tenant-a", session_type="sandbox")
        self.manager.create_session(tenant_id="tenant-a", session_type="audit")
        sandbox = self.manager.list_sessions_by_tenant(
            "tenant-a", session_type_filter="sandbox"
        )
        self.assertEqual(len(sandbox), 1)
        self.assertEqual(sandbox[0].session_type, "sandbox")

    def test_get_tenant_statistics(self):
        """获取租户统计"""
        self.manager.create_session(tenant_id="tenant-a", session_type="sandbox")
        self.manager.create_session(tenant_id="tenant-a", session_type="audit")
        stats = self.manager.get_tenant_statistics("tenant-a")
        self.assertEqual(stats["tenant_id"], "tenant-a")
        self.assertEqual(stats["total_sessions"], 2)
        self.assertEqual(stats["active_sessions"], 2)
        self.assertIn("sandbox", stats["sessions_by_type"])
        self.assertIn("audit", stats["sessions_by_type"])

    def test_empty_tenant_statistics(self):
        """空租户统计"""
        stats = self.manager.get_tenant_statistics("nonexistent")
        self.assertEqual(stats["total_sessions"], 0)


class TestExpirationCleanup(unittest.TestCase):
    """过期清理测试"""

    def setUp(self):
        self.manager = SessionStateManager()

    def test_cleanup_expired(self):
        """清理过期会话"""
        session = self.manager.create_session(ttl=0.01)
        time.sleep(0.02)
        count = self.manager.cleanup_expired()
        self.assertEqual(count, 1)
        expired = self.manager.get_session(session.session_id)
        self.assertEqual(expired.status, SessionStatus.EXPIRED.value)

    def test_no_expired_sessions(self):
        """无过期会话"""
        self.manager.create_session(ttl=3600)
        count = self.manager.cleanup_expired()
        self.assertEqual(count, 0)

    def test_expired_session_creates_snapshot(self):
        """过期会话自动创建快照"""
        session = self.manager.create_session(ttl=0.01, initial_state={"key": "value"})
        time.sleep(0.02)
        self.manager.cleanup_expired()
        snapshots = self.manager.list_snapshots(session.session_id)
        # 初始快照 + 过期快照
        self.assertGreaterEqual(len(snapshots), 2)

    def test_non_active_session_not_expired(self):
        """非活跃会话不被过期清理"""
        session = self.manager.create_session(ttl=0.01)
        self.manager.suspend_session(session.session_id)
        time.sleep(0.02)
        count = self.manager.cleanup_expired()
        self.assertEqual(count, 0)  # 已挂起，不处理


class TestAuditLog(unittest.TestCase):
    """审计日志测试"""

    def setUp(self):
        self.manager = SessionStateManager(enable_audit_log=True)

    def test_create_session_logged(self):
        """创建会话被记录"""
        session = self.manager.create_session()
        logs = self.manager.get_change_logs(session.session_id)
        self.assertTrue(any(log.operation == "create" for log in logs))

    def test_update_state_logged(self):
        """更新状态被记录"""
        session = self.manager.create_session()
        self.manager.update_state(session.session_id, {"key": "value"})
        logs = self.manager.get_change_logs(session.session_id)
        update_logs = [log for log in logs if log.operation == "update"]
        self.assertGreater(len(update_logs), 0)
        self.assertEqual(update_logs[-1].field, "key")
        self.assertEqual(update_logs[-1].new_value, "value")

    def test_suspend_resume_logged(self):
        """挂起和恢复被记录"""
        session = self.manager.create_session()
        self.manager.suspend_session(session.session_id)
        self.manager.resume_session(session.session_id)
        logs = self.manager.get_change_logs(session.session_id)
        operations = [log.operation for log in logs]
        self.assertIn("suspend", operations)
        self.assertIn("resume", operations)

    def test_delete_logged(self):
        """删除被记录"""
        session = self.manager.create_session()
        self.manager.delete_session(session.session_id)
        logs = self.manager.get_change_logs(session.session_id)
        self.assertTrue(any(log.operation == "delete" for log in logs))

    def test_audit_log_disabled(self):
        """审计日志禁用"""
        manager = SessionStateManager(enable_audit_log=False)
        session = manager.create_session()
        logs = manager.get_change_logs(session.session_id)
        self.assertEqual(len(logs), 0)

    def test_change_log_limit(self):
        """变更日志数量限制"""
        logs = self.manager.get_change_logs(limit=5)
        self.assertLessEqual(len(logs), 5)


class TestPersistence(unittest.TestCase):
    """持久化测试"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="photonbox_test_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_session_persisted_to_file(self):
        """会话持久化到文件"""
        manager = SessionStateManager(storage_dir=self.tmpdir)
        session = manager.create_session(initial_state={"key": "value"})
        # 检查文件是否存在
        files = os.listdir(self.tmpdir)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].startswith("session_"))
        self.assertTrue(files[0].endswith(".json"))

    def test_load_from_storage(self):
        """从存储加载会话"""
        manager1 = SessionStateManager(storage_dir=self.tmpdir)
        session = manager1.create_session(
            tenant_id="tenant-a",
            initial_state={"key": "value"},
        )
        session_id = session.session_id

        # 创建新的管理器，应该从文件加载
        manager2 = SessionStateManager(storage_dir=self.tmpdir)
        loaded = manager2.get_session(session_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.tenant_id, "tenant-a")
        self.assertEqual(loaded.state["key"], "value")

    def test_delete_removes_file(self):
        """删除会话移除文件"""
        manager = SessionStateManager(storage_dir=self.tmpdir)
        session = manager.create_session()
        self.assertEqual(len(os.listdir(self.tmpdir)), 1)
        manager.delete_session(session.session_id)
        self.assertEqual(len(os.listdir(self.tmpdir)), 0)

    def test_save_all(self):
        """强制保存所有会话"""
        manager = SessionStateManager(storage_dir=self.tmpdir)
        manager.create_session()
        manager.create_session()
        manager.save_all()
        self.assertEqual(len(os.listdir(self.tmpdir)), 2)


class TestStatistics(unittest.TestCase):
    """统计信息测试"""

    def setUp(self):
        self.manager = SessionStateManager()

    def test_get_statistics(self):
        """获取统计信息"""
        self.manager.create_session(session_type="sandbox", tenant_id="tenant-a")
        self.manager.create_session(session_type="audit", tenant_id="tenant-b")
        stats = self.manager.get_statistics()
        self.assertEqual(stats["total_sessions"], 2)
        self.assertEqual(stats["total_tenants"], 2)
        self.assertIn("sandbox", stats["sessions_by_type"])
        self.assertIn("audit", stats["sessions_by_type"])
        self.assertGreater(stats["total_snapshots"], 0)  # 每个会话有初始快照

    def test_empty_statistics(self):
        """空管理器统计"""
        stats = self.manager.get_statistics()
        self.assertEqual(stats["total_sessions"], 0)
        self.assertEqual(stats["total_tenants"], 0)
        self.assertEqual(stats["total_snapshots"], 0)


class TestConvenienceFunctions(unittest.TestCase):
    """便捷接口函数测试"""

    def test_create_session_manager(self):
        """创建会话管理器"""
        manager = create_session_manager()
        self.assertIsInstance(manager, SessionStateManager)

    def test_create_session_manager_with_storage(self):
        """带存储目录创建"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = create_session_manager(storage_dir=tmpdir, default_ttl=3600)
            self.assertEqual(manager.storage_dir, tmpdir)
            self.assertEqual(manager.default_ttl, 3600)


class TestSessionStateDataclass(unittest.TestCase):
    """会话状态数据类测试"""

    def test_to_dict(self):
        """序列化为字典"""
        session = SessionState(
            session_id="test-1",
            session_type="sandbox",
            tenant_id="tenant-a",
            state={"key": "value"},
        )
        d = session.to_dict()
        self.assertEqual(d["session_id"], "test-1")
        self.assertEqual(d["session_type"], "sandbox")
        self.assertEqual(d["state"]["key"], "value")

    def test_from_dict(self):
        """从字典反序列化"""
        data = {
            "session_id": "test-1",
            "session_type": "sandbox",
            "tenant_id": "tenant-a",
            "status": "active",
            "created_at": 1000.0,
            "updated_at": 1000.0,
            "last_accessed_at": 1000.0,
            "expires_at": None,
            "state": {"key": "value"},
            "metadata": {},
            "parent_session_id": None,
            "tags": [],
        }
        session = SessionState.from_dict(data)
        self.assertEqual(session.session_id, "test-1")
        self.assertEqual(session.state["key"], "value")

    def test_from_dict_ignores_extra_fields(self):
        """从字典反序列化忽略额外字段"""
        data = {
            "session_id": "test-1",
            "session_type": "sandbox",
            "tenant_id": "tenant-a",
            "status": "active",
            "created_at": 1000.0,
            "updated_at": 1000.0,
            "last_accessed_at": 1000.0,
            "expires_at": None,
            "state": {},
            "metadata": {},
            "parent_session_id": None,
            "tags": [],
            "extra_field": "should_be_ignored",
        }
        session = SessionState.from_dict(data)
        self.assertEqual(session.session_id, "test-1")
        self.assertFalse(hasattr(session, "extra_field"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
