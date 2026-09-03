"""
evolution.raw_layer — WikiSkill 原始轨迹层（Raw Layer）

WikiSkill 三层架构的最底层：
- 保存原始执行轨迹，不可变（append-only），作为证据
- 记录每次 Skill 执行的完整上下文：输入、输出、错误、耗时、工具调用
- 不做任何加工，保留原始数据供 Wiki 层编译

参考论文：WikiSkill: Compiling Agent Experience into Persistent Knowledge for Skill Evolution
- Google Research, 2026
- 三层架构：Raw Layer → Wiki Layer → Skill Layer
- Raw 层关键设计：不可变、留证据、不加工

设计原则：
1. 只追加，不修改（append-only）
2. 完整记录，不丢失上下文
3. 带哈希校验，防止篡改
4. 可追溯，每条记录有唯一ID和时间戳
"""
from __future__ import annotations
import json
import hashlib
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict


@dataclass
class RawTrajectory:
    """
    原始执行轨迹（不可变）

    记录一次 Skill 执行的完整上下文，作为 Wiki 层编译的原材料。
    一旦创建，不可修改（append-only）。
    """
    trajectory_id: str = field(default_factory=lambda: f"raw_{int(time.time()*1000)}_{hash(id(object()))%10000:04d}")
    skill_id: str = ""
    skill_name: str = ""
    skill_version: str = ""
    task: str = ""                          # 任务描述
    input_data: Dict[str, Any] = field(default_factory=dict)  # 完整输入
    output_data: Dict[str, Any] = field(default_factory=dict)  # 完整输出
    success: bool = False
    error: str = ""
    error_type: str = ""                   # 错误类型：timeout / exception / logic_error / validation_error
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)  # 工具调用记录
    duration_ms: int = 0
    token_usage: Dict[str, int] = field(default_factory=dict)  # token 使用统计
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)  # 额外元数据
    _hash: str = ""                        # 内容哈希（防篡改）

    def __post_init__(self):
        """创建时计算哈希"""
        if not self._hash:
            self._hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """计算内容哈希（防篡改）"""
        content = json.dumps({
            "skill_id": self.skill_id,
            "skill_version": self.skill_version,
            "task": self.task,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "success": self.success,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def verify_integrity(self) -> bool:
        """验证轨迹完整性（防篡改）"""
        return self._hash == self._compute_hash()

    def to_dict(self) -> dict:
        """转换为字典"""
        d = asdict(self)
        d["_hash"] = self._hash
        return d

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class RawLayer:
    """
    原始轨迹层（Raw Layer）

    WikiSkill 三层架构的最底层，负责：
    1. 记录原始执行轨迹（append-only，不可修改）
    2. 提供轨迹查询和检索
    3. 完整性校验（防篡改）
    4. 按 Skill、时间、成功率等维度筛选

    关键设计：
    - 只追加，不修改、不删除
    - 每条轨迹带哈希校验
    - 内存存储 + 可选持久化到文件
    - 为 Wiki 层提供原材料

    使用示例：
        raw = RawLayer()
        trajectory = raw.record(
            skill_id="code_gen",
            task="生成排序函数",
            input_data={"language": "python"},
            output_data={"code": "def sort(): ..."},
            success=True,
            duration_ms=1500,
        )
        # 查询失败轨迹
        failures = raw.get_failures(skill_id="code_gen")
        # 验证完整性
        assert raw.verify_all()
    """

    def __init__(self, max_trajectories: int = 10000, persist_path: Optional[str] = None):
        """
        初始化原始轨迹层

        Args:
            max_trajectories: 最大轨迹数量（超过后淘汰最旧的）
            persist_path: 持久化文件路径（可选，None 表示仅内存）
        """
        self._trajectories: List[RawTrajectory] = []
        self._max_trajectories = max_trajectories
        self._persist_path = persist_path
        self._total_recorded = 0
        self._tamper_detected = 0

        # 如果有持久化路径，尝试加载
        if persist_path:
            self._load_from_file()

    def record(self,
               skill_id: str,
               task: str,
               input_data: Optional[Dict[str, Any]] = None,
               output_data: Optional[Dict[str, Any]] = None,
               success: bool = False,
               error: str = "",
               error_type: str = "",
               tool_calls: Optional[List[Dict[str, Any]]] = None,
               duration_ms: int = 0,
               token_usage: Optional[Dict[str, int]] = None,
               skill_name: str = "",
               skill_version: str = "",
               metadata: Optional[Dict[str, Any]] = None) -> RawTrajectory:
        """
        记录一条原始执行轨迹（append-only）

        Args:
            skill_id: Skill ID
            task: 任务描述
            input_data: 完整输入数据
            output_data: 完整输出数据
            success: 是否成功
            error: 错误信息
            error_type: 错误类型
            tool_calls: 工具调用记录
            duration_ms: 执行耗时（毫秒）
            token_usage: token 使用统计
            skill_name: Skill 名称
            skill_version: Skill 版本
            metadata: 额外元数据

        Returns:
            创建的 RawTrajectory 对象
        """
        trajectory = RawTrajectory(
            skill_id=skill_id,
            skill_name=skill_name,
            skill_version=skill_version,
            task=task,
            input_data=input_data or {},
            output_data=output_data or {},
            success=success,
            error=error,
            error_type=error_type,
            tool_calls=tool_calls or [],
            duration_ms=duration_ms,
            token_usage=token_usage or {},
            metadata=metadata or {},
        )

        self._trajectories.append(trajectory)
        self._total_recorded += 1

        # 超过最大数量，淘汰最旧的
        if len(self._trajectories) > self._max_trajectories:
            self._trajectories = self._trajectories[-self._max_trajectories:]

        # 持久化
        if self._persist_path:
            self._save_to_file()

        return trajectory

    def get_all(self) -> List[RawTrajectory]:
        """获取所有轨迹"""
        return list(self._trajectories)

    def get_by_skill(self, skill_id: str) -> List[RawTrajectory]:
        """按 Skill ID 获取轨迹"""
        return [t for t in self._trajectories if t.skill_id == skill_id]

    def get_failures(self, skill_id: Optional[str] = None) -> List[RawTrajectory]:
        """获取失败轨迹"""
        failures = [t for t in self._trajectories if not t.success]
        if skill_id:
            failures = [t for t in failures if t.skill_id == skill_id]
        return failures

    def get_successes(self, skill_id: Optional[str] = None) -> List[RawTrajectory]:
        """获取成功轨迹"""
        successes = [t for t in self._trajectories if t.success]
        if skill_id:
            successes = [t for t in successes if t.skill_id == skill_id]
        return successes

    def get_recent(self, count: int = 10, skill_id: Optional[str] = None) -> List[RawTrajectory]:
        """获取最近的轨迹"""
        trajectories = self._trajectories
        if skill_id:
            trajectories = [t for t in trajectories if t.skill_id == skill_id]
        return trajectories[-count:]

    def get_by_error_type(self, error_type: str) -> List[RawTrajectory]:
        """按错误类型获取轨迹"""
        return [t for t in self._trajectories if t.error_type == error_type]

    def get_success_rate(self, skill_id: Optional[str] = None, window: Optional[int] = None) -> float:
        """
        计算成功率

        Args:
            skill_id: 可选，按 Skill 过滤
            window: 可选，只看最近 N 条

        Returns:
            成功率（0.0 - 1.0）
        """
        trajectories = self._trajectories
        if skill_id:
            trajectories = [t for t in trajectories if t.skill_id == skill_id]
        if window:
            trajectories = trajectories[-window:]

        if not trajectories:
            return 0.0

        successes = sum(1 for t in trajectories if t.success)
        return successes / len(trajectories)

    def verify_all(self) -> bool:
        """验证所有轨迹的完整性（防篡改）"""
        for trajectory in self._trajectories:
            if not trajectory.verify_integrity():
                self._tamper_detected += 1
                return False
        return True

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self._trajectories)
        successes = sum(1 for t in self._trajectories if t.success)
        failures = total - successes

        # 按 Skill 统计
        skill_stats: Dict[str, Dict[str, Any]] = {}
        for t in self._trajectories:
            if t.skill_id not in skill_stats:
                skill_stats[t.skill_id] = {"total": 0, "success": 0, "failure": 0}
            skill_stats[t.skill_id]["total"] += 1
            if t.success:
                skill_stats[t.skill_id]["success"] += 1
            else:
                skill_stats[t.skill_id]["failure"] += 1

        # 按错误类型统计
        error_type_stats: Dict[str, int] = {}
        for t in self._trajectories:
            if t.error_type:
                error_type_stats[t.error_type] = error_type_stats.get(t.error_type, 0) + 1

        return {
            "total": total,
            "total_recorded": self._total_recorded,
            "success": successes,
            "failure": failures,
            "success_rate": successes / total if total > 0 else 0.0,
            "tamper_detected": self._tamper_detected,
            "skill_stats": skill_stats,
            "error_type_stats": error_type_stats,
        }

    def _save_to_file(self):
        """持久化到文件"""
        if not self._persist_path:
            return
        try:
            data = [t.to_dict() for t in self._trajectories]
            with open(self._persist_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass  # 持久化失败不影响主流程

    def _load_from_file(self):
        """从文件加载"""
        if not self._persist_path:
            return
        try:
            with open(self._persist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for item in data:
                trajectory = RawTrajectory(**{k: v for k, v in item.items() if k != '_hash'})
                trajectory._hash = item.get('_hash', '')
                self._trajectories.append(trajectory)
            self._total_recorded = len(self._trajectories)
        except Exception:
            pass  # 加载失败不影响主流程

    def clear(self):
        """清空所有轨迹（谨慎使用）"""
        self._trajectories.clear()
        self._total_recorded = 0
        self._tamper_detected = 0
