"""
Agent1: 代码架构与威胁分析
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from output_format import RiskyModule, RiskLevel, Agent1Output
from utils import run_opencode, save_json, build_context_prompt


SYSTEM_PROMPT = """你是一个代码安全架构分析师，负责分析代码结构并识别潜在的安全威胁。

## 任务
分析目标代码，识别外部入口点和攻击路径，标记高风险模块。

## 输入
- 代码路径: {code_path}
- 输出路径: {output_path}

## 分析要求

### 1. 代码结构扫描
- 列出主要目录和文件
- 识别模块划分和依赖关系
- 确定代码语言和框架

### 2. 外部入口点识别
- HTTP API 接口
- 文件上传/下载点
- 命令行接口
- 数据库连接点
- 外部服务调用

### 3. 攻击路径追踪
对于每个外部入口，分析数据流向：
- 入口 → 输入校验 → 业务处理 → 数据存储
- 追踪未校验的用户输入如何传播到危险操作

### 4. 风险模块标记
根据以下条件标记风险级别：
- HIGH: 有外部入口且包含危险操作（SQL/命令执行/文件操作）
- MEDIUM: 有外部入口或包含敏感操作
- LOW: 无外部入口的内部模块

## 输出格式
输出JSON到 {output_path}，格式如下：
{{
  "risky_modules": [
    {{
      "module_path": "文件或目录路径",
      "module_name": "模块名称",
      "entry_points": ["入口点列表"],
      "attack_paths": ["攻击路径列表"],
      "risk_level": "HIGH|MEDIUM|LOW",
      "risk_reason": "为什么标记为风险"
    }}
  ],
  "architecture_summary": "架构总体描述"
}}

## 重要提示
- 输出必须是有效的JSON格式
- 每个风险模块必须给出具体的entry_points和attack_paths
- 专注于识别真实的攻击面，不是所有文件都需要标记
"""


class Agent1:
    """代码架构与威胁分析Agent"""

    def __init__(self, code_path: str, output_path: str, agent_name: str = None, model: str = None):
        self.code_path = code_path
        self.output_path = output_path
        self.agent_name = agent_name
        self.model = model

    def analyze(self) -> Dict[str, Any]:
        """
        执行架构分析和威胁建模

        Returns:
            Agent1输出字典
        """
        prompt = SYSTEM_PROMPT.format(
            code_path=self.code_path,
            output_path=self.output_path
        )

        # 执行opencode分析
        result = run_opencode(prompt, cwd=self.code_path, agent=self.agent_name, model=self.model)

        # 解析结果
        import json
        try:
            data = json.loads(result)
        except json.JSONDecodeError:
            # 如果直接解析失败，尝试提取JSON
            data = self._extract_json(result)

        # 如果仍为空，尝试从输出文件读取（opencode可能直接写了文件）
        if not data and Path(self.output_path).exists():
            try:
                with open(self.output_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        # 保存结果
        if data:
            save_json(data, self.output_path)

        return data if data else {"risky_modules": [], "architecture_summary": ""}

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """从文本中提取JSON数据"""
        import re
        # 查找JSON对象
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {}

    def get_risky_modules(self) -> List[RiskyModule]:
        """获取分析出的风险模块列表"""
        import json
        try:
            with open(self.output_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return [
                RiskyModule(
                    module_path=m["module_path"],
                    module_name=m["module_name"],
                    entry_points=m.get("entry_points", []),
                    attack_paths=m.get("attack_paths", []),
                    risk_level=RiskLevel(m["risk_level"]),
                    risk_reason=m.get("risk_reason", "")
                )
                for m in data.get("risky_modules", [])
            ]
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return []


def run_agent1(code_path: str, output_path: str, agent_name: str = None, model: str = None) -> Dict[str, Any]:
    """运行Agent1的便捷函数"""
    agent = Agent1(code_path, output_path, agent_name, model)
    return agent.analyze()