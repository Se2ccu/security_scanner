"""
Agent2: 漏洞模式分析
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from pathlib import Path
from typing import List, Dict, Any
from output_format import ModulePattern, VulnerabilityPattern, Agent2Output
from utils import run_opencode, save_json, load_json, build_context_prompt
from output_format import load_patterns, get_patterns_for_module


SYSTEM_PROMPT = """你是一个漏洞模式分析专家，负责根据风险模块类型匹配相关漏洞模式。

## 任务
基于Agent1的分析结果，为每个风险模块生成需要检查的漏洞模式列表。

## 输入 (Agent1输出)
{agent1_output}

## 代码路径
{code_path}

## 分析要求

### 1. 加载内置漏洞模式库
内置以下常见漏洞模式：
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- XSS (CWE-79)
- Authentication Bypass (CWE-287)
- Insecure Deserialization (CWE-502)
- SSRF (CWE-918)
- IDOR (CWE-639)

### 2. 根据模块特性匹配模式
- 数据库相关模块 → SQL Injection, Insecure Deserialization
- API模块 → 根据输入类型匹配相关模式
- 认证模块 → Authentication Bypass, IDOR
- 文件处理模块 → Path Traversal
- 网络请求模块 → SSRF

### 3. 动态补充业务逻辑模式
根据Agent1发现的入口点，补充特定检查规则：
- 如果有认证流程，检查认证绕过逻辑
- 如果有文件上传，检查上传绕过
- 如果有外部API调用，检查SSRF

### 4. 输出格式
```json
{{
  "module_patterns": [
    {{
      "module_path": "模块路径",
      "patterns": [
        {{
          "pattern_name": "漏洞类型",
          "cwe_id": "CWE编号",
          "check_rules": ["具体检查规则"],
          "priority": "HIGH|MEDIUM|LOW"
        }}
      ]
    }}
  ]
}}
```

## 重要提示
- 每个模块至少匹配1个相关模式
- 根据风险级别调整优先级
- 输出必须是有效的JSON格式
"""


class Agent2:
    """漏洞模式分析Agent"""

    def __init__(self, code_path: str, agent1_output: Dict[str, Any], output_path: str,
                 agent_name: str = None, model: str = None):
        self.code_path = code_path
        self.agent1_output = agent1_output
        self.output_path = output_path
        self.agent_name = agent_name
        self.model = model

    def analyze(self) -> Dict[str, Any]:
        """
        执行漏洞模式分析

        Returns:
            Agent2输出字典
        """
        prompt = SYSTEM_PROMPT.format(
            agent1_output=json.dumps(self.agent1_output, ensure_ascii=False, indent=2),
            code_path=self.code_path
        )

        # 执行opencode分析
        result = run_opencode(prompt, cwd=self.code_path, agent=self.agent_name, model=self.model)

        # 解析结果
        try:
            data = json.loads(result)
        except json.JSONDecodeError:
            data = self._extract_json(result)

        # 如果仍为空，尝试从输出文件读取
        if not data and Path(self.output_path).exists():
            try:
                with open(self.output_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        # 保存结果
        if data:
            save_json(data, self.output_path)

        return data if data else {"module_patterns": []}

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """从文本中提取JSON数据"""
        import re
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {}

    def get_module_patterns(self) -> List[ModulePattern]:
        """获取模块模式列表"""
        try:
            with open(self.output_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return [
                ModulePattern(
                    module_path=m["module_path"],
                    patterns=[
                        VulnerabilityPattern(
                            pattern_name=p["pattern_name"],
                            cwe_id=p.get("cwe_id", ""),
                            check_rules=p.get("check_rules", []),
                            priority=p.get("priority", "MEDIUM")
                        )
                        for p in m.get("patterns", [])
                    ]
                )
                for m in data.get("module_patterns", [])
            ]
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return []


def run_agent2(code_path: str, agent1_output: Dict[str, Any], output_path: str,
               agent_name: str = None, model: str = None) -> Dict[str, Any]:
    """运行Agent2的便捷函数"""
    agent = Agent2(code_path, agent1_output, output_path, agent_name, model)
    return agent.analyze()