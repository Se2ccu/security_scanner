"""
输出格式定义 - 定义report.json的JSON Schema和Agent间传递的数据结构
"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
import json


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class AttackPath:
    path: str
    description: str


@dataclass
class RiskyModule:
    module_path: str
    module_name: str
    entry_points: List[str]
    attack_paths: List[str]
    risk_level: RiskLevel
    risk_reason: str

    def to_dict(self):
        return {
            "module_path": self.module_path,
            "module_name": self.module_name,
            "entry_points": self.entry_points,
            "attack_paths": self.attack_paths,
            "risk_level": self.risk_level.value,
            "risk_reason": self.risk_reason
        }


@dataclass
class VulnerabilityPattern:
    pattern_name: str
    cwe_id: str
    check_rules: List[str]
    priority: str


@dataclass
class ModulePattern:
    module_path: str
    patterns: List[VulnerabilityPattern]

    def to_dict(self):
        return {
            "module_path": self.module_path,
            "patterns": [
                {"pattern_name": p.pattern_name, "cwe_id": p.cwe_id,
                 "check_rules": p.check_rules, "priority": p.priority}
                for p in self.patterns
            ]
        }


@dataclass
class Vulnerability:
    file: str
    function: str
    line: int
    type: str
    cwe_id: str
    severity: Severity
    description: str
    poc: str
    attack_chain: List[str]

    def to_dict(self):
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "type": self.type,
            "cwe_id": self.cwe_id,
            "severity": self.severity.value,
            "description": self.description,
            "poc": self.poc,
            "attack_chain": self.attack_chain
        }


@dataclass
class Agent1Output:
    risky_modules: List[RiskyModule]
    architecture_summary: str

    def to_dict(self):
        return {
            "risky_modules": [m.to_dict() for m in self.risky_modules],
            "architecture_summary": self.architecture_summary
        }


@dataclass
class Agent2Output:
    module_patterns: List[ModulePattern]

    def to_dict(self):
        return {
            "module_patterns": [m.to_dict() for m in self.module_patterns]
        }


@dataclass
class ScanReport:
    code_path: str
    scan_time: str
    agent1_output: Agent1Output
    agent2_output: Agent2Output
    vulnerabilities: List[Vulnerability]

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)

    def to_dict(self):
        return {
            "scan_summary": {
                "code_path": self.code_path,
                "scan_time": self.scan_time,
                "total_vulnerabilities": self.total_vulnerabilities
            },
            "agent1_output": self.agent1_output.to_dict(),
            "agent2_output": self.agent2_output.to_dict(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @staticmethod
    def from_dict(data: dict) -> 'ScanReport':
        return ScanReport(
            code_path=data["scan_summary"]["code_path"],
            scan_time=data["scan_summary"]["scan_time"],
            agent1_output=data["agent1_output"],
            agent2_output=data["agent2_output"],
            vulnerabilities=data["vulnerabilities"]
        )


# 默认漏洞模式库
DEFAULT_PATTERNS = [
    {
        "name": "SQL Injection",
        "cwe_id": "CWE-89",
        "check_rules": [
            "字符串拼接SQL查询",
            "未使用参数化查询",
            "直接使用用户输入构建SQL",
            "ORM误用导致注入"
        ],
        "applicable_modules": ["database", "api", "web"]
    },
    {
        "name": "Command Injection",
        "cwe_id": "CWE-78",
        "check_rules": [
            "使用system/exec/popen等执行系统命令",
            "字符串拼接命令参数",
            "未校验用户输入用于命令"
        ],
        "applicable_modules": ["system", "api", "cli"]
    },
    {
        "name": "Path Traversal",
        "cwe_id": "CWE-22",
        "check_rules": [
            "文件路径拼接用户输入",
            "未校验路径规范化和符号链接",
            "使用用户输入访问文件系统"
        ],
        "applicable_modules": ["file", "api", "web"]
    },
    {
        "name": "XSS",
        "cwe_id": "CWE-79",
        "check_rules": [
            "未转义的用户输入输出到HTML",
            "直接拼接HTML响应",
            "富文本过滤不严"
        ],
        "applicable_modules": ["web", "api"]
    },
    {
        "name": "Authentication Bypass",
        "cwe_id": "CWE-287",
        "check_rules": [
            "认证检查可被绕过",
            "弱密码校验逻辑",
            "会话固定漏洞",
            "权限检查缺失或不完整"
        ],
        "applicable_modules": ["auth", "api", "web"]
    },
    {
        "name": "Insecure Deserialization",
        "cwe_id": "CWE-502",
        "check_rules": [
            "反序列化用户可控数据",
            "使用pickle/yaml危险的加载方式"
        ],
        "applicable_modules": ["api", "web", "database"]
    },
    {
        "name": "SSRF",
        "cwe_id": "CWE-918",
        "check_rules": [
            "用户输入作为URL/URI参数",
            "未校验URL目标地址",
            "跟随重定向到内部服务"
        ],
        "applicable_modules": ["api", "web"]
    },
    {
        "name": "IDOR",
        "cwe_id": "CWE-639",
        "check_rules": [
            "资源访问未验证所有权",
            "直接使用用户ID访问他人资源",
            "顺序递增的ID可被猜测"
        ],
        "applicable_modules": ["api", "web"]
    }
]


def load_patterns() -> List[dict]:
    """加载漏洞模式库"""
    try:
        with open("/home/zt/Cline/security_scanner/rules/vuln_patterns.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("patterns", DEFAULT_PATTERNS)
    except FileNotFoundError:
        return DEFAULT_PATTERNS


def get_patterns_for_module(module_type: str) -> List[dict]:
    """获取适用于特定模块类型的漏洞模式"""
    all_patterns = load_patterns()
    return [p for p in all_patterns if module_type in p.get("applicable_modules", [])]