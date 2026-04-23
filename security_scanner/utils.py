"""
OpenCode工具封装
"""
import subprocess
import json
from typing import Optional, Dict, Any


def run_opencode(prompt: str, cwd: str = None, timeout: int = 1200,
                  agent: str = None, model: str = None) -> str:
    """
    执行 opencode run 命令

    Args:
        prompt: 要发送给opencode的提示
        cwd: 工作目录
        timeout: 超时时间（秒）
        agent: 指定使用的agent名称
        model: 指定使用的模型 (格式: provider/model)

    Returns:
        opencode命令的输出
    """
    cmd = ["opencode", "run", prompt]
    if agent:
        cmd.extend(["--agent", agent])
    if model:
        cmd.extend(["--model", model])
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=timeout
    )
    if result.stderr:
        print(f"opencode stderr: {result.stderr}", file=__import__('sys').stderr)
    return result.stdout


def parse_opencode_json_output(output: str) -> Optional[Dict[str, Any]]:
    """
    解析opencode输出的JSON字符串

    Args:
        output: opencode的输出

    Returns:
        解析后的字典，解析失败返回None
    """
    try:
        # 尝试直接解析
        return json.loads(output)
    except json.JSONDecodeError:
        # 尝试提取JSON块
        lines = output.strip().split('\n')
        for i, line in enumerate(lines):
            if '{' in line:
                json_str = '\n'.join(lines[i:])
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    continue
        return None


def extract_json_from_response(response: str) -> Optional[Dict[str, Any]]:
    """
    从OpenCode响应中提取JSON数据

    处理可能包含markdown代码块的情况
    """
    import re

    # 移除markdown代码块标记
    cleaned = re.sub(r'```json\s*', '', response)
    cleaned = re.sub(r'```\s*', '', cleaned)

    try:
        return json.loads(cleaned.strip())
    except json.JSONDecodeError:
        # 尝试找到JSON数组或对象
        match = re.search(r'\{[\s\S]*\}|\[[\s\S]*\]', cleaned)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None


def save_json(data: Dict[str, Any], filepath: str) -> None:
    """保存JSON到文件"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_json(filepath: str) -> Optional[Dict[str, Any]]:
    """从文件加载JSON"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Failed to load {filepath}: {e}")
        return None


def build_context_prompt(base_prompt: str, context: Dict[str, Any]) -> str:
    """
    将上下文信息构建到提示中

    Args:
        base_prompt: 基础提示
        context: 上下文数据

    Returns:
        添加了上下文的完整提示
    """
    context_json = json.dumps(context, ensure_ascii=False, indent=2)
    return f"{base_prompt}\n\nContext (JSON):\n{context_json}"