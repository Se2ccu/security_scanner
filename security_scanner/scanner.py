#!/usr/bin/env python3
"""
安全漏洞扫描器 - 主入口

多Agent串行执行:
Agent1: 代码架构与威胁分析
Agent2: 漏洞模式分析
Agent3: 漏洞挖掘与报告生成
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.agent1_arch import run_agent1
from agents.agent2_pattern import run_agent2
from agents.agent3_exploit import run_agent3
from output_format import ScanReport, Agent1Output, Agent2Output
from utils import save_json, load_json


def parse_args():
    parser = argparse.ArgumentParser(
        description="多Agent代码安全漏洞挖掘工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python scanner.py /path/to/code
  python scanner.py /path/to/code -o ./results
  python scanner.py /path/to/code -o /tmp/scan_results
  python scanner.py /path/to/code --agent1-name arch_agent --agent2-name pattern_agent --agent3-name exploit_agent
  python scanner.py /path/to/code -m anthropic/claude-3-5-sonnet
        """
    )
    parser.add_argument("code_path", help="要扫描的代码路径")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="输出目录路径 (默认: <code_path>/scan_results)"
    )
    parser.add_argument(
        "--agent1-name",
        default=None,
        help="Agent1使用的opencode agent名称"
    )
    parser.add_argument(
        "--agent2-name",
        default=None,
        help="Agent2使用的opencode agent名称"
    )
    parser.add_argument(
        "--agent3-name",
        default=None,
        help="Agent3使用的opencode agent名称"
    )
    parser.add_argument(
        "-m", "--model",
        default=None,
        help="指定使用的模型 (格式: provider/model)"
    )
    return parser.parse_args()


def ensure_output_dir(output_dir: str) -> Path:
    """确保输出目录存在"""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_scan(code_path: str, output_dir: str = None,
             agent1_name: str = None, agent2_name: str = None, agent3_name: str = None,
             model: str = None) -> ScanReport:
    """
    执行完整的安全扫描流程

    Args:
        code_path: 要扫描的代码路径
        output_dir: 输出目录（默认: <code_path>/scan_results）

    Args:
        code_path: 要扫描的代码路径
        output_dir: 输出目录
        agent1_name: Agent1使用的agent名称
        agent2_name: Agent2使用的agent名称
        agent3_name: Agent3使用的agent名称
        model: 指定使用的模型

    Returns:
        ScanReport: 完整的扫描报告
    """
    # 如果未指定输出目录，默认在代码目录下创建scan_results
    if output_dir is None:
        output_dir = str(Path(code_path).absolute() / "scan_results")
    else:
        # 确保输出目录是绝对路径
        output_dir = str(Path(output_dir).absolute())

    output_path = ensure_output_dir(output_dir)

    # Agent1 输出文件路径
    agent1_file = Path(output_dir) / "agent1_output.json"
    agent2_file = Path(output_dir) / "agent2_output.json"
    report_file = Path(output_dir) / "report.json"

    print(f"[*] 开始安全扫描...")
    print(f"[*] 代码路径: {code_path}")
    print(f"[*] 输出目录: {output_dir}")

    # Agent1: 代码架构与威胁分析
    print(f"\n[1/3] Agent1: 代码架构与威胁分析...")
    if agent1_name:
        print(f"    [*] 使用agent: {agent1_name}")
    agent1_data = run_agent1(code_path, str(agent1_file), agent_name=agent1_name, model=model)
    if agent1_data:
        modules_count = len(agent1_data.get("risky_modules", []))
        print(f"    ✓ Agent1 完成，发现 {modules_count} 个风险模块")
    else:
        print(f"    ✗ Agent1 失败，使用空结果继续")

    # Agent2: 漏洞模式分析（从 agent1_output.json 读取）
    print(f"\n[2/3] Agent2: 漏洞模式分析...")
    if agent2_name:
        print(f"    [*] 使用agent: {agent2_name}")
    # 从文件读取 agent1 结果
    agent1_data_from_file = load_json(str(agent1_file)) if agent1_file.exists() else {}
    agent2_data = run_agent2(code_path, agent1_data_from_file, str(agent2_file),
                             agent_name=agent2_name, model=model)
    if agent2_data:
        patterns_count = len(agent2_data.get("module_patterns", []))
        print(f"    ✓ Agent2 完成，分析 {patterns_count} 个模块模式")
    else:
        print(f"    ✗ Agent2 失败，使用空结果继续")

    # Agent3: 漏洞挖掘与报告生成（从 agent2_output.json 读取）
    print(f"\n[3/3] Agent3: 漏洞挖掘与报告生成...")
    if agent3_name:
        print(f"    [*] 使用agent: {agent3_name}")
    # 从文件读取 agent2 结果
    agent2_data_from_file = load_json(str(agent2_file)) if agent2_file.exists() else {}
    vulnerabilities_data = run_agent3(code_path, agent2_data_from_file, str(report_file),
                                       agent_name=agent3_name, model=model)
    if vulnerabilities_data:
        vulns_count = len(vulnerabilities_data.get("vulnerabilities", []))
        print(f"    ✓ Agent3 完成，发现 {vulns_count} 个漏洞")
    else:
        print(f"    ✗ Agent3 失败，使用空结果继续")

    # 构建最终报告
    report = ScanReport(
        code_path=code_path,
        scan_time=datetime.now().isoformat(),
        agent1_output=agent1_data_from_file if not agent1_data else agent1_data,
        agent2_output=agent2_data_from_file if not agent2_data else agent2_data,
        vulnerabilities=vulnerabilities_data.get("vulnerabilities", []) if vulnerabilities_data else []
    )

    # 保存最终报告
    final_report_path = Path(output_dir) / "report.json"
    save_json(report.to_dict(), str(final_report_path))

    print(f"\n{'='*50}")
    print(f"[✓] 扫描完成!")
    print(f"[✓] 报告已保存到: {final_report_path}")
    print(f"[✓] 共发现 {report.total_vulnerabilities} 个漏洞")

    return report


def main():
    args = parse_args()

    # 验证代码路径存在
    if not Path(args.code_path).exists():
        print(f"错误: 代码路径不存在: {args.code_path}", file=sys.stderr)
        sys.exit(1)

    try:
        report = run_scan(
            args.code_path, args.output,
            agent1_name=args.agent1_name,
            agent2_name=args.agent2_name,
            agent3_name=args.agent3_name,
            model=args.model
        )

        # 输出摘要
        print(f"\n漏洞摘要:")
        for vuln in report.vulnerabilities:
            print(f"  [{vuln['severity']}] {vuln['type']} - {vuln['file']}:{vuln.get('line', '?')}")

    except KeyboardInterrupt:
        print("\n\n[!] 扫描被用户中断", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] 扫描出错: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()