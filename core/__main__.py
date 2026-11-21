"""SubLoader 命令行入口.

用法:
  run.sh                      立即执行一次(失败按配置自动重试)
  run.sh run --once           立即执行一次(不重试)
  run.sh rules                单独下载/更新分流规则(GitHub 镜像加速)
  run.sh login                从本地登录配置获取并保存 token
  可选 -c 配置路径;定时由 WorkBuddy agent 自动化触发
"""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import sys
from pathlib import Path

from .config import Config, LOG_BACKUPS, load_config

LOG_MAX_BYTES = 2 * 1024 * 1024


def setup_logging(cfg) -> None:
    log_path = cfg.log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, str(cfg.get("log", "level", "info")).upper(), logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
    file_handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(file_handler)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)


def _load(args) -> Config:
    try:
        cfg = load_config(Path(args.config) if args.config else None)
    except (OSError, ValueError) as exc:
        # TOML 错误可能含配置行内容,避免回显 token 或订阅地址.
        print("配置加载失败: %s" % type(exc).__name__, file=sys.stderr)
        sys.exit(2)
    errors = cfg.validate()
    if errors:
        for err in errors:
            print("配置错误: %s" % err, file=sys.stderr)
        sys.exit(2)
    try:
        setup_logging(cfg)
    except OSError as exc:
        print("日志初始化失败: %s" % type(exc).__name__, file=sys.stderr)
        sys.exit(1)
    return cfg


def cmd_run(args) -> int:
    from . import store
    from .runner import run_with_retry

    cfg = _load(args)
    log = logging.getLogger("core")
    log.info("========== 开始执行 ==========")
    attempts = 1 if args.once else None
    try:
        with store.run_lock(cfg.raw_file.parent / "subloader.lock"):
            return 0 if run_with_retry(cfg, attempts=attempts) else 1
    except store.BusyError:
        log.warning("另一实例正在执行,本次触发跳过")
        return 0
    except Exception:
        log.exception("执行失败")
        return 1


def cmd_rules(args) -> int:
    """单独下载/更新分流规则."""
    from . import rules as rules_mod, store

    cfg = _load(args)
    log = logging.getLogger("core")
    log.info("========== 更新分流规则 ==========")
    try:
        return 0 if rules_mod.download_all(cfg) else 1
    except store.BusyError:
        log.warning("另一实例正在更新规则,本次触发跳过")
        return 0
    except Exception:
        log.exception("分流规则更新失败")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="subloader", description="西部世界VPN 订阅下载与 Clash/QX 配置生成",
        epilog="账号密码登录：./run.sh login（帮助：./run.sh login --help）")
    parser.add_argument("-c", "--config", help="配置文件路径(默认 项目根/config.toml)")
    parser.add_argument("--once", action="store_true", help="不重试,只执行一次")
    sub = parser.add_subparsers(dest="command")
    p_run = sub.add_parser("run", help="立即执行一次")
    p_run.add_argument("--once", action="store_true", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    p_rules = sub.add_parser("rules", help="下载/更新分流规则")
    for child in (p_run, p_rules):
        child.add_argument("-c", "--config", default=argparse.SUPPRESS,
                           help="配置文件路径")
    args = parser.parse_args(argv)

    if args.command == "rules":
        return cmd_rules(args)
    # 无子命令时默认执行一次(带重试)
    args.once = getattr(args, "once", False)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
