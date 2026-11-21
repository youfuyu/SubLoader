"""文件落盘:原始文件保存、原子覆盖、备份、运行锁."""

from __future__ import annotations

import datetime
import fcntl
import json
import logging
import os
import tempfile
from contextlib import contextmanager, ExitStack
from pathlib import Path

from .paths import WRITE_LOCK_NAME, check_file_paths, path_key

log = logging.getLogger("core.store")


class BusyError(Exception):
    """另一实例正在执行."""


@contextmanager
def run_lock(lock_path: Path):
    """非阻塞运行锁(flock):防止定时触发与手动执行并发写文件.

    进程退出(含崩溃)锁自动释放,无需陈锁清理.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+")
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BusyError("另一实例正在执行")
        fh.seek(0)
        fh.truncate()
        fh.write(str(os.getpid()))
        fh.flush()
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def _atomic_write(path: Path, content: str, backup: bool = True) -> None:
    """先复制备份,再原子替换;任何准备失败均不移动旧文件."""
    _write_many([(path, content, backup)])


def _stage(path: Path, content: bytes, suffix: str, pending: set[Path]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # 唯一临时文件避免并发覆盖;节点密码文件仅当前用户可读写.
    with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".%s." % path.name, suffix=suffix,
            delete=False) as fh:
        tmp = Path(fh.name)
        pending.add(tmp)
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    return tmp


def _write_many(files: list[tuple[Path, str, bool]]) -> None:
    # 按实际写入目录加锁:不同配置共享任何输出目录时也不能交叉提交.
    parents = {path_key(path.parent): path.parent for path, _, _ in files}
    check_file_paths([path for path, _, _ in files]
                     + [p.with_suffix(p.suffix + ".bak") for p, _, backup in files if backup]
                     + [p / WRITE_LOCK_NAME for p in parents.values()],
                     [p.parent for p, _, _ in files])
    with ExitStack() as locks:
        for key in sorted(parents):
            locks.enter_context(run_lock(parents[key] / WRITE_LOCK_NAME))
        _write_many_locked(files)


def _write_many_locked(files: list[tuple[Path, str, bool]]) -> None:
    """准备所有文件及回滚副本后提交;可捕获的写入异常会回滚已替换文件.

    多路径替换不是跨文件的原子事务,不保证断电/强制终止时的版本一致性.
    回滚本身失败时保留恢复副本并明确报告其位置.
    """
    paths = [path for path, _, _ in files]
    backups = [path.with_suffix(path.suffix + ".bak")
               for path, _, backup in files if backup]
    check_file_paths(paths + backups)
    pending: set[Path] = set()
    prepared = []
    committed = []
    try:
        for path, content, backup in files:
            tmp = _stage(path, content.encode("utf-8"), ".tmp", pending)
            old = _stage(path, path.read_bytes(), ".rollback", pending) if path.exists() else None
            bak_tmp = None
            if backup and old is not None:
                bak_tmp = _stage(path, old.read_bytes(), ".backup", pending)
            prepared.append((path, tmp, old, bak_tmp))

        # 备份失败即中止,正式文件仍然保留在原位置.
        for path, _, _, bak_tmp in prepared:
            if bak_tmp is not None:
                os.replace(bak_tmp, path.with_suffix(path.suffix + ".bak"))
        for path, tmp, old, _ in prepared:
            os.replace(tmp, path)
            committed.append((path, old))
    except BaseException:
        for path, old in reversed(committed):
            try:
                if old is None:
                    path.unlink(missing_ok=True)
                else:
                    os.replace(old, path)
            except OSError:
                if old is not None:
                    pending.discard(old)
                log.exception("回滚 %s 失败,恢复副本: %s", path, old)
        raise
    finally:
        for tmp in pending:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                log.warning("无法清理临时文件 %s", tmp)
    for path, content, _ in files:
        log.info("已写入 %s (%d 字节)", path, len(content.encode("utf-8")))


def _raw_text(payload: dict, account: dict | None) -> str:
    meta = {
        "fetched_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "account": account,
        "response": payload,
    }
    return json.dumps(meta, ensure_ascii=False, indent=2)


def save_raw(cfg, payload: dict, account: dict | None) -> Path:
    """保存带抓取时间和账户元信息的原始响应."""
    if cfg.validate():
        raise ValueError("配置无效,拒绝写入")
    target = cfg.raw_file
    _atomic_write(target, _raw_text(payload, account), backup=True)
    return target


def save_outputs(cfg, clash_text: str, qx_text: str) -> None:
    """依次原子替换两种订阅,写入异常时回滚已替换文件."""
    if cfg.validate():
        raise ValueError("配置无效,拒绝写入")
    backup = bool(cfg.get("output", "backup_old", True))
    _write_many([(cfg.clash_path, clash_text, backup),
                 (cfg.quantumultx_path, qx_text, backup)])


def save_bundle(cfg, payload: dict, account: dict | None,
                clash_text: str, qx_text: str) -> None:
    """自检成功后一起保存原始响应和两种订阅,写入异常时回滚."""
    if cfg.validate():
        raise ValueError("配置无效,拒绝写入")
    backup = bool(cfg.get("output", "backup_old", True))
    _write_many([(cfg.raw_file, _raw_text(payload, account), True),
                 (cfg.clash_path, clash_text, backup),
                 (cfg.quantumultx_path, qx_text, backup)])
