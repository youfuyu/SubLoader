"""统一路径身份和运行文件冲突检查."""

from pathlib import Path
import unicodedata


WRITE_LOCK_NAME = ".subloader-write.lock"


def path_key(path: Path) -> str:
    # 保守拒绝仅大小写或 Unicode 正规形式不同的路径,避免 macOS 别名覆盖.
    return unicodedata.normalize("NFC", str(path.resolve())).casefold()


def check_file_paths(files: list[Path], directories: list[Path] = (),
                     protected: list[Path] = ()) -> None:
    keys = [path_key(p) for p in files]
    if len(keys) != len(set(keys)):
        raise ValueError("文件路径重复或存在大小写别名")
    protected_keys = {path_key(p) for p in protected}
    if set(keys) & protected_keys:
        raise ValueError("运行文件不能覆盖配置文件")
    directory_keys = [path_key(p) for p in directories]
    spellings = {}
    for path, key in zip(directories, directory_keys):
        spelling = str(path.resolve())
        if key in spellings and spellings[key] != spelling:
            raise ValueError("运行目录不能仅大小写或 Unicode 正规形式不同")
        spellings[key] = spelling
    for path, key in zip(files, keys):
        if path.is_dir() or key in directory_keys:
            raise ValueError("文件路径与目录冲突")
        if any(other.startswith(key + "/") for other in keys + directory_keys + list(protected_keys)):
            raise ValueError("文件路径不能用作其他文件的父目录")
    if any(p.exists() and not p.is_dir() for p in directories):
        raise ValueError("输出目录指向了已有文件")
