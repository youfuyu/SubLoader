#!/bin/bash
# SubLoader 启动器:使用项目内 uv 虚拟环境
# 用法: ./run.sh [run|rules] [-c 配置路径] [--once]
DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$DIR/.venv/bin/python"
# 保留调用方工作目录以解析相对 -c 路径,通过模块搜索路径定位 core.
export PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}"
if command -v uv >/dev/null 2>&1; then
  # 以 pyproject.toml 为准同步依赖(已同步时是秒级空操作)
  if ! (cd "$DIR" && uv sync --quiet --frozen --no-install-project); then
    echo "依赖同步失败,请检查 uv 输出后重试" >&2
    exit 1
  fi
fi
if [ ! -x "$PY" ]; then
  echo "虚拟环境不存在,且 uv 不可用或同步失败;请先: cd $DIR && uv venv && uv pip install pyyaml" >&2
  exit 1
fi
exec "$PY" -m core "$@"
