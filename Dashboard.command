#!/bin/sh
cd -- "$(dirname -- "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  echo "Set up the Python environment first; see START_HERE.md."
  printf 'Press Enter to close. '
  read -r answer
  exit 1
fi
.venv/bin/python -m trustedge.dashboard "$@"
