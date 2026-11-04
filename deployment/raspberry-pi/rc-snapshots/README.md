# Local release-candidate snapshots

Created by `../scripts/preserve_local_rc.sh`.

- `*.tar.gz` — working-tree archive (gitignored); restore if Pi deploy fails  
- `*-manifest.txt` — tag, HEAD, and `git status` at preserve time  

Tags are **local only** — do not `git push --tags` unless you explicitly decide to publish.
