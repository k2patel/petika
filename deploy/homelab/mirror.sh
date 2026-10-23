#!/bin/sh
# The sidecar mounts only ciphertext Git history, never account or grant data.
set -eu
export HOME=/tmp
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/scripts/askpass.sh
while :; do
  # UI-managed transfers take over after the first settings save.
  if [ -f /mirror/ui-managed ]; then sleep 60; continue; fi
  failed=0
  for repository in /mirror/repository.git /mirror/*/repository.git; do
    [ -f /mirror/ui-managed ] && break
    [ -f "$repository/HEAD" ] || continue
    collection=$(basename "$(dirname "$repository")")
    if [ "$collection" = mirror ]; then
      branch=legacy
    else
      case "$collection" in *[!0-9a-f]*|'') echo 'Invalid collection directory'; failed=1; continue;; esac
      [ "${#collection}" = 64 ] || { failed=1; continue; }
      branch="collections/$collection"
    fi
    git --git-dir="$repository" rev-parse --verify HEAD >/dev/null 2>&1 || continue
    # Fast-forward only: never discard remote history after a local rollback.
    if git --git-dir="$repository" -c safe.directory="$repository" push "$PETIKA_BACKUP_URL" "HEAD:refs/heads/$branch"; then
      echo "Replicated $branch"
    else
      echo "Replication failed for $branch; retrying next interval" >&2
      failed=1
    fi
  done
  if [ "$failed" = 0 ]; then date -u +%FT%TZ > /tmp/last-success; fi
  sleep 60
done
