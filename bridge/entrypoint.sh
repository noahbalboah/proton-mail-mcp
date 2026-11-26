#!/bin/bash
# run  : serve IMAP to the internal network (default).
# login: one-time interactive setup. Run with the stack stopped:
#        docker compose run --rm -it bridge login
set -euo pipefail

case "${1:-run}" in
  login)
    if ! gpg --list-secret-keys pass-key >/dev/null 2>&1; then
      gpg --batch --generate-key /etc/bridge/gpgparams
      pass init pass-key
    fi
    # In the Bridge CLI: `login`, then `info` shows the IMAP username and the Bridge
    # password that go into the stack's .env (IMAP_USER, IMAP_PASSWORD). Then `exit`.
    exec /usr/lib/protonmail/bridge/bridge --cli
    ;;
  run)
    if ! gpg --list-secret-keys pass-key >/dev/null 2>&1; then
      echo "Bridge is not set up yet: run 'docker compose run --rm -it bridge login' first." >&2
      exit 1
    fi
    socat TCP-LISTEN:11143,fork,reuseaddr TCP:127.0.0.1:1143 &
    exec /usr/lib/protonmail/bridge/bridge --noninteractive
    ;;
  *)
    echo "usage: entrypoint.sh [run|login]" >&2
    exit 2
    ;;
esac
