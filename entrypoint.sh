#!/bin/sh
# "serve" / "--serve" -> API REST; qualquer outro argumento -> recon.sh
if [ "${1:-}" = "serve" ] || [ "${1:-}" = "--serve" ]; then
  exec /app/api-server
fi
exec /app/recon.sh "$@"
