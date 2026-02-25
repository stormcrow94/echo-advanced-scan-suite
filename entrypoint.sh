#!/bin/sh
if [ "$1" = "serve" ] || [ "$1" = "--serve" ]; then
  exec /app/api-server
else
  exec /app/recon.sh "$@"
fi
