#!/usr/bin/env sh
# configuration file
# configuration
BASEDIR=$(dirname "$0")
CFGFILE="$BASEDIR/../configs/mbear.yaml"

python3 -m monobear.checkpassword -c "$CFGFILE"
exec "$@"
