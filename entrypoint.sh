#!/bin/sh

if [ ${#@} -lt 1 ]; then
  echo "usage: $0 <Days>"
  return 1
fi

days=$1

python3 /external-users/main.py

exit 0
