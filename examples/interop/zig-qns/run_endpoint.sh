#!/bin/bash
set -euo pipefail

/setup.sh

ROLE=${ROLE:-server}
TESTCASE=${TESTCASE:-}

LOGDIR=/logs
mkdir -p "$LOGDIR"

if [ "$ROLE" = "client" ]; then
  # Wait for simulator ready
  /wait-for-it.sh sim:57832 -s -t 150 || echo "sim wait timeout"
  echo "Starting qns client for testcase=$TESTCASE" | tee -a $LOGDIR/qns.log
  exec qns-endpoint 2>&1 | tee -a $LOGDIR/client.log
else
  echo "Starting qns server for testcase=$TESTCASE" | tee -a $LOGDIR/qns.log
  exec qns-endpoint 2>&1 | tee -a $LOGDIR/server.log
fi
