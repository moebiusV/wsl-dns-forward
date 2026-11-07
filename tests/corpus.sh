#!/bin/sh
# SPDX-License-Identifier: ISC
# Replay the fuzz seed/regression corpus through the non-libFuzzer drivers.
# Under WMF_WRAP=valgrind this also checks for memory errors and leaks.
: "${REPLAY_DIR:=.}" "${CORPUS_DIR:=fuzz/corpus}"
rc=0
for t in query relay helper; do
    files=$(ls "$CORPUS_DIR/$t"/* 2>/dev/null) || continue
    if [ "$WMF_WRAP" = valgrind ]; then
        valgrind -q --error-exitcode=99 --leak-check=full "$REPLAY_DIR/replay_$t" $files || rc=1
    else
        "$REPLAY_DIR/replay_$t" $files || rc=1
    fi
done
[ $rc = 0 ] && echo "corpus: all inputs replayed cleanly"
exit $rc
