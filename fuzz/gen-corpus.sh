#!/bin/sh
# Writes the seed corpora into $1 (default fuzz/corpus): one file per seed, named by what it is. Seeds come
# from tests/host-scenarios.txt and from the verbs of the protocol, never from a network capture.
set -eu
out=${1:-fuzz/corpus}
scen=tests/host-scenarios.txt

for h in protocol dispatch scenario statepaths; do
    rm -rf "$out/$h"
    mkdir -p "$out/$h"
done

# every command of the scenario file, with its $NAMEs given a value
n=0
sed -e 's/^@[^ ]* //' -e 's/ *=>.*$//' -e '/^#/d' -e '/^$/d' \
    -e 's#\$URI#http://example.org/plugin#g' -e 's#\$BAD_URI#urn:no:such:plugin#g' \
    -e 's#\$PARAM#gain#g' -e 's#\$DIR#/tmp/state#g' -e 's#\$PORT_A#system:capture_1#g' \
    -e 's#\$PORT_B#system:playback_1#g' "$scen" | sort -u | while IFS= read -r cmd; do
    n=$((n + 1))
    printf '%s' "$cmd" > "$out/protocol/scenario-$n"
    printf '\001%s' "$cmd" > "$out/dispatch/scenario-$n"
done

# the verbs the scenario file does not carry, and the shapes a parser has to refuse
i=0
while IFS= read -r cmd; do
    i=$((i + 1))
    printf '%s' "$cmd" > "$out/protocol/extra-$i"
    printf '\002%s' "$cmd" > "$out/dispatch/extra-$i"
done <<'SEEDS'
cpu_load
quit
monitor_output 3 gain
track_info 3 "Lead Vocal" #FF8800 bus
track_info 3 x - master
remote_pages 3
remote_page_get 3 0
param_info 3 cutoff
connect system:capture_1 system:playback_1
disconnect system:capture_1 system:playback_1
param_set 3 gain
param_set 3 gain 1 2
add
add urn:x
remove
remove 3 4
unknown_verb 1 2 3
patch_set 3 urn:p "a b c"
state_save
%i %s %f
param_get 99999999999999999999 gain
param_set -1 gain nan
SEEDS

# a verb whose reply carries a value, with a salt that makes the backend succeed
printf '\006param_get 3 gain' > "$out/dispatch/param-get"

# the scenario file reader: the real file, and its edges
cp "$scen" "$out/scenario/host-scenarios"
printf 'add $URI 3 => resp 3\n@state_save remove 3 => resp 0\n' > "$out/scenario/guarded"
printf 'no arrow here\n' > "$out/scenario/no-arrow"
printf '@guard_only => x\n' > "$out/scenario/guard-no-command"
printf 'cmd $URI $UNKNOWN $EMPTY => $PORT_A | resp 0\n' > "$out/scenario/vars"
printf '# comment\n\n   \n' > "$out/scenario/blank"
printf 'a => b\n\000' > "$out/scenario/nul"

# the state paths: an instance number and a request path
seed() { printf "$1" > "$out/statepaths/$2"; }
seed '\003\000\000\000.' dot
seed '\003\000\000\000plugin/state.ttl' nested
seed '\377\377\377\377a/b/c/d' negative
seed '\000\000\000\000/absolute' absolute
seed '\003\000\000\000a//b' double-slash
seed '\003\000\000\000..' dotdot
seed '\003\000\000\000../../etc/passwd' traversal
seed '\003\000\000\000..x/y' dots
