#!/usr/bin/env bash
# Demo session for asciinema recording.
# Usage:
#   asciinema rec demo.cast --cols 100 --rows 65 --command "bash scripts/demo-session.sh"
#   # Convert v3→v2 timestamps, then:
#   svg-term --in demo-v2.cast --out docs/assets/demo.svg --window --no-cursor --width 100 --height 65
#   agg demo-v2.cast docs/assets/demo.gif --theme dracula --font-size 14
set -e
cd "$(dirname "$0")/.."
source .venv/bin/activate
export FORCE_COLOR=1
export PS1='$ '

# Simulate typing for the command
type_cmd() {
    local cmd="$1"
    local delay="${2:-0.08}"
    printf '$ '
    for (( i=0; i<${#cmd}; i++ )); do
        printf '%s' "${cmd:$i:1}"
        sleep "$delay"
    done
    echo
}

clear
sleep 0.5

# Scene 1: Scan — command types out, results slam on screen
type_cmd "aegis scan examples/"
sleep 0.3
FORCE_COLOR=1 aegis scan examples/ 2>&1 | sed "s|$(pwd)/||g" || true
sleep 6

# Scene 2: Guardrail demo
clear
sleep 0.3
type_cmd "python scripts/demo_script.py"
sleep 0.3
FORCE_COLOR=1 python scripts/demo_script.py
sleep 6
