#!/bin/bash
# block-suspicious-files.sh — Block draft/temp/secret files from being committed
# Used by pre-commit framework

BLOCKED=""

for file in "$@"; do
    basename=$(basename "$file")
    dirname=$(dirname "$file")

    # Root-level files starting with _ (like _crewai_4877_comment.md)
    if [ "$dirname" = "." ] && echo "$basename" | grep -qE '^_'; then
        BLOCKED="$BLOCKED\n  $file (root-level underscore file)"
    fi

    # Draft/temp/backup files anywhere
    if echo "$basename" | grep -qEi '\.(draft|tmp|bak|temp|scratch)(\.|$)'; then
        BLOCKED="$BLOCKED\n  $file (draft/temp/backup file)"
    fi

    # Common scratch patterns in root
    if [ "$dirname" = "." ] && echo "$basename" | grep -qEi '^(notes_|scratch_|TODO_|draft_|temp_)'; then
        BLOCKED="$BLOCKED\n  $file (scratch/draft file)"
    fi

    # Secrets / credentials (extra safety net)
    if echo "$basename" | grep -qEi '(\.env$|credentials\.json|secret|\.pem$|\.key$)'; then
        if ! echo "$basename" | grep -qEi '\.example$'; then
            BLOCKED="$BLOCKED\n  $file (possible secret/credential)"
        fi
    fi
done

if [ -n "$BLOCKED" ]; then
    printf "\033[0;31m[pre-commit] Blocked suspicious files:\033[0m\n"
    printf "$BLOCKED\n"
    exit 1
fi

exit 0
