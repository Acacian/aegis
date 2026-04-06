# Aegis Demo — Runtime Security for AI Agents
# Record with: vhs scripts/demo.tape
# Requires: vhs (charmbracelet/vhs), python3, agent-aegis installed
#
# Output: demo.gif (for README / HN launch)

# ---------------------------------------------------------------------------
# Terminal settings
# ---------------------------------------------------------------------------

Output demo.gif
Set Shell bash
Set FontSize 16
Set Width 960
Set Height 600
Set Padding 20
Set FontFamily "JetBrains Mono"
Set TypingSpeed 40ms
Set Theme { "name": "Aegis", "black": "#1e1e2e", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#cba6f7", "cyan": "#89dceb", "white": "#cdd6f4", "brightBlack": "#585b70", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#cba6f7", "brightCyan": "#89dceb", "brightWhite": "#cdd6f4", "background": "#1e1e2e", "foreground": "#cdd6f4", "cursor": "#f5e0dc", "selection": "#45475a" }

# ---------------------------------------------------------------------------
# Scene 1: Title + Install
# ---------------------------------------------------------------------------

Sleep 1s

Type "# Aegis -- Runtime Security for AI Agents"
Enter
Sleep 500ms

Type "# Zero-code guardrails for LLM apps: injection, PII, toxicity"
Enter
Sleep 1s

Type "pip install agent-aegis"
Enter
Sleep 2s

# Simulate pip output
Type "# Successfully installed agent-aegis-0.9.1"
Enter
Sleep 1.5s

# ---------------------------------------------------------------------------
# Scene 2: Show the demo script
# ---------------------------------------------------------------------------

Type "cat scripts/demo_script.py | head -20"
Enter
Sleep 2s

# ---------------------------------------------------------------------------
# Scene 3: Run the guardrail demo
# ---------------------------------------------------------------------------

Type "clear"
Enter
Sleep 500ms

Type "# Let's see Aegis detect a prompt injection attack in real-time"
Enter
Sleep 1s

Type "python scripts/demo_script.py"
Enter

# Wait for the script to complete (it has internal pauses)
Sleep 12s

# ---------------------------------------------------------------------------
# Scene 4: Static scanner
# ---------------------------------------------------------------------------

Type@50ms "clear"
Enter
Sleep 500ms

Type "# Aegis can also scan your codebase for ungoverned AI calls"
Enter
Sleep 1s

Type "python -m aegis scan examples/"
Enter
Sleep 4s

# ---------------------------------------------------------------------------
# Scene 5: Closing
# ---------------------------------------------------------------------------

Sleep 2s

Type "# github.com/acacian/aegis  |  pip install agent-aegis"
Enter
Sleep 3s
