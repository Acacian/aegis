# Aegis Demo — Find ungoverned AI calls. Fix them in one line.
# Record with: vhs scripts/demo.tape
# Requires: vhs (charmbracelet/vhs), agent-aegis installed in venv

Output docs/assets/demo.gif
Set Shell bash
Set FontSize 15
Set Width 880
Set Height 520
Set Padding 16
Set FontFamily "JetBrains Mono"
Set TypingSpeed 30ms
Set Theme { "name": "Aegis", "black": "#1e1e2e", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#cba6f7", "cyan": "#89dceb", "white": "#cdd6f4", "brightBlack": "#585b70", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#cba6f7", "brightCyan": "#89dceb", "brightWhite": "#cdd6f4", "background": "#1e1e2e", "foreground": "#cdd6f4", "cursor": "#f5e0dc", "selection": "#45475a" }

# Activate venv for scan command
Hide
Type "source .venv/bin/activate"
Enter
Sleep 500ms
Show

Sleep 1s

# Scene 1: Scan a codebase
Type "aegis scan examples/"
Enter
Sleep 4s

# Pause to let viewer read
Sleep 5s

# Scene 2: Fix it
Type "clear"
Enter
Sleep 500ms

Type "# Fix: add one line to your code"
Enter
Sleep 1s

Type 'python -c "import aegis; aegis.auto_instrument(); print('"'"'aegis: instrumented'"'"')"'
Enter
Sleep 3s

# Scene 3: Re-scan
Sleep 1s
Type "# github.com/acacian/aegis  |  pip install agent-aegis"
Enter
Sleep 3s
