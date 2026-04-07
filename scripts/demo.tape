# Aegis Demo
# Record with: vhs scripts/demo.tape

Output docs/assets/demo.gif
Set Shell "bash"
Set FontSize 14
Set Width 920
Set Height 540
Set Padding 16
Set FontFamily "JetBrains Mono"
Set TypingSpeed 30ms
Set Theme { "name": "Aegis", "black": "#1e1e2e", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#cba6f7", "cyan": "#89dceb", "white": "#cdd6f4", "brightBlack": "#585b70", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#cba6f7", "brightCyan": "#89dceb", "brightWhite": "#cdd6f4", "background": "#1e1e2e", "foreground": "#cdd6f4", "cursor": "#f5e0dc", "selection": "#45475a" }

# Hidden setup: run scan, let output be the first visible frame
Hide
Type@0ms "source .venv/bin/activate && export FORCE_COLOR=1 && export PS1='$ '"
Enter
Sleep 1s
Type@0ms "clear && aegis scan examples/"
Enter
Sleep 8s
Show

# First visible frame = colorful scan results already on screen
Sleep 5s

# Scene 2: Guardrail demo
Type "clear"
Enter
Sleep 200ms
Type "python scripts/demo_script.py"
Enter
Sleep 18s

# CTA
Type "# pip install agent-aegis  |  github.com/acacian/aegis"
Enter
Sleep 3s
