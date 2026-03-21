# VHS tape file for recording Aegis terminal demo
# Install: go install github.com/charmbracelet/vhs@latest
# Run: vhs examples/demo.tape
#
# Outputs: examples/demo.gif

Output examples/demo.gif

Set FontSize 16
Set Width 900
Set Height 600
Set Theme "Dracula"
Set Padding 20

Type "python examples/terminal_demo.py"
Enter
Sleep 15s
