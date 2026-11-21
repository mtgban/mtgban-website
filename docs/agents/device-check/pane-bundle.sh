#!/bin/bash
# Print pane-sweep.js with probe.js inlined, ready to paste into
# javascript_tool. Writes it to $1 too when given a path.
here=$(cd "$(dirname "$0")" && pwd)
bundle=$(python3 -I - "$here" <<'EOF'
import sys
here = sys.argv[1]
probe = open(f'{here}/probe.js').read()
runner = open(f'{here}/pane-sweep.js').read()
if '`' in probe or '${' in probe:
    raise SystemExit('probe.js must not use backticks or ${: it is pasted as String.raw')
print(runner.replace('__PROBE__', 'String.raw`' + probe.rstrip() + '`'))
EOF
)
[ -n "$1" ] && printf '%s\n' "$bundle" > "$1"
printf '%s\n' "$bundle"
