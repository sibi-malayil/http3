#!/usr/bin/env python3

with open('/home/sibi/http3/src/http3/webtransport.rs', 'r') as f:
    lines = f.readlines()

brace_count = 0
for i, line in enumerate(lines, 1):
    open_braces = line.count('{')
    close_braces = line.count('}')
    brace_count += open_braces - close_braces
    if brace_count < 0:
        print(f"Extra closing brace at line {i}: {line.strip()}")
        break

if brace_count != 0:
    print(f"Final brace count: {brace_count}")