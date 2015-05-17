#!/usr/bin/env python

import sys

h = None

for line in open(sys.argv[1]):
    line = line.strip()

    if "hash" in line and "=>" in line:
        data = line.split("=>")
        h = data[1].strip(" '").rstrip(" ',")
        h = h.replace(":", "$")

    if "salt" in line and "=>" in line:
        data = line.split("=>")
        s = data[1].strip(" '").rstrip(" ',")
        print "$wonderful$%s$%s" % (s, h)
