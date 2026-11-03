import io
import sys

from shield.modules.pulse.monitor import main

if isinstance(sys.stdout, io.TextIOWrapper):
    sys.stdout.reconfigure(encoding="utf-8")

main()
