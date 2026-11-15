"""
The numbering-plan worker: `python -m modules.phone_worker`.

Reads one JSON request on stdin ({"phone": ..., "region": ...}) and writes one JSON answer on
stdout: {"result": {...}} with the offline facts, or {"bad_input": "..."} for text that is not
a phone number. Then it exits, and the library's tables (about 115 MB) go with it.

The number arrives on stdin, never on the command line. Nothing is logged or printed besides
the one answer.
"""

import json
import sys


def main() -> int:
    from modules import phone_plan
    try:
        req = json.loads(sys.stdin.read(4096))
        phone, region = str(req["phone"])[:64], str(req.get("region") or "US")[:2]
    except Exception:
        return 2
    try:
        answer = {"result": phone_plan.offline_facts(phone, region)}
    except phone_plan.PhoneInputError as e:
        answer = {"bad_input": str(e)}
    sys.stdout.write(json.dumps(answer))
    return 0


if __name__ == "__main__":
    sys.exit(main())
