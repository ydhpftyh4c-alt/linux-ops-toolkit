from pathlib import Path
from zipfile import BadZipFile
import argparse
import json
import sys

from . import backup, health


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Linux diagnostics and verified file backups")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("health", help="Read-only disk, memory, systemd and TCP checks")
    check.add_argument("--path", type=Path, default=Path("."))
    check.add_argument("--warning", type=float, default=85)
    check.add_argument("--critical", type=float, default=95)
    check.add_argument("--skip-memory", action="store_true")
    check.add_argument("--service", action="append", default=[])
    check.add_argument("--tcp", nargs=2, action="append", default=[], metavar=("HOST", "PORT"))
    check.add_argument("--json", action="store_true", dest="as_json")
    check.add_argument("--output", type=Path)
    archive = commands.add_parser("backup", help="Create, verify or restore a content backup")
    actions = archive.add_subparsers(dest="action", required=True)
    for action in ["create", "verify", "restore"]:
        sub = actions.add_parser(action)
        sub.add_argument("source", type=Path)
        if action != "verify":
            sub.add_argument("destination", type=Path)
        sub.add_argument("--max-bytes", type=int, default=backup.MAX_BYTES)
    args = parser.parse_args(argv)
    try:
        if args.command == "health":
            health.usage_status(0, args.warning, args.critical)
            checks = [health.disk_check(args.path, args.warning, args.critical)]
            if not args.skip_memory:
                checks.append(health.memory_check(warning=args.warning, critical=args.critical))
            checks += [health.service_check(unit) for unit in args.service]
            checks += [health.tcp_check(host, int(port)) for host, port in args.tcp]
            result = health.report(checks)
            if args.output:
                health.write_report(args.output, result)
            if args.as_json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                for item in checks:
                    print(f"{item.status:8} {item.name}: {item.message}")
            return result["exit_code"]
        if args.max_bytes <= 0:
            raise ValueError("--max-bytes must be positive")
        if args.action == "create":
            count = backup.create(args.source, args.destination, args.max_bytes)
        elif args.action == "restore":
            count = backup.restore(args.source, args.destination, args.max_bytes)
        else:
            count = backup.verify(args.source, args.max_bytes)
        print(json.dumps({"action": args.action, "files": count, "status": "ok"}))
        return 0
    except (OSError, ValueError, KeyError, BadZipFile, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
