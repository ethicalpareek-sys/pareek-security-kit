"""Command-line interface."""
from __future__ import annotations
import argparse, sys, time
from core import __version__, __codename__
from core.banner import Colors, show_banner, show_legal, show_menu, show_loader, typewriter
from core.config import load_config
from core.dependency_checker import print_report as doctor_report
from core.logger import setup_logger
from core.permissions import describe as env_describe
from core.validators import (
    ValidationError, validate_domain, validate_host, validate_port_range,
    validate_threads, validate_timeout, validate_url,
)

STUB_HINT = (f"  {Colors.yellow('⚠')}  {Colors.bold('This subcommand ships in a later phase.')}\n"
             f"     {Colors.dim('Phase 1-2 provided: CLI, validators, config, logger,')}\n"
             f"     {Colors.dim('rate limiter, output engine, dependency checker,')}\n"
             f"     {Colors.dim('3D gradient banner.')}")


def build_parser():
    p = argparse.ArgumentParser(
        prog="pareek",
        description=(f"PAREEK SECURITY KIT v{__version__} '{__codename__}' — "
                     "authorized security testing CLI.\n"
                     "Use only on systems you own or have written permission to test."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  pareek --doctor\n"
                "  pareek --menu\n"
                "  pareek --info example.com\n"
                "  pareek --dns example.com\n"
                "  pareek --ports 192.168.1.10 --range 1-1024\n"
                "  pareek --web https://example.com\n"
                "  pareek --tls example.com\n"),
    )
    p.add_argument("--version", action="version",
                   version=f"Pareek Security Kit {__version__} ({__codename__})")

    g = p.add_argument_group("global options")
    g.add_argument("--quiet", action="store_true")
    g.add_argument("--verbose", action="store_true")
    g.add_argument("--json", action="store_true")
    g.add_argument("--output", metavar="PATH")
    g.add_argument("--timeout", type=float, default=5.0)
    g.add_argument("--threads", type=int, default=50)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--yes", action="store_true")
    g.add_argument("--log-file", metavar="PATH")

    a = p.add_argument_group("actions")
    a.add_argument("--menu", action="store_true")
    a.add_argument("--doctor", action="store_true")
    a.add_argument("--info", metavar="TARGET")
    a.add_argument("--dns", metavar="TARGET")
    a.add_argument("--ports", metavar="TARGET")
    a.add_argument("--range", dest="port_range", metavar="SPEC")
    a.add_argument("--service-scan", metavar="TARGET")
    a.add_argument("--web", metavar="URL")
    a.add_argument("--tls", metavar="HOST")
    a.add_argument("--pcap", metavar="FILE")
    a.add_argument("--hash", metavar="FILE")
    a.add_argument("--report", metavar="FILE")
    return p


def _dispatch(args, log):
    if args.doctor:
        doctor_report()
        return 0

    if args.menu or len(sys.argv) == 1:
        show_banner()
        show_legal()
        show_menu()
        print(f"  {env_describe()}\n")
        return 0

    if args.info:
        t = validate_host(args.info)
        log.info("info target validated: %s", t)
        print(STUB_HINT); return 0
    if args.dns:
        t = validate_domain(args.dns)
        log.info("dns target validated: %s", t)
        print(STUB_HINT); return 0
    if args.ports:
        t = validate_host(args.ports)
        if args.port_range:
            ports = validate_port_range(args.port_range)
            log.info("ports target=%s count=%d", t, len(ports))
        print(STUB_HINT); return 0
    if args.service_scan:
        validate_host(args.service_scan); print(STUB_HINT); return 0
    if args.web:
        validate_url(args.web); print(STUB_HINT); return 0
    if args.tls:
        validate_host(args.tls); print(STUB_HINT); return 0
    if args.pcap or args.hash or args.report:
        print(STUB_HINT); return 0

    show_banner()
    show_legal()
    show_menu()
    print(f"  {env_describe()}\n")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    log = setup_logger(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)
    _ = load_config()

    try:
        validate_timeout(args.timeout); validate_threads(args.threads)
    except ValidationError as exc:
        print(f"{Colors.red('✗')} {exc}", file=sys.stderr); return 2

    try:
        return _dispatch(args, log)
    except ValidationError as exc:
        print(f"{Colors.red('✗ Validation:')} {exc}", file=sys.stderr); return 2
    except PermissionError as exc:
        print(f"{Colors.red('✗ Permission:')} {exc}", file=sys.stderr); return 3
    except FileNotFoundError as exc:
        print(f"{Colors.red('✗ File:')} {exc}", file=sys.stderr); return 4
    except Exception as exc:
        log.exception("Unhandled error")
        print(f"{Colors.red('✗ Unexpected:')} {exc}", file=sys.stderr); return 1
