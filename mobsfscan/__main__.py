#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""The MobSF SAST cli: mobsfscan."""
import argparse
import sys

from mobsfscan import __version__
from mobsfscan.mobsfscan import MobSFScan
from mobsfscan.formatters import (
    cli,
    json_fmt,
    sarif,
    sonarqube,
)


def handle_exit(results, exit_warn, no_fail):
    """Handle Exit."""
    if not results.get('results'):
        return

    if not no_fail:
        for meta in results.get('results').values():
            severity = meta['metadata']['severity']
            ewarn = severity == 'WARNING' and exit_warn
            if severity == 'ERROR' or ewarn:
                sys.exit(1)
    sys.exit(0)


def main():
    """Main CLI."""
    parser = argparse.ArgumentParser()
    parser.add_argument('path',
                        nargs='*',
                        help=('Path can be file(s) or '
                              'directories with source code'))
    parser.add_argument('--json',
                        help='set output format as JSON',
                        action='store_true')
    parser.add_argument('--sarif',
                        help='set output format as SARIF 2.1.0',
                        action='store_true')
    parser.add_argument('--sonarqube',
                        help='set output format compatible with SonarQube',
                        action='store_true')
    parser.add_argument('--html',
                        help='set output format as HTML',
                        action='store_true')
    parser.add_argument('--type',
                        help='optional: force android or ios rules explicitly',
                        choices=['android', 'ios', 'auto'],
                        default='auto')
    parser.add_argument('-o', '--output',
                        help='output filename to save the result',
                        required=False)
    parser.add_argument('-c', '--config',
                        help='location to .mobsf config file',
                        required=False)
    parser.add_argument('-w', '--exit-warning',
                        help='non zero exit code on warning',
                        action='store_true',
                        required=False)
    parser.add_argument('--no-fail',
                        help=(
                            'force zero exit code, '
                            'takes precedence over '
                            '--exit-warning'),
                        action='store_true',
                        required=False)
    parser.add_argument('-v', '--version',
                        help='show mobsfscan version',
                        required=False,
                        action='store_true')
    args = parser.parse_args()
    if args.path:
        is_json = args.json or args.sonarqube or args.sarif
        scan_results = MobSFScan(
            args.path,
            is_json,
            args.type,
            args.config,
        ).scan()
        if args.sonarqube:
            sonarqube.sonarqube_output(
                args.output,
                scan_results,
                __version__)
        elif args.json:
            json_fmt.json_output(
                args.output,
                scan_results,
                __version__)
        elif args.sarif:
            sarif.sarif_output(
                args.output,
                scan_results,
                __version__,
                args.path)
        elif args.html:
            cli.cli_output(
                args.output,
                scan_results,
                __version__,
                'unsafehtml')
        else:
            cli.cli_output(
                args.output,
                scan_results,
                __version__,
                'fancy_grid')
        handle_exit(
            scan_results,
            args.exit_warning,
            args.no_fail)

    elif args.version:
        cli.print_tool_info(__version__)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
