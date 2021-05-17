# -*- coding: utf_8 -*-
"""CLI mobsfscan output format."""
from tabulate import tabulate

from html import escape

from mobsfscan.logger import init_logger

logger = init_logger(__name__)
UNSAFE_HTML = 'unsafehtml'


def _escape(data, fmt):
    """Escape HTML unsafe data."""
    if fmt == UNSAFE_HTML:
        return escape(data)
    return data


def print_tool_info(ver):
    """Tool info."""
    tool_str = '\nmobsfscan: v{} | Ajin Abraham | opensecurity.in'.format(ver)
    logger.info(tool_str)
    return tool_str


def format_table(rule_id, details, fmt):
    """Get CLI friendly format."""
    items = []
    items.append(['RULE ID', rule_id])
    for meta, value in details['metadata'].items():
        if meta == 'id':
            continue
        meta_format = meta.upper().replace('_', '')
        items.append([meta_format, value])
    # Get files
    fstore = []
    files = details.get('files')
    if files:
        for match in files:
            file_path = match['file_path']
            fstore.append(['File', _escape(file_path, fmt)])
            position = match['match_position']
            pos = f'{position[0]} - {position[1]}'
            fstore.append(['Match Position', pos])
            lines = match.get('match_lines')
            line = (lines[0] if lines[0] == lines[1]
                    else f'{lines[0]}: {lines[1]}')
            fstore.append(['Line Number(s)', line])
            match_string = match['match_string']
            if isinstance(match_string, list):
                match_string = '\n'.join(ln.strip() for ln in match_string)
            if fmt == UNSAFE_HTML:
                match_string = f'<pre>{_escape(match_string, fmt)}</pre>'
            fstore.append(['Match String', match_string])
        if fstore:
            files_tbl = tabulate(fstore, tablefmt=fmt)
            items.append(['FILES', files_tbl])
    return tabulate(items, tablefmt=fmt)


def cli_output(outfile, scan_results, version, fmt):
    """Format output printing."""
    tool = print_tool_info(version)
    if not scan_results['results']:
        logger.info('No issues found.')
        return []
    scan_results.pop('errors', None)
    buffer = []
    for out in scan_results:
        for rule_id, details in scan_results[out].items():
            formatted = format_table(rule_id, details, fmt)
            buffer.append(formatted)
            severity = details['metadata']['severity'].lower()
            if not outfile:
                if severity == 'error':
                    logger.error(formatted)
                elif severity == 'warning':
                    logger.warning(formatted)
                else:
                    logger.info(formatted)
    if outfile and buffer:
        buffer.insert(0, tool)
        outdata = '\n'.join(buffer)
        with open(outfile, 'w') as of:
            of.write(outdata)
    return buffer
