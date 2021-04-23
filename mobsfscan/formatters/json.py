# -*- coding: utf_8 -*-
"""JSON output format."""
import json


def json_output(outfile, scan_results, version):
    """JSON Output."""
    scan_results['mobsfscan_version'] = version
    jout = json.dumps(
        scan_results,
        sort_keys=True,
        indent=2,
        separators=(',', ': '))
    if outfile:
        with open(outfile, 'w') as of:
            of.write(jout)
    else:
        print(jout)
    return jout
