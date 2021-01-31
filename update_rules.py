"""Download Latest Rules."""
# !/usr/bin/env python3
from io import BytesIO
from pathlib import Path
from hashlib import sha256

from requests import get


BASE_URL = (
    'https://raw.githubusercontent.com/MobSF/'
    'Mobile-Security-Framework-MobSF/master/mobsf/'
    'StaticAnalyzer/views/')
RULES_URL = {
    'android_rules.yaml': f'{BASE_URL}android/rules/android_rules.yaml',
    'objective_c_rules.yaml': f'{BASE_URL}ios/rules/objective_c_rules.yaml',
    'swift_rules.yaml': f'{BASE_URL}ios/rules/swift_rules.yaml',
}


def get_sha256(file_obj, obj=True):
    """SHA 256 of object or file."""
    fp = None
    blocksize = 65536
    hasher = sha256()
    if obj:
        buf = file_obj.read(blocksize)
        obj = file_obj
    else:
        fp = open(file_obj, 'rb')
        buf = fp.read(blocksize)
        obj = fp
    while buf:
        hasher.update(buf)
        buf = obj.read(blocksize)
    if fp:
        fp.close()
    return hasher.hexdigest()


def should_update(resp, local_file):
    """Check if update is needed."""
    if not local_file.exists():
        return True
    update = False
    in_mem = BytesIO(resp)
    if get_sha256(in_mem) != get_sha256(local_file.as_posix(), False):
        print(f'{local_file.stem} is outdated!')
        update = True
    else:
        print(f'{local_file.stem} is the latest!')
    in_mem.truncate(0)
    return update


def download_rule(url, rule_file):
    """Download Rules."""
    response = get(url, timeout=3)
    res = response.content
    update = should_update(res, rule_file)
    if not update:
        return
    rule_file.write_bytes(res)


def run():
    """Try update."""
    for name, url in RULES_URL.items():
        b = Path(__file__).parent
        rule_file = b / 'mobsfscan' / 'rules' / 'pattern_matcher' / name
        download_rule(url, rule_file)


if __name__ == '__main__':
    run()
