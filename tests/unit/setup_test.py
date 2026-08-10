"""Test Setup."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan


def scanner(paths):
    return MobSFScan(paths, True).scan()


def get_paths():
    base_dir = Path(__file__).parents[1] / 'assets' / 'src'
    android_layout = base_dir / 'android_layout'
    dot_file = base_dir / 'dot_mobsf'
    android_new_rules = base_dir / 'android_new_rules'
    java = base_dir / 'java'
    kotlin = base_dir / 'kotlin'
    swift = base_dir / 'swift'
    objc = base_dir / 'objc'
    xmlp = base_dir / 'xml'
    paths = {
        'android_layout': android_layout,
        'android_new_rules': android_new_rules,
        'dot_file': dot_file,
        'java': java,
        'kotlin': kotlin,
        'swift': swift,
        'objc': objc,
        'xml': xmlp,
    }
    return paths
