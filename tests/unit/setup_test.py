"""Test Setup."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan


def scanner(paths):
    return MobSFScan(paths, True).scan()


def get_paths():
    base_dir = Path(__file__).parents[1] / 'assets' / 'src'
    dot_file = base_dir / 'dot_mobsf'
    java = base_dir / 'java'
    kotlin = base_dir / 'kotlin'
    swift = base_dir / 'swift'
    objc = base_dir / 'objc'
    paths = {
        'dot_file': dot_file,
        'java': java,
        'kotlin': kotlin,
        'swift': swift,
        'objc': objc,
    }
    return paths
