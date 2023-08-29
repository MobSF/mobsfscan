"""Setup for mobsfscan."""
from setuptools import (
    find_packages,
    setup,
)

from pathlib import Path


def read(rel_path):
    init = Path(__file__).resolve().parent / rel_path
    return init.read_text('utf-8', 'ignore')


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            return line.split('\'')[1]
    raise RuntimeError('Unable to find version string.')


description = ('mobsfscan is a static analysis tool that can'
               ' find insecure code patterns in your Android and'
               ' iOS source code. Supports Java, Kotlin,'
               ' Swift, and Objective C Code.')
setup(
    name='mobsfscan',
    version=get_version('mobsfscan/__init__.py'),
    description=description,
    author='Ajin Abraham',
    author_email='ajin25@gmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        ('License :: OSI Approved :: GNU Lesser '
         'General Public License v3 or later (LGPLv3+)'),
        'Programming Language :: Python :: 3.7',
    ],
    packages=find_packages(include=[
        'mobsfscan', 'mobsfscan.*',
    ]),
    entry_points={
        'console_scripts': [
            'mobsfscan = mobsfscan.__main__:main',
        ],
    },
    include_package_data=True,
    url='https://github.com/MobSF/mobsfscan',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    install_requires=[
        'colorama>=0.4.5',
        'libsast>=1.5.3',
        'sarif-om>=1.0.4',
        'jschema-to-python>=1.2.3',
        'tabulate>=0.8.10',
        'xmltodict>=0.13.0',
    ],
)
