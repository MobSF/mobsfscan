# mobsfscan
**mobsfscan** is a static analysis tool that can find insecure code patterns in your Android and iOS source code. Supports Java, Kotlin, Android XML, Swift and Objective C Code. mobsfscan uses [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) static analysis rules and is powered by [semgrep](https://github.com/returntocorp/semgrep) and [libsast](https://github.com/ajinabraham/libsast) pattern matcher.

Made with ![Love](https://cloud.githubusercontent.com/assets/4301109/16754758/82e3a63c-4813-11e6-9430-6015d98aeaab.png) in India  [![Tweet](https://img.shields.io/twitter/url?url=https://github.com/MobSF/mobsfscan)](https://twitter.com/intent/tweet/?text=mobsfscan%20is%20a%20static%20analysis%20tool%20that%20can%20find%20insecure%20code%20patterns%20in%20your%20Android%20and%20iOS%20source%20code.%20Supports%20Java,%20Kotlin,%20Swift,%20and%20Objective%20C%20Code.%20by%20%40ajinabraham%20%40OpenSecurity_IN&url=https://github.com/MobSF/mobsfscan)

[![PyPI version](https://badge.fury.io/py/mobsfscan.svg)](https://badge.fury.io/py/mobsfscan)
[![License](https://img.shields.io/:license-lgpl3.0+-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0.en.html)
[![python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux-green.svg)](https://github.com/MobSF/mobsfscan/)
[![Build](https://github.com/MobSF/mobsfscan/workflows/Build/badge.svg)](https://github.com/MobSF/mobsfscan/actions?query=workflow%3ABuild)

### Support mobsfscan

[![Donate to MobSF](https://user-images.githubusercontent.com/4301109/117404264-7aab5480-aebe-11eb-9cbd-da82d7346bb3.png)](https://opensecurity.in/donate)

If you liked mobsfscan and find it useful, please consider donating.

## e-Learning Courses & Certifications
![MobSF Course](https://user-images.githubusercontent.com/4301109/76344880-ad68b580-62d8-11ea-8cde-9e3475fc92f6.png) [Automated Mobile Application Security Assessment with MobSF -MAS](https://opsecx.com/index.php/product/automated-mobile-application-security-assessment-with-mobsf/)

![Android Security Tools Course](https://user-images.githubusercontent.com/4301109/76344939-c709fd00-62d8-11ea-8208-774f1d5a7c52.png) [Android Security Tools Expert -ATX](https://opsecx.com/index.php/product/android-security-tools-expert-atx/)


## Installation

`pip install mobsfscan`

Requires Python 3.7+

## Command Line Options

```bash
$ mobsfscan
usage: mobsfscan [-h] [--json] [--sarif] [--sonarqube] [--html] [--type {android,ios,auto}] [-o OUTPUT] [-c CONFIG] [-w] [--no-fail] [-v] [path ...]

positional arguments:
  path                  Path can be file(s) or directories with source code

optional arguments:
  -h, --help            show this help message and exit
  --json                set output format as JSON
  --sarif               set output format as SARIF 2.1.0
  --sonarqube           set output format compatible with SonarQube
  --html                set output format as HTML
  --type {android,ios,auto}
                        optional: force android or ios rules explicitly
  -o OUTPUT, --output OUTPUT
                        output filename to save the result
  -c CONFIG, --config CONFIG
                        location to .mobsf config file
  -w, --exit-warning    non zero exit code on warning
  --no-fail             force zero exit code, takes precedence over --exit-warning
  -v, --version         show mobsfscan version
```


## Example Usage

```bash
$ mobsfscan tests/assets/src/
- Pattern Match ████████████████████████████████████████████████████████████ 3
- Semantic Grep ██████ 37

mobsfscan: v0.3.0 | Ajin Abraham | opensecurity.in
╒══════════════╤════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╕
│ RULE ID      │ android_webview_ignore_ssl                                                                                                                             │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ DESCRIPTION  │ Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MITM attacks │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ TYPE         │ RegexAnd                                                                                                                                               │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ PATTERN      │ ['onReceivedSslError\\(WebView', '\\.proceed\\(\\);']                                                                                                  │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ SEVERITY     │ ERROR                                                                                                                                                   │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ INPUTCASE    │ exact                                                                                                                                                  │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ CVSS         │ 7.4                                                                                                                                                    │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ CWE          │ CWE-295 Improper Certificate Validation                                                                                                                │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ OWASP-MOBILE │ M3: Insecure Communication                                                                                                                             │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ MASVS        │ MSTG-NETWORK-3                                                                                                                                         │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ REF          │ https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification                │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ FILES        │ ╒════════════════╤═════════════════════════════════════════════════════════════════════════════════════════════╕                                       │
│              │ │ File           │ ../test_files/android_src/app/src/main/java/opensecurity/webviewignoressl/MainActivity.java │                                       │
│              │ ├────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤                                       │
│              │ │ Match Position │ 1480 - 1491                                                                                 │                                       │
│              │ ├────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤                                       │
│              │ │ Line Number(s) │ 50                                                                                          │                                       │
│              │ ├────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤                                       │
│              │ │ Match String   │ .proceed();                                                                                 │                                       │
│              │ ├────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤                                       │
│              │ │ File           │ ../test_files/android_src/app/src/main/java/opensecurity/webviewignoressl/MainActivity.java │                                       │
│              │ ├────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤                                       │
│              │ │ Match Position │ 1331 - 1357                                                                                 │                                       │
│              │ ├────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤                                       │
│              │ │ Line Number(s) │ 46                                                                                          │                                       │
│              │ ├────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤                                       │
│              │ │ Match String   │ onReceivedSslError(WebView                                                                  │                                       │
│              │ ╘════════════════╧═════════════════════════════════════════════════════════════════════════════════════════════╛                                       │
╘══════════════╧════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╛
```

## Python API

```python
>>> from mobsfscan.mobsfscan import MobSFScan
>>> src = 'tests/assets/src/java/java_vuln.java'
>>> scanner = MobSFScan([src], json=True)
>>> scanner.scan()
{
    'results': {
        'android_logging': {
            'files': [{
                'file_path': 'tests/assets/src/java/java_vuln.java',
                'match_position': (13, 73),
                'match_lines': (19, 19),
                'match_string': '            Log.d("htbridge", "getAllRecords(): " + records.toString());'
            }],
            'metadata': {
                'cwe': 'CWE-532 Insertion of Sensitive Information into Log File',
                'owasp-mobile': 'M1: Improper Platform Usage',
                'masvs': 'MSTG-STORAGE-3',
                'reference': 'https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs',
                'description': 'The App logs information. Please ensure that sensitive information is never logged.',
                'severity': 'INFO'
            }
        },
        'android_certificate_pinning': {
            'metadata': {
                'cwe': 'CWE-295 Improper Certificate Validation',
                'owasp-mobile': 'M3: Insecure Communication',
                'masvs': 'MSTG-NETWORK-4',
                'reference': 'https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#testing-custom-certificate-stores-and-certificate-pinning-mstg-network-4',
                'description': 'This App does not use TLS/SSL certificate or public key pinning to detect or prevent MITM attacks in secure communication channel.',
                'severity': 'INFO'
            }
        },
        'android_root_detection': {
            'metadata': {
                'cwe': 'CWE-919 - Weaknesses in Mobile Applications',
                'owasp-mobile': 'M8: Code Tampering',
                'masvs': 'MSTG-RESILIENCE-1',
                'reference': 'https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection-mstg-resilience-1',
                'description': 'This App does not have root detection capabilities. Running a sensitive application on a rooted device questions the device integrity and affects users data.',
                'severity': 'INFO'
            }
        },
        'android_prevent_screenshot': {
            'metadata': {
                'cwe': 'CWE-200 Information Exposure',
                'owasp-mobile': 'M2: Insecure Data Storage',
                'masvs': 'MSTG-STORAGE-9',
                'reference': 'https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots-mstg-storage-9',
                'description': 'This App does not have capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc.',
                'severity': 'INFO'
            }
        },
        'android_safetynet_api': {
            'metadata': {
                'cwe': 'CWE-353 Missing Support for Integrity Check',
                'owasp-mobile': 'M8: Code Tampering',
                'masvs': 'MSTG-RESILIENCE-1',
                'reference': 'https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection-mstg-resilience-1',
                'description': "This App does not uses SafetyNet Attestation API that provides cryptographically-signed attestation, assessing the device's integrity. This check helps to ensure that the servers are interacting with the genuine app running on a genuine Android device. ",
                'severity': 'INFO'
            }
        },
        'android_detect_tapjacking': {
            'metadata': {
                'cwe': 'CWE-200 Information Exposure',
                'owasp-mobile': 'M1: Improper Platform Usage',
                'masvs': 'MSTG-PLATFORM-9',
                'reference': 'https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-for-overlay-attacks-mstg-platform-9',
                'description': "This app does not has capabilities to prevent tapjacking attacks. An attacker can hijack the user's taps and tricks him into performing some critical operations that he did not intend to.",
                'severity': 'INFO'
            }
        }
    },
    'errors': []
}
```

## Configure mobsfscan

A `.mobsf` file in the root of the source code directory allows you to configure mobsfscan. You can also use a custom `.mobsf` file using `--config` argument.

```yaml
---
- ignore-filenames:
  - skip.java

  ignore-paths:
  - __MACOSX
  - skip_dir

  ignore-rules:
  - android_kotlin_logging
  - android_safetynet_api
  - android_prevent_screenshot
  - android_detect_tapjacking
  - android_certificate_pinning
  - android_root_detection
  - android_certificate_transparency

  severity-filter:
  - WARNING
  - ERROR
```
## Suppress Findings

You can suppress findings from source files by adding the comment `// mobsf-ignore: rule_id1, rule_id2` to the line that trigger the findings.

Example:

```java
String password = "strong password"; // mobsf-ignore: hardcoded_password
```

## CI/CD Integrations

You can enable mobsfscan in your CI/CD or DevSecOps pipelines.

#### Github Action

Add the following to the file `.github/workflows/mobsfscan.yml`.

```yaml
name: mobsfscan

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4.2.2
    - uses: actions/setup-python@v5.3.0
      with:
        python-version: '3.12'
    - name: mobsfscan
      uses: MobSF/mobsfscan@main
      with:
        args: '. --json'
```
Example: [pivaa with mobsfscan github action](https://github.com/MobSF/pivaa/actions/workflows/mobsfscan.yml)

#### Github Code Scanning Integration
Add the following to the file `.github/workflows/mobsfscan_sarif.yml`.

```yaml
name: mobsfscan sarif
on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]

jobs:
  mobsfscan:
    runs-on: ubuntu-latest
    name: mobsfscan code scanning
    steps:
    - name: Checkout the code
      uses: actions/checkout@v4.2.2
    - uses: actions/setup-python@v5.3.0
      with:
        python-version: '3.12'
    - name: mobsfscan
      uses: MobSF/mobsfscan@main
      with:
        args: '. --sarif --output results.sarif || true'
    - name: Upload mobsfscan report
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif
```
![mobsfscan github code scanning](https://user-images.githubusercontent.com/4301109/118427198-839be300-b681-11eb-8b79-92b916ffe3ef.png)

#### Gitlab CI/CD

Add the following to the file `.gitlab-ci.yml`.

```yaml
stages:
    - test
mobsfscan:
    image: python
    before_script:
        - pip3 install --upgrade mobsfscan
    script:
        - mobsfscan .
```
Example: 


#### Travis CI

Add the following to the file `.travis.yml`.

```yaml
language: python
install:
    - pip3 install --upgrade mobsfscan
script:
    - mobsfscan .
```

#### Circle CI

Add the following to the file `.circleci/config.yaml`

```yaml
version: 2.1
jobs:
  mobsfscan:
    docker:
      - image: cimg/python:3.9.6
    steps:
      - checkout
      - run:
          name: Install mobsfscan
          command: pip install --upgrade mobsfscan
      - run:
           name: mobsfscan check
           command: mobsfscan .
```

## Docker

### Prebuilt image from [DockerHub](https://hub.docker.com/r/opensecurity/mobsfscan)

```bash
docker pull opensecurity/mobsfscan
docker run -v /path-to-source-dir:/src opensecurity/mobsfscan /src
```

### Build Locally

```
docker build -t mobsfscan .
docker run -v /path-to-source-dir:/src mobsfscan /src
```
