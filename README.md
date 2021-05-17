# mobsfscan
**mobsfscan** is a static analysis tool that can find insecure code patterns in your Android and iOS source code. Supports Java, Kotlin, Swift, and Objective C Code. mobsfscan uses MobSF static analysis rules and is powered by a simple pattern matcher from [libsast](https://github.com/ajinabraham/libsast).

Made with ![Love](https://cloud.githubusercontent.com/assets/4301109/16754758/82e3a63c-4813-11e6-9430-6015d98aeaab.png) in India  [![Tweet](https://img.shields.io/twitter/url?url=https://github.com/MobSF/mobsfscan)](https://twitter.com/intent/tweet/?text=mobsfscan%20is%20a%20static%20analysis%20tool%20that%20can%20find%20insecure%20code%20patterns%20in%20your%20Android%20and%20iOS%20source%20code.%20Supports%20Java,%20Kotlin,%20Swift,%20and%20Objective%20C%20Code.%20by%20%40ajinabraham%20%40OpenSecurity_IN&url=https://github.com/MobSF/mobsfscan)

[![PyPI version](https://badge.fury.io/py/mobsfscan.svg)](https://badge.fury.io/py/mobsfscan)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-green.svg)](https://github.com/MobSF/mobsfscan)
[![License](https://img.shields.io/:license-lgpl3.0+-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0.en.html)
[![python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/MobSF/mobsfscan.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MobSF/mobsfscan/context:python)
[![Requirements Status](https://requires.io/github/MobSF/mobsfscan/requirements/?branch=main)](https://requires.io/github/MobSF/mobsfscan/requirements/?branch=main)
[![Build](https://github.com/MobSF/mobsfscan/workflows/Build/badge.svg)](https://github.com/MobSF/mobsfscan/actions?query=workflow%3ABuild)

### Support mobsfscan

* **Donate via Paypal:** [![Donate via Paypal](https://user-images.githubusercontent.com/4301109/76471686-c43b0500-63c9-11ea-8225-2a305efb3d87.gif)](https://paypal.me/ajinabraham)
* **Sponsor the Project:** [![Github Sponsors](https://user-images.githubusercontent.com/4301109/95517226-9e410780-098e-11eb-9ef5-7b8c7561d725.png)](https://github.com/sponsors/ajinabraham)

## e-Learning Courses & Certifications
![MobSF Course](https://user-images.githubusercontent.com/4301109/76344880-ad68b580-62d8-11ea-8cde-9e3475fc92f6.png) [Automated Mobile Application Security Assessment with MobSF -MAS](https://opsecx.com/index.php/product/automated-mobile-application-security-assessment-with-mobsf/)

![Android Security Tools Course](https://user-images.githubusercontent.com/4301109/76344939-c709fd00-62d8-11ea-8208-774f1d5a7c52.png) [Android Security Tools Expert -ATX](https://opsecx.com/index.php/product/android-security-tools-expert-atx/)


## Installation

`pip install mobsfscan`

Requires Python 3.6+

## Command Line Options

```bash
$ mobsfscan
usage: mobsfscan [-h] [--json] [--sarif] [--sonarqube] [-o OUTPUT] [-c CONFIG] [-w] [-v] [path ...]

positional arguments:
  path                  Path can be file(s) or directories with source code

optional arguments:
  -h, --help            show this help message and exit
  --json                set output format as JSON
  --sarif               set output format as SARIF 2.1.0
  --sonarqube           set output format compatible with SonarQube
  -o OUTPUT, --output OUTPUT
                        output filename to save the result
  -c CONFIG, --config CONFIG
                        Location to .mobsf config file
  -w, --exit-warning    non zero exit code on warning
  -v, --version         show mobsfscan version
```


## Example Usage

```bash
$ mobsfscan ../test_files/android_src/app/src
- Pattern Match ████████████████████████████████████████████████████████████ 13

mobsfscan: v0.0.1 | Ajin Abraham | opensecurity.in
╒══════════════╤════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╕
│ RULE ID      │ android_webview_ignore_ssl                                                                                                                             │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ DESCRIPTION  │ Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MITM attacks │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ TYPE         │ RegexAnd                                                                                                                                               │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ PATTERN      │ ['onReceivedSslError\\(WebView', '\\.proceed\\(\\);']                                                                                                  │
├──────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ SEVERITY     │ high                                                                                                                                                   │
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
>>> src = '../test_files/android_src/app/src'
>>> scanner = MobSFScan([src], json=True)
>>> scanner.scan()
{{
    'results': {
        'android_webview_ignore_ssl': {
            'files': [{
                'file_path': '../test_files/android_src/app/src/main/java/opensecurity/webviewignoressl/MainActivity.java',
                'match_string': 'onReceivedSslError(WebView',
                'match_position': (1331, 1357),
                'match_lines': (46, 46)
            }, {
                'file_path': '../test_files/android_src/app/src/main/java/opensecurity/webviewignoressl/MainActivity.java',
                'match_string': '.proceed();',
                'match_position': (1480, 1491),
                'match_lines': (50, 50)
            }],
            'metadata': {
                'id': 'android_webview_ignore_ssl',
                'description': 'Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MITM attacks',
                'type': 'RegexAnd',
                'pattern': ['onReceivedSslError\\(WebView', '\\.proceed\\(\\);'],
                'severity': 'high',
                'input_case': 'exact',
                'cvss': 7.4,
                'cwe': 'CWE-295 Improper Certificate Validation',
                'owasp-mobile': 'M3: Insecure Communication',
                'masvs': 'MSTG-NETWORK-3',
                'ref': 'https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification'
            }
        }
    }
}
```

## Configure mobsfscan

A `.mobsf` file in the root of the source code directory allows you to configure njsscan. You can also use a custom `.mobsf` file using `--config` argument.

```yaml
---
- scan-extensions:
  - .java
  - .kt
  - .swift
  - .m

  ignore-filenames:
  - skip.js

  ignore-paths:
  - __MACOSX
  - node_modules
  - Pods

  ignore-extensions:
  - .dex
  - .jar
  - .apk
  - .ipa
  - .zip
  - .tar.gz

  ignore-rules:
  - android_logging
  - ios_app_logging

  suppress-findings:
    android_webview_ignore_ssl:
    - opensecurity/webviewignoressl/MainActivity.java,50,46,3
    - Foo.java,22
    - webviewignoressl/,33
```

## CI/CD Integrations

You can enable mobsfscan in your CI/CD or DevSecOps pipelines.

#### Github Action

Add the following to the file `.github/workflows/mobsf.yml`.

```yaml
name: mobsfscan
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  njsscan:
    runs-on: ubuntu-latest
    name: mobsf static analysis
    steps:
    - name: Checkout the code
      uses: actions/checkout@v2
    - name: mobsf static scan
      id: mobsfscan
      uses: MobSF/mobsfscan-action@main
      with:
        args: '.'
```
Example: 

#### Github Code Scanning Integration

Add the following to the file `.github/workflows/mobsfscan_sarif.yml`.

```yaml
name: mobsfscan sarif
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  mobsfscan:
    runs-on: ubuntu-latest
    name: mobsfscan code scanning
    steps:
    - name: Checkout the code
      uses: actions/checkout@v2
    - name: mobsfscan scan
      id: mobsfscan
      uses: MobSF/mobsfscan@main
      with:
        args: '. --sarif --output results.sarif || true'
    - name: Upload mobsfscan report
      uses: github/codeql-action/upload-sarif@v1
      with:
        sarif_file: results.sarif
```
![mobsfscan web ui](https://user-images.githubusercontent.com/4301109/99230041-cfe29500-27bc-11eb-8baa-d5b30e21348d.png)


#### Gitlab CI/CD

Add the following to the file `.gitlab-ci.yml`.

```yaml
stages:
    - test
njsscan:
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
