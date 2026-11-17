# PortScan

TCP port scanner and service prober using Python asyncio and Rich.

Author: Soar (2026)

## Features

- Scans single ports, comma-separated lists, ranges (`1-1024`), or the built-in top 100 preset.
- Grabs banners for HTTP, SSH, FTP, SMTP, and common databases.
- Reads TLS certificate subject and version on encrypted ports.
- Supports randomized port order with `--shuffle`.
- Exports results to JSON (`-oJ`), CSV (`-oC`), or standalone HTML (`-oH`).

## Requirements

- Python 3.10+
- `rich`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Scan top 100 ports on a target:

```bash
python portscan.py 127.0.0.1
```

Scan specific ports with a 0.5-second timeout:

```bash
python portscan.py 192.168.1.1 -p 22,80,443,8080 -t 0.5
```

Scan a port range with higher concurrency:

```bash
python portscan.py 10.0.0.1 -p 1-1000 -c 300
```

Export scan output to HTML and JSON:

```bash
python portscan.py scanme.org -p top100 -oH report.html -oJ results.json
```

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `-p`, `--ports` | Ports to scan (`top100`, `all`, or list/range) | `top100` |
| `-c`, `--concurrency` | Max concurrent worker connections | `150` |
| `-t`, `--timeout` | Socket timeout in seconds | `1.0` |
| `--no-banners` | Skip banner grabbing | `False` |
| `--shuffle` | Randomize port scan order | `False` |
| `-oJ` | Write JSON export to path | None |
| `-oC` | Write CSV export to path | None |
| `-oH` | Write HTML report to path | None |

## Copyright

Copyright (c) 2026 Soar. All rights reserved.

## Developers

[![I2TT](https://img.shields.io/badge/I2TT-GITHUB-black?style=for-the-badge&logo=github)](https://github.com/i2tt) [![K2CV](https://img.shields.io/badge/K2CV-GITHUB-black?style=for-the-badge&logo=github)](https://github.com/k2cv)

Authored-By: [k2cv](https://github.com/k2cv)

## Disclaimer

This software is for educational and network testing purposes only. Use entirely at your own risk.
