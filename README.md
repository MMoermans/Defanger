# Defanger

Defang and refang indicators of compromise (IPs, domains, URLs, email addresses) in values, files
and whole reports. Defanged indicators can't be clicked or auto-linked by mistake, so they are safe
to put in tickets, chat and write-ups.

```console
$ defanger 203.0.113.7 evil.com https://evil.example.com/a/b
203[.]0[.]113[.]7
evil[.]com
hxxps://evil[.]example[.]com/a/b

$ defanger "hxxps://evil[.]example[.]com/a/b"
https://evil.example.com/a/b
```

![CI](https://github.com/MMoermans/Defanger/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

## Install

```bash
pip install git+https://github.com/MMoermans/Defanger.git
```

Or run it from a clone without installing: `python -m defanger ...` (Python 3.10+, standard library only).
`python fangy.py` still works and asks for a value, like the first version.

## What it does

| Command | |
|---|---|
| `defanger [values...]` | Defang or refang, whichever the input needs |
| `defanger defang` / `refang` | Force a direction |
| `defanger extract` | List the indicators in the input, as text, JSON or CSV |
| `defanger check` | Exit 1 if the input still has live (clickable) indicators |

Input is values on the command line, `-f FILE` (repeatable) or stdin. Output goes to stdout, to
`-o FILE`, or back into the files with `-i/--in-place` (a `.bak` copy is kept).

```bash
defanger -f report.md -o report.safe.md        # defang a whole report
defanger -i -f notes.md                        # in place, notes.md.bak is the original
cat alerts.log | defanger defang               # in a pipeline
defanger refang -f iocs.txt -o live.txt        # refang before feeding a tool
```

With no command the direction is chosen from the input: text that already contains defang markers
such as `[.]` or `hxxp` is refanged, anything else is defanged.

### Indicator types

URLs (`http`, `https`, `ftp`, `ftps`, `sftp`), email addresses, IPv4, IPv6 and domains. Limit them with
`--only url,domain` (`ip` means IPv4 and IPv6).

| Live | Defanged |
|---|---|
| `203.0.113.7:8443` | `203[.]0[.]113[.]7:8443` |
| `2001:db8::1` | `2001[:]db8[:][:]1` |
| `evil.example.com` | `evil[.]example[.]com` |
| `https://evil.example.com/a.php?x=1` | `hxxps://evil[.]example[.]com/a.php?x=1` |
| `http://user:pw@host.co.uk/` | `hxxp://user:pw[@]host[.]co[.]uk/` |
| `bad.actor@evil.com` | `bad.actor[@]evil[.]com` |

Only the host of a URL is defanged, not the path. `--colon` also defangs the `://`
(`hxxps[://]evil[.]com`). `--style` picks the notation: `brackets` (`[.]`, default), `parens` (`(.)`)
or `word` (`[dot]`, `[at]`).

### Refang understands the common styles

`[.]` `(.)` `{.}` `[dot]` `(dot)` `[@]` `(@)` `[at]` `[:]` `[://]` `hxxp` `hXXp` `h**p` `fxp` `sfxp`.
It only rewrites those markers, so ordinary text is left alone.

### Extract

```console
$ defanger extract -f report.md --expand --format csv
type,value,defanged,source
url,https://evil.example.com/a,hxxps://evil[.]example[.]com/a,report.md
domain,evil.example.com,evil[.]example[.]com,report.md
ipv4,203.0.113.7,203[.]0[.]113[.]7,report.md
```

Works on defanged and live text alike. Values are deduplicated (`--all` keeps duplicates).
`--expand` adds the host of every URL and the domain of every email address as separate indicators.
The text format prints defanged values so the list is safe to paste; `--live` prints the real ones.

### Check: keep live indicators out of reports

```console
$ defanger check -f report.md --ignore example.org,corp.local
report.md:14: live domain: bad[.]net
report.md:20: live url: hxxp://c2[.]evil[.]example[.]com/x
2 live indicator(s) found
```

The exit status is 1 when something is found, so it works as a CI step or a pre-commit hook.
`--ignore` allows a domain and its subdomains, or an IP address.

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: defanger-check
      name: no live indicators in reports
      entry: defanger check --ignore example.com -f
      language: system
      files: ^reports/.*\.md$
```

## As a library

```python
from defanger import defang_text, refang_text, extract

defang_text("C2 at 203.0.113.7 via http://evil.com/a")
# 'C2 at 203[.]0[.]113[.]7 via hxxp://evil[.]com/a'

[(i.kind, i.value) for i in extract("hxxp://evil[.]com/a", expand_hosts=True)]
# [('url', 'http://evil.com/a'), ('domain', 'evil.com')]
```

`defang_text` takes `style`, `only`, `colon`, `include_ambiguous` and `stats` (a `Counter` that
receives the count per type). `find_iocs`, `defang_value`, `is_defanged` and `expand` are there too.

## Development

```bash
pip install -e ".[dev]"
pytest && ruff check .
```

The bundled TLD list lives in `defanger/data/tlds.txt`; its header names the IANA version it came from.
