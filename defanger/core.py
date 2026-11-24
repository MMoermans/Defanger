"""Defang and refang indicators of compromise (IOCs) in free text.

Defanging makes an indicator harmless to click or auto-link (``hxxp://evil[.]com``) so it can be
shared in reports, tickets and chat. Refanging reverses it before the indicator is used in a tool.

Supported indicator types: ``url``, ``email``, ``ipv4``, ``ipv6`` and ``domain``.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

KINDS = ("url", "email", "ipv4", "ipv6", "domain")

# Bare "name.ext" strings that are far more often a file than a domain. They are only treated as
# domains inside URLs and email addresses, or when include_ambiguous is set.
AMBIGUOUS_TLDS = frozenset({"sh", "py", "pl", "rs", "md", "zip", "mov", "pm", "so", "ps", "cc"})

# token sets: (dot, at, colon, colon-slash-slash)
STYLES: dict[str, tuple[str, str, str, str]] = {
    "brackets": ("[.]", "[@]", "[:]", "[://]"),
    "parens": ("(.)", "(@)", "(:)", "(://)"),
    "word": ("[dot]", "[at]", "[:]", "[://]"),
}

URL_SCHEME_DEFANG = {
    "http": "hxxp",
    "https": "hxxps",
    "ftp": "fxp",
    "ftps": "fxps",
    "sftp": "sfxp",
}


@dataclass(frozen=True)
class IOC:
    """An indicator found in text. ``value`` is the live (refanged) form."""

    kind: str
    value: str
    start: int
    end: int


# --------------------------------------------------------------------------------------------------
# TLDs
# --------------------------------------------------------------------------------------------------
@lru_cache(maxsize=1)
def tlds() -> frozenset[str]:
    """The IANA root zone, bundled with the package (see defanger/data/tlds.txt for its version)."""
    text = resources.files("defanger").joinpath("data/tlds.txt").read_text(encoding="utf-8")
    return frozenset(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def _valid_domain(domain: str, *, allow_ambiguous: bool) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld not in tlds():
        return False
    return allow_ambiguous or tld not in AMBIGUOUS_TLDS


# --------------------------------------------------------------------------------------------------
# Finding indicators
# --------------------------------------------------------------------------------------------------
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD = r"(?:xn--[A-Za-z0-9-]{2,59}|[A-Za-z]{2,24})"
_DOMAIN = rf"(?:{_LABEL}\.)+{_TLD}"

_FIND = re.compile(
    rf"""
    (?P<url>(?<!\w)(?P<scheme>https?|ftps?|sftp)://[^\s<>"'`\\]+)
  | (?P<email>(?<![\w.+%-])[A-Za-z0-9._%+-]+@{_DOMAIN}(?![\w-]))
  | (?P<ipv4>(?<![\w.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\w|\.\w))
  | (?P<ipv6>(?<![\w:.])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?:\.\d{{1,3}}){{0,3}}(?![\w]))
  | (?P<domain>(?<![\w@.-]){_DOMAIN}(?![\w-]|@|\[@\]|\(@\)|\{{@\}}|\[at\]|\(at\)|\{{at\}}))
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _trim_url(url: str) -> str:
    """Remove punctuation that belongs to the sentence around a URL, not to the URL."""
    while url:
        last = url[-1]
        if last in ".,;:!?'\"":
            url = url[:-1]
        elif last == ")" and url.count("(") < url.count(")"):
            url = url[:-1]
        elif last == "]" and url.count("[") < url.count("]"):
            url = url[:-1]
        elif last in ">}":
            url = url[:-1]
        else:
            break
    return url


def _ipv6_candidate(raw: str) -> str | None:
    cand = raw
    if cand.endswith(":") and not cand.endswith("::"):
        cand = cand[:-1]
    if cand.count(":") < 2 or cand in ("::", ":::"):
        return None
    try:
        ipaddress.IPv6Address(cand)
    except ValueError:
        return None
    return cand


def _split_authority(url: str) -> tuple[str, str, int, int]:
    """Return (scheme, authority, start, end) of a URL; start/end locate the authority in the URL."""
    scheme, _, rest = url.partition("://")
    offset = len(scheme) + 3
    end = len(rest)
    for ch in "/?#":
        pos = rest.find(ch)
        if pos != -1:
            end = min(end, pos)
    return scheme, rest[:end], offset, offset + end


def _host_of(authority: str) -> str:
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else host[1:]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def find_iocs(text: str, *, include_ambiguous: bool = False) -> list[IOC]:
    """Live (not yet defanged) indicators in text, in order of appearance."""
    return list(_iter_iocs(text, include_ambiguous))


def _iter_iocs(text: str, include_ambiguous: bool) -> Iterator[IOC]:
    for m in _FIND.finditer(text):
        if m.group("url") is not None:
            url = _trim_url(m.group("url"))
            if "://" not in url or not url.partition("://")[2]:
                continue
            yield IOC("url", url, m.start(), m.start() + len(url))
        elif m.group("email") is not None:
            domain = m.group("email").rsplit("@", 1)[1]
            if _valid_domain(domain, allow_ambiguous=True):
                yield IOC("email", m.group("email"), m.start(), m.end())
        elif m.group("ipv4") is not None:
            yield IOC("ipv4", m.group("ipv4"), m.start(), m.end())
        elif m.group("ipv6") is not None:
            cand = _ipv6_candidate(m.group("ipv6"))
            if cand is not None:
                yield IOC("ipv6", cand, m.start(), m.start() + len(cand))
        elif m.group("domain") is not None:
            if _valid_domain(m.group("domain"), allow_ambiguous=include_ambiguous):
                yield IOC("domain", m.group("domain"), m.start(), m.end())


def expand(ioc: IOC, *, include_ambiguous: bool = False) -> list[IOC]:
    """The host of a URL and the domain of an email address as their own indicators."""
    if ioc.kind == "url":
        _, authority, _, _ = _split_authority(ioc.value)
        host = _host_of(authority)
    elif ioc.kind == "email":
        host = ioc.value.rsplit("@", 1)[1]
    else:
        return []
    try:
        ipaddress.IPv4Address(host)
        return [IOC("ipv4", host, ioc.start, ioc.end)]
    except ValueError:
        pass
    if ":" in host:
        cand = _ipv6_candidate(host)
        return [IOC("ipv6", cand, ioc.start, ioc.end)] if cand else []
    if "." in host and _valid_domain(host, allow_ambiguous=True):
        return [IOC("domain", host.lower(), ioc.start, ioc.end)]
    return []


# --------------------------------------------------------------------------------------------------
# Defang
# --------------------------------------------------------------------------------------------------
def _tokens(style: str) -> tuple[str, str, str, str]:
    try:
        return STYLES[style]
    except KeyError:
        raise ValueError(f"unknown style '{style}' (choose from: {', '.join(STYLES)})") from None


def defang_value(kind: str, value: str, *, style: str = "brackets", colon: bool = False) -> str:
    """Defang one indicator of a known kind."""
    dot, at, col, colslash = _tokens(style)
    if kind in ("ipv4", "domain"):
        return value.replace(".", dot)
    if kind == "ipv6":
        return value.replace(":", col)
    if kind == "email":
        local, _, domain = value.rpartition("@")
        return local + at + domain.replace(".", dot)
    if kind == "url":
        scheme, authority, _, a_end = _split_authority(value)
        rest = value[a_end:]
        authority = refang_text(authority)  # half-defanged input must not be defanged twice
        if authority.startswith("[") and "]" in authority:  # [IPv6]:port, keep the port colon
            inside, _, tail = authority[1:].partition("]")
            host_part = "[" + inside.replace(":", col).replace(".", dot) + "]" + tail
        else:
            host_part = authority.replace(".", dot).replace("@", at)
        scheme_out = URL_SCHEME_DEFANG.get(scheme.lower(), scheme)
        return f"{scheme_out}{colslash if colon else '://'}{host_part}{rest}"
    raise ValueError(f"unknown indicator kind '{kind}'")


def defang_text(
    text: str,
    *,
    style: str = "brackets",
    only: Iterable[str] | None = None,
    colon: bool = False,
    include_ambiguous: bool = False,
    stats: Counter | None = None,
) -> str:
    """Defang every live indicator in ``text``. Text that is already defanged is left as it is.

    ``only`` limits the kinds to defang (see KINDS). The ``url`` kind covers the URL's host too.
    ``stats`` receives a count per kind.
    """
    _tokens(style)
    wanted = set(KINDS if only is None else only)
    unknown = wanted - set(KINDS)
    if unknown:
        raise ValueError(f"unknown indicator kind(s): {', '.join(sorted(unknown))}")
    out: list[str] = []
    pos = 0
    for ioc in _iter_iocs(text, include_ambiguous):
        if ioc.start < pos:
            continue
        out.append(text[pos : ioc.start])
        if ioc.kind in wanted:
            out.append(defang_value(ioc.kind, ioc.value, style=style, colon=colon))
            if stats is not None:
                stats[ioc.kind] += 1
        else:
            out.append(text[ioc.start : ioc.end])
        pos = ioc.end
    out.append(text[pos:])
    return "".join(out)


# --------------------------------------------------------------------------------------------------
# Refang
# --------------------------------------------------------------------------------------------------
_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    # Scheme: hxxp, hXXp, h**p, fxp, sfxp. Only when a colon follows, so prose is not touched.
    (re.compile(r"(?<![A-Za-z])h(?:xx|\*\*)p(s?)(?=:|\[:|\(:|\{:|\[://\])", re.IGNORECASE), r"http\1"),
    (re.compile(r"(?<![A-Za-z])(s?)fxp(s?)(?=:|\[:|\(:|\{:|\[://\])", re.IGNORECASE), r"\1ftp\2"),
    (re.compile(r"\[://\]|\(://\)|\{://\}"), "://"),
    (re.compile(r"\[::\]|\(::\)"), "::"),
    (re.compile(r"\[:\]|\(:\)|\{:\}"), ":"),
    (re.compile(r"\[/\]|\(/\)"), "/"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\}", re.IGNORECASE), "@"),
]


def is_defanged(text: str) -> bool:
    """True if the text contains any recognised defang marker."""
    return any(rule.search(text) for rule, _ in _REFANG_RULES)


def refang_text(text: str) -> str:
    """Reverse the common defang styles: [.] (.) {.} [dot], [@] [at], [:] [://], hxxp, fxp."""
    for rule, repl in _REFANG_RULES:
        text = rule.sub(repl, text)
    return text


# --------------------------------------------------------------------------------------------------
# Extract
# --------------------------------------------------------------------------------------------------
def extract(
    text: str,
    *,
    only: Iterable[str] | None = None,
    expand_hosts: bool = False,
    include_ambiguous: bool = False,
    unique: bool = True,
) -> list[IOC]:
    """Indicators in text, whether it is defanged or not. Values are the live form.

    With ``expand_hosts`` the host of every URL and the domain of every email address is listed as
    its own indicator as well.
    """
    wanted = set(KINDS if only is None else only)
    unknown = wanted - set(KINDS)
    if unknown:
        raise ValueError(f"unknown indicator kind(s): {', '.join(sorted(unknown))}")
    live = refang_text(text)
    found: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc: IOC) -> None:
        key = (ioc.kind, ioc.value.lower() if ioc.kind in ("domain", "email") else ioc.value)
        if ioc.kind in wanted and (not unique or key not in seen):
            seen.add(key)
            found.append(ioc)

    for ioc in _iter_iocs(live, include_ambiguous):
        add(ioc)
        if expand_hosts:
            for sub in expand(ioc, include_ambiguous=include_ambiguous):
                add(sub)
    return found
