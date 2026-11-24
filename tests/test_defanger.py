import json
from collections import Counter

import pytest

from defanger import (
    KINDS,
    defang_text,
    defang_value,
    extract,
    find_iocs,
    is_defanged,
    refang_text,
)
from defanger.cli import main
from defanger.core import tlds

SAMPLE = """\
Contact bad.actor@evil-mail.com or visit https://evil.example.com/a/b.php?x=1.
C2 at 203.0.113.7:8443 and 2001:db8::1, also see setup.py and README.md, Node.js, 12:30:45, aa:bb:cc:dd:ee:ff.
(see http://x.org/path_(1)), [link](http://link.io/a), ftp://files.test.net, http://[2001:db8::2]:8080/p
"""


# --- the original behaviour was wrong ---------------------------------------------------------------
def test_every_dot_is_defanged_not_all_but_the_last():
    # v1 returned "1[.]2[.]3.4", which left a clickable address behind
    assert defang_text("1.2.3.4") == "1[.]2[.]3[.]4"
    assert defang_text("evil.example.com") == "evil[.]example[.]com"


def test_invalid_ips_are_not_treated_as_ips():
    assert find_iocs("256.1.1.1 and 1.2.3 and 01.2.3.4") == []


# --- defang -----------------------------------------------------------------------------------------
def test_defang_all_kinds():
    out = defang_text(SAMPLE)
    assert "bad.actor[@]evil-mail[.]com" in out
    assert "hxxps://evil[.]example[.]com/a/b.php?x=1." in out
    assert "203[.]0[.]113[.]7:8443" in out
    assert "2001[:]db8[:][:]1" in out
    assert "hxxp://x[.]org/path_(1))" in out
    assert "[link](hxxp://link[.]io/a)" in out
    assert "fxp://files[.]test[.]net" in out
    assert "hxxp://[2001[:]db8[:][:]2]:8080/p" in out  # the port colon stays


def test_things_that_look_like_indicators_but_are_not_are_left_alone():
    out = defang_text(SAMPLE)
    for harmless in ("setup.py", "README.md", "Node.js", "12:30:45", "aa:bb:cc:dd:ee:ff", "b.php"):
        assert harmless in out


def test_ambiguous_extensions_need_a_flag_but_work_in_urls():
    assert defang_text("run evil.sh now") == "run evil.sh now"
    assert defang_text("run evil.sh now", include_ambiguous=True) == "run evil[.]sh now"
    assert defang_text("http://evil.sh/x") == "hxxp://evil[.]sh/x"


def test_unknown_tlds_are_ignored():
    assert defang_text("file.exe config.yaml a.b.notatld") == "file.exe config.yaml a.b.notatld"
    assert "com" in tlds() and "xn--p1ai" in tlds()


def test_idempotent_and_round_trips():
    once = defang_text(SAMPLE)
    assert defang_text(once) == once
    assert refang_text(once) == SAMPLE


def test_idempotent_for_an_email_whose_local_part_looks_like_a_domain():
    # "actor" is a real TLD, so "bad.actor" looks like a domain once the @ is defanged
    once = defang_text("bad.actor@evil.com")
    assert once == "bad.actor[@]evil[.]com"
    assert defang_text(once) == once


def test_half_defanged_input_is_completed():
    assert defang_text("http://evil[.]com/x") == "hxxp://evil[.]com/x"
    assert defang_text("hxxp://evil.com/x") == "hxxp://evil[.]com/x"


def test_styles_and_colon_option():
    assert defang_text("u@a.com", style="parens") == "u(@)a(.)com"
    assert defang_text("1.2.3.4", style="word") == "1[dot]2[dot]3[dot]4"
    assert defang_text("https://a.com", colon=True) == "hxxps[://]a[.]com"
    with pytest.raises(ValueError, match="unknown style"):
        defang_text("a.com", style="nope")


def test_only_limits_what_is_defanged_and_counts():
    stats = Counter()
    out = defang_text("1.2.3.4 evil.com", only=["domain"], stats=stats)
    assert out == "1.2.3.4 evil[.]com"
    assert stats == {"domain": 1}
    with pytest.raises(ValueError):
        defang_text("x", only=["nonsense"])


def test_url_trailing_punctuation_is_not_part_of_the_url():
    assert defang_text("See http://a.com/x, and http://b.org.") == "See hxxp://a[.]com/x, and hxxp://b[.]org."
    assert defang_text("(http://a.com/x)") == "(hxxp://a[.]com/x)"


def test_credentials_in_urls():
    assert defang_value("url", "http://user:pw@host.co.uk/x") == "hxxp://user:pw[@]host[.]co[.]uk/x"


# --- refang -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("defanged,live", [
    ("hxxp://evil[.]com", "http://evil.com"),
    ("hXXps://evil(.)com/a", "https://evil.com/a"),
    ("h**p://evil{.}com", "http://evil.com"),
    ("evil[dot]com", "evil.com"),
    ("EVIL[DOT]COM", "EVIL.COM"),
    ("user[at]evil[.]com", "user@evil.com"),
    ("user(@)evil.com", "user@evil.com"),
    ("hxxp[:]//evil.com", "http://evil.com"),
    ("hxxps[://]evil.com", "https://evil.com"),
    ("fxp://files[.]x[.]net", "ftp://files.x.net"),
    ("sfxp://files.x.net", "sftp://files.x.net"),
    ("2001[:]db8[::]1", "2001:db8::1"),
])
def test_refang_styles(defanged, live):
    assert is_defanged(defanged)
    assert refang_text(defanged) == live


def test_refang_leaves_ordinary_text_alone():
    text = "The hxxp word and fxp files are fine. a.b.c 1.2.3.4"
    assert not is_defanged(text)
    assert refang_text(text) == text


# --- extract ----------------------------------------------------------------------------------------
def test_extract_works_on_defanged_text_and_returns_live_values():
    found = extract(defang_text(SAMPLE))
    values = [(i.kind, i.value) for i in found]
    assert ("email", "bad.actor@evil-mail.com") in values
    assert ("ipv4", "203.0.113.7") in values
    assert ("ipv6", "2001:db8::1") in values
    assert ("url", "https://evil.example.com/a/b.php?x=1") in values


def test_extract_expand_lists_hosts_and_dedupes():
    found = extract("http://Evil.com/a http://evil.com/b mail@evil.com 1.2.3.4", expand_hosts=True)
    assert [(i.kind, i.value) for i in found] == [
        ("url", "http://Evil.com/a"), ("domain", "evil.com"),
        ("url", "http://evil.com/b"), ("email", "mail@evil.com"), ("ipv4", "1.2.3.4"),
    ]
    assert len(extract("evil.com EVIL.com", unique=True)) == 1
    assert len(extract("evil.com EVIL.com", unique=False)) == 2
    assert [i.kind for i in extract("1.2.3.4 evil.com", only=["ipv4"])] == ["ipv4"]


def test_all_kinds_are_known():
    assert set(KINDS) == {"url", "email", "ipv4", "ipv6", "domain"}


# --- command line -----------------------------------------------------------------------------------
def test_cli_values_auto_direction(capsys):
    assert main(["1.2.3.4", "evil.com"]) == 0
    assert capsys.readouterr().out == "1[.]2[.]3[.]4\nevil[.]com\n"
    assert main(["hxxp://evil[.]com"]) == 0
    assert capsys.readouterr().out == "http://evil.com\n"


def test_cli_explicit_commands_override_the_direction(capsys):
    assert main(["defang", "evil.com", "--style", "word"]) == 0
    assert capsys.readouterr().out == "evil[dot]com\n"
    assert main(["refang", "evil.com"]) == 0
    assert capsys.readouterr().out == "evil.com\n"


def test_cli_file_to_file_and_stats(tmp_path, capsys):
    src = tmp_path / "report.md"
    src.write_text(SAMPLE, encoding="utf-8", newline="")
    out = tmp_path / "safe.md"
    assert main(["-f", str(src), "-o", str(out), "--stats"]) == 0
    assert out.read_text(encoding="utf-8") == defang_text(SAMPLE)
    assert "defanged:" in capsys.readouterr().err
    assert src.read_text(encoding="utf-8") == SAMPLE  # the original is untouched


def test_cli_in_place_keeps_a_backup(tmp_path):
    src = tmp_path / "r.txt"
    src.write_text("c2 evil.com\n", encoding="utf-8", newline="")
    assert main(["defang", "-i", "-f", str(src)]) == 0
    assert src.read_text(encoding="utf-8") == "c2 evil[.]com\n"
    assert (tmp_path / "r.txt.bak").read_text(encoding="utf-8") == "c2 evil.com\n"
    assert main(["refang", "-i", "--no-backup", "-f", str(src)]) == 0
    assert src.read_text(encoding="utf-8") == "c2 evil.com\n"


def test_cli_stdin(monkeypatch, capsys):
    import io

    class Pipe(io.StringIO):
        def isatty(self):
            return False

    monkeypatch.setattr("sys.stdin", Pipe("host evil.com\n"))
    assert main(["defang"]) == 0
    assert capsys.readouterr().out == "host evil[.]com\n"


def test_cli_extract_formats(tmp_path, capsys):
    f = tmp_path / "r.txt"
    f.write_text("a evil[.]com b 1[.]2[.]3[.]4 c evil.com", encoding="utf-8")
    assert main(["extract", "-f", str(f)]) == 0
    assert capsys.readouterr().out == "evil[.]com\n1[.]2[.]3[.]4\n"
    assert main(["extract", "-f", str(f), "--live", "--all"]) == 0
    assert capsys.readouterr().out == "evil.com\n1.2.3.4\nevil.com\n"
    assert main(["extract", "-f", str(f), "--format", "json", "--only", "ip"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [{"type": "ipv4", "value": "1.2.3.4", "defanged": "1[.]2[.]3[.]4", "source": str(f)}]
    assert main(["extract", "-f", str(f), "--format", "csv"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "type,value,defanged,source"


def test_cli_check_exit_codes_and_ignore(tmp_path, capsys):
    f = tmp_path / "r.md"
    f.write_text("ok evil[.]com\nlive: bad.net and http://corp.example.org/x\n", encoding="utf-8")
    assert main(["check", "-f", str(f)]) == 1
    out = capsys.readouterr().out
    assert f"{f}:2: live domain: bad[.]net" in out
    assert "live url: hxxp://corp[.]example[.]org/x" in out
    assert main(["check", "-f", str(f), "--ignore", "example.org,bad.net"]) == 0
    assert main(["check", "-f", str(f), "--only", "ip"]) == 0
    clean = tmp_path / "clean.md"
    clean.write_text(defang_text(f.read_text(encoding="utf-8")), encoding="utf-8")
    assert main(["check", "-f", str(clean), "-q"]) == 0


def test_cli_errors(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["-f", str(tmp_path / "missing.txt")])
    assert exc.value.code == 2
    assert "cannot read" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        main(["defang", "--only", "nonsense", "x"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["defang", "-i", "x.com"])
    assert exc.value.code == 2


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("defanger ")


def test_random_mixes_are_idempotent_leave_nothing_live_and_round_trip():
    import random

    rnd = random.Random(1)
    atoms = [
        "evil.com", "a.b.example.co.uk", "203.0.113.7", "10.0.0.1:8080", "2001:db8::1", "::1",
        "http://evil.com/a/b?c=d.e", "https://x.org", "ftp://f.net/z", "user@mail.example.com",
        "bad.actor@evil.com", "setup.py", "v1.2.3", "12:30:45", "aa:bb:cc:dd:ee:ff", "Node.js", "e.g.",
        "(http://a.com/x)", "[http://b.com]", "http://[2001:db8::2]:80/", "evil.com.", "1.2.3.4.5",
        "foo@bar", "d41d8cd98f00b204e9800998ecf8427e", "key:evil.com", "t.co", "a.zip",
    ]
    seps = [" ", ", ", "\n", " and ", ": ", "; ", " (", ") "]
    for _ in range(500):
        text = "".join(rnd.choice(atoms) + rnd.choice(seps) for _ in range(rnd.randint(1, 6)))
        defanged = defang_text(text)
        assert defang_text(defanged) == defanged, text
        assert find_iocs(defanged) == [], text
        assert refang_text(defanged) == text, text
