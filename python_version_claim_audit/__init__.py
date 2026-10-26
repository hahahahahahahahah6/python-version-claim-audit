"""Offline, read-only audit of version claims."""
import argparse
import fnmatch
import io
import json
from pathlib import Path
import re
import tokenize

__version__ = "0.1.0"
V = r"3\.(?:1[0-4]|[89])(?![\d.])"
CLASSIFIER = re.compile(r"Programming Language :: Python :: (3\.\d+)(?![\d.])")


def version(value):
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        raise ValueError("unsupported version: " + value)
    parts = tuple(map(int, value.split(".")))
    return parts + (0,) * (3 - len(parts))


def satisfies(candidate, spec):
    """Evaluate our numeric subset of PEP 440, with comma conjunction."""
    current = version(candidate)
    outcomes = []
    for item in spec.split(","):
        match = re.fullmatch(r"\s*(~=|==|!=|>=|<=|>|<)\s*(\d+(?:\.\d+)*(?:\.\*)?)\s*", item)
        if not match:
            raise ValueError("unsupported specifier: " + item)
        op, target = match.groups()
        if target.endswith(".*"):
            if op not in ("==", "!="):
                raise ValueError("wildcards require == or !=")
            prefix = tuple(map(int, target[:-2].split(".")))
            equal = current[:len(prefix)] == prefix
            outcomes.append(equal if op == "==" else not equal)
            continue
        other = version(target)
        if op == "~=":
            parts = list(map(int, target.split(".")))
            if len(parts) < 2:
                raise ValueError("compatible release needs two components")
            upper = parts[:-1]
            upper[-1] += 1
            outcomes.append(current >= other and current < version(".".join(map(str, upper))))
        else:
            outcomes.append({"==": current == other, "!=": current != other,
                             ">=": current >= other, "<=": current <= other,
                             ">": current > other, "<": current < other}[op])
    return all(outcomes)


def without_comments(text, is_python=False):
    if is_python:
        try:
            return tokenize.untokenize(t for t in tokenize.generate_tokens(io.StringIO(text).readline)
                                       if t.type != tokenize.COMMENT)
        except (tokenize.TokenError, IndentationError):
            raise ValueError("cannot tokenize setup.py")
    # Preserve hash characters within quoted strings.
    return re.sub(r"(\"[^\"\n]*\"|'[^'\n]*')|#[^\n]*", lambda m: m.group(1) or "", text)


def evidence(root):
    sources = []
    for name in ("pyproject.toml", "setup.py", "setup.cfg"):
        path = root / name
        if not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8")
        clean = without_comments(raw, name == "setup.py")
        sources.append(clean)
        if name == "pyproject.toml":
            section = re.search(r"(?ms)^\[project\]\s*$(.*?)(?=^\[|\Z)", clean)
            target = section.group(1) if section else ""
            match = re.search(r"(?m)^\s*requires-python\s*=\s*['\"]([^'\"]+)['\"]", target)
        elif name == "setup.py":
            match = re.search(r"\bpython_requires\s*=\s*['\"]([^'\"]+)['\"]", clean)
        else:
            section = re.search(r"(?ms)^\[options\]\s*$(.*?)(?=^\[|\Z)", clean)
            target = section.group(1) if section else ""
            match = re.search(r"(?m)^\s*python_requires\s*=\s*['\"]?([^'\"\n]+)", target)
        if match:
            spec = match.group(1).strip()
            satisfies("3.9", spec)  # Validate even when there are no claims.
            return spec, None
    listed = set(CLASSIFIER.findall("\n".join(sources)))
    return None, listed or None


def claims(text):
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not line[marker.end():].strip():
                fence = None
            continue
        if fence:
            continue
        occupied = []
        negative = [rf"does not support Python ({V})", rf"no Python ({V}) support",
                    rf"not compatible with Python ({V})", rf"Python ({V}) not supported",
                    rf"does not work with Python ({V})", rf"drops Python ({V})", rf"dropped Python ({V})"]
        positive = [rf"Python ({V}) or higher", rf"Python ({V}) or later", rf"Python ({V})\+",
                    rf"Python >= ({V})", rf"requires Python ({V})", rf"supports Python ({V})",
                    rf"works with Python ({V})", rf"runs on Python ({V})",
                    rf"compatible with Python ({V})", rf"Python ({V}) supported"]
        found = []
        for pattern in negative:
            for m in re.finditer(r"(?<!\w)" + pattern + r"(?!\w)", line):
                occupied.append(m.span())
                found.append((m.start(), "NOSUPPORT", m.group(1)))
        for m in re.finditer(rf"(?<!\w)Python ({V})(?: to |-|–)({V})(?!\w)", line):
            a, b = int(m.group(1)[2:]), int(m.group(2)[2:])
            if a <= b:
                occupied.append(m.span())
                found.extend((m.start(), "SUPPORT", "3." + str(n)) for n in range(a, b + 1))
        for pattern in positive:
            for m in re.finditer(r"(?<!\w)" + pattern + r"(?!\w)", line):
                if not any(m.start() < end and m.end() > start for start, end in occupied):
                    occupied.append(m.span())
                    found.append((m.start(), "SUPPORT", m.group(1)))
        for _, kind, value in sorted(found, key=lambda item: item[0]):
            yield number, kind, value


def audit(root, ignores=()):
    root = Path(root)
    if not root.is_dir():
        raise ValueError("root must be a directory")
    spec, listed = evidence(root)
    paths = [root / "README.md"] + sorted((root / "docs").rglob("*.md"))
    findings = {}
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) for pattern in ignores):
            continue
        for line, kind, value in claims(path.read_text(encoding="utf-8")):
            supported = satisfies(value, spec) if spec is not None else (value in listed if listed else None)
            false = supported is not True if kind == "SUPPORT" else supported is True
            if false:
                family = "documented-version-claim-false" if kind == "SUPPORT" else "documented-no-version-claim-false"
                findings.setdefault(family, {"rule": family, "severity": "MEDIUM" if "tests" in path.relative_to(root).parts[:-1] else "HIGH",
                                             "file": relative, "line": line, "version": value, "claim": kind})
    return list(findings.values())


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(__import__("sys").stderr)
        self.exit(1, self.prog + ": error: " + message + "\n")


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--ignore", nargs="+", action="extend", default=[])
    parser.add_argument("--fail-on", choices=("HIGH", "MEDIUM"), default="HIGH")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        findings = audit(args.root, args.ignore)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    failed = any(f["severity"] == "HIGH" or args.fail_on == "MEDIUM" for f in findings)
    status = "FAIL" if failed else "PASS"
    if args.json:
        print(json.dumps({"status": status, "findings": findings}, sort_keys=True))
    else:
        print(status)
        for f in findings:
            detail = " {file}:{line} {claim} {version}".format(**f) if args.verbose else ""
            print(f["rule"] + " " + f["severity"] + detail)
    return 2 if failed else 0
