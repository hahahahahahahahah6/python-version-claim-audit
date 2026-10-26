# python-version-claim-audit

An offline static checker for documentation promises about interpreter versions.
Version 0.1.0 uses only the standard library at runtime. It reads root README.md,
docs/**/*.md and version metadata, without executing setup.py or writing to the
audited tree. It never reads .env files.

Install and run:

```sh
python3 -m pip install .
python-version-claim-audit . --verbose
python3 -m python_version_claim_audit . --json
python3 -m unittest discover
python3 -m build
```

The console and module interfaces accept an optional root (default: current
working directory), --json, --verbose, --ignore GLOB ... (repeatable), and
--fail-on HIGH|MEDIUM (default HIGH). Exit codes: 0 PASS, 2 findings meeting
the threshold, 1 usage or unsupported configuration error. --version prints
0.1.0. JSON has status and findings; each finding includes rule, severity,
file, line, version and claim. Verbose text identifies the first false claim
in each family. Findings below the selected threshold remain visible.

## Matching and evidence

Templates are case-sensitive. Inline code counts; backtick and tilde fenced
blocks do not. Recognized phrase forms (V, A, B denote minors from 3.8 to 3.14):

```text
Python V or higher
Python V or later
Python V+
Python >= V
requires Python V
supports Python V
works with Python V
runs on Python V
compatible with Python V
Python V supported
Python A to B
Python A-B
Python A–B
does not support Python V
no Python V support
not compatible with Python V
Python V not supported
does not work with Python V
drops Python V
dropped Python V
```

Ranges expand inclusively. Lower-bound phrases assert the named minor, rather
than expanding to every future minor. Evidence priority is project.requires-python
in pyproject.toml, then python_requires in setup.py or setup.cfg, then minor
classifiers when no specifier exists. Classifiers form a closed list. Comments
are ignored. A positive promise without evidence fails; a negative statement
without evidence passes. There is one finding per family, at the first false
claim. Findings under a tests/ directory are MEDIUM; others are HIGH.

## Differentiation

Unlike platform-claim-audit, this checks interpreter minors rather than OS
promises. Unlike config-claim-audit, it compares documentation with support
metadata rather than general configuration. Unlike dependency-claim-audit,
it does not inspect installed dependencies. Unlike readme-claim-audit, its
vocabulary and evidence are confined to interpreter version declarations.

## Limitations

Matching uses exact templates, not semantics. There is no generic negation
detection beyond the listed negative templates; arbitrary negated sentences
are outside the supported grammar. Range templates accept only the three
separators listed above. Pre-releases are not special-cased: unsupported
specifier syntax produces a usage error. The specifier parser is a subset of
PEP 440: numeric comparisons, compatible release, comma conjunction and equality
wildcards only; no environment markers or extras. It does not prove a version
actually runs; it only compares declared support with declared configuration.
.python-version and CI YAML are not support evidence; neither are lockfiles,
documentation itself, or classifiers without a minor version. Metadata is read
statically; dynamically computed setup.py values are not evaluated. The small
TOML reader handles a literal project table, quoted single-line specifiers and
literal classifier text; it is not a general TOML implementation.

Build and verification need setuptools and the build frontend available locally;
the audit itself never uses the network. Distribution artifacts belong in the
existing release queue only; this project does not upload or execute a drip job.

Licensed under MIT.
