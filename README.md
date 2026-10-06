# aurvet

A read-only CLI that screens AUR packages *before* you build and install
them. For each package it fetches the current PKGBUILD, install scripts,
and metadata from `aur.archlinux.org`, runs static heuristics,
cross-checks community campaign bad-lists, and — with `--deep` — does the
same for the package's AUR-only dependencies. It builds and installs
nothing.

> **Read this first — what this tool is, and is not.**
>
> - **Heuristic screening, not a verdict of safety.** It flags known
>   patterns of past incident classes and structural red flags; it cannot
>   prove a package safe, and it is not a substitute for reading the
>   package. Concretely:
>   - a `clean` verdict means *"nothing we know how to flag fired"* — it
>     is not a statement that the package is safe;
>   - a `reject` verdict means *"the current AUR revision carries a
>     strong indicator"* — it is a statement about the package as it
>     exists in the AUR, **not** about your already-installed copy or
>     your system. Whether an already-installed package compromised your
>     system is a different question with its own process
>     ([RUNBOOK.md](RUNBOOK.md) §5).
> - **Provided as-is, at your own risk.** aurvet is community tooling,
>   not security software under maintenance: no warranty of any kind,
>   express or implied. It may miss threats, misbehave, or change without
>   notice. If you are gating installs on it, read the code — `rules.py`
>   contains every check it performs — and keep the final call yours.
> - What each verdict and exit code means, and what *you* still have to
>   do after a green light: [RUNBOOK.md](RUNBOOK.md).

It is a *pre-install* tool. Post-breach forensics (is my already-installed
system compromised?) is a different question; there are community
post-breach tools for specific incidents (e.g.
[`aur-malware-check`](https://github.com/lenucksi/aur-malware-check) for
the 2026-06 campaign family). Review any such tool and its data yourself
before relying on it.

## What it screens for

For every requested package (and, with `--deep`, its AUR-only dependencies):

1. **Known-bad lists** — cross-references community-maintained campaign
   package lists (fetched from the `aur-malware-check` upstream: the 2026-06
   *aur-infected* campaign incl. the live official HedgeDoc feed, CHAOS RAT
   2025, Russian spam, plus whatever that upstream declares). Exact name
   match on the package as it exists in the AUR today ⇒ `REJECT` — a
   statement about that revision, not about any copy you already
   installed. (These lists are third-party data; trust them accordingly.)
2. **Content heuristics** — the PKGBUILD and every install script are fetched
   from `aur.archlinux.org` itself and scanned for:
   - `curl|sh` / downloaded-file execution / `eval $(curl …)` (BLOCK)
   - base64 obfuscated payloads (BLOCK / WARN)
   - known-malicious JS packages installed at build time — the generalized
     2026-06 vector (`npm install atomic-lockfile`, `bun install js-digest`, …)
   - non-TLS (`http://`) sources, missing/incomplete checksums
   - untrusted file-host/shortener URLs (pastebin, 0x0.st, ngrok, …)
   - root-acting statements in any script: `systemctl enable`, `crontab`,
     `useradd`, writes to `/etc`, shell rc files, `ld.so.preload`, setuid
     chmod (the 2026-06 persistence toolkit, generalized)
   - `install=` scripts (always surfaced for your reading)
   - floating VCS sources / `noextract` prebuilt binaries (context)
3. **Naming / provenance** — orphan packages, out-of-date flags,
   shadowing/conflicting with official repository package names, names
   one edit away from an official package (typosquats).
4. **Dependency graph** — the full `depends` + `makedepends` tree is
   resolved; AUR helpers install AUR-only dependencies *without* showing
   them to you, so each gets at least a list check, and a malicious
   dependency ⇒ `REJECT` of the parent.
5. **Cleared-state tracking** — `--clear` records exactly what you vetted
   (per-file SHA-256, mirror commit, committers). Later runs — or `--watch`
   — diff the package against that state: unified diffs of every changed
   file, new commits, and new committers since you cleared it. The update
   policy built on this is documented in
   [RUNBOOK.md](RUNBOOK.md) §5.

**What it does *not* check** — the gaps, before you lean on a `clean`:

- the *contents of the source tarballs*. It reads the PKGBUILD, install
  scripts, and the *declared* source URLs — not the code inside the
  sources. A malicious upstream release of a legitimate project (the
  xz/uuidd class) needs the source-verification step in RUNBOOK §3.
- anything that only becomes visible at *build or run time*: what a
  bundled build system or a fetched dependency actually does on your
  machine. That is what the sandboxed build path (RUNBOOK §4) is for.
- dependencies that live in the *official repos*. Those are treated as a
  trusted layer built under Arch CI review; the checks stop at the AUR
  boundary.
- *anything outside the pattern net*. A malicious package that trips no
  heuristic reads `clean`. That is the fundamental limit of pre-install
  tooling, including this one.

**It never builds and never installs anything.** All it does is GET
requests to `aur.archlinux.org` (metadata + snapshots), the
`archlinux/aur` GitHub mirror (commit history and past file contents only),
and the community campaign lists (item 1 above). Its own input channel is
treated as part of the trust boundary: TLS is verified, non-http(s)
schemes are refused, redirects are allowed only on the same host and never
downgrading to `http://` (a policy violation aborts loudly instead of
following or silently serving a cache), responses are size-capped, and all
server-derived text is stripped of ANSI/control sequences before it is
printed, so a hostile package cannot manipulate your terminal inside the
report. Local side effects: a cache dir (`~/.cache/aurvet/`) and an
opt-in state file (`~/.config/aurvet/state.json`).

## Install & use

Python ≥ 3.10, standard library only. Run it from your checkout of the
repository (or put the checkout on your `PYTHONPATH`; `pip install .` into a
venv also works):

```sh
python3 -m aurvet --no-color yay              # one-off check
python3 -m aurvet --deep altair               # recurse into AUR deps
python3 -m aurvet --clear yay                 # record "I reviewed this" state
python3 -m aurvet --watch                     # re-check all cleared packages
python3 -m aurvet -j yay > report.json        # machine-readable
```

Exit codes (Nagios-style, so they chain in scripts): `0` clean — no
heuristic fired (not "proven safe"); `1` review — a human read is
required before installing; `2` reject — strong indicator, do not install
without hand-reading the flagged lines; `3` error — fetch or usage
failure, not a safety statement. What to do with each verdict:
[RUNBOOK.md](RUNBOOK.md) §2.

Run `python3 -m aurvet --help` for all options. For the full process —
what each verdict means, how to work through `review` findings, how to
build in a sandboxed Tier 2 pass, incident response — read
[RUNBOOK.md](RUNBOOK.md).

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

Fully offline: canned AUR responses and fixture PKGBUILDs, no network.

## Layout

```
aurvet/
├── __main__.py   CLI
├── aur.py        AUR RPC + snapshots (aur.archlinux.org); history (GitHub mirror)
├── lists.py      known-bad campaign lists (aur-malware-check upstream)
├── pkgbuild.py   PKGBUILD parser
├── rules.py      static heuristic rules
├── deps.py       dependency graph + official-repo membership
├── state.py      cleared-state bookkeeping
├── report.py     verdicts + rendering
├── verify.py     orchestration
└── http.py       stdlib GET with ETag cache + retry
```
