# AUR Install-Safety Runbook

This is the process for deciding whether an AUR package is safe to install,
and for catching the changes that undermine a past "yes" across updates.
`aurvet` automates the cheap, repetitive parts; the human steps below are
what make the decision.

> **No step in this runbook guarantees safety.** `aurvet` is a *heuristic*
> screening tool: it flags known patterns of past incident classes and
> structural red flags; it cannot prove a package safe, and packages can
> change after you vet them. Each tier below reduces risk; the residual
> risk is yours to accept, package by package. Treat every aid in this
> document — `aurvet`, the campaign lists, other community tools — as an
> input to your own judgment, not an authority.

```
Tier 0  automated fast pass      aurvet (this tool)
Tier 1  human review             read what Tier 0 flagged
Tier 2  sandboxed build          for anything where build-time trust matters
Tier 3  ongoing policy           updates, incident feeds, response
```

---

## 1. Threat model (what we're defending against)

| ID | Vector | How it looks in a package | History |
|----|--------|---------------------------|---------|
| V1 | Malicious build step | `npm install atomic-lockfile` in `build()`, any rogue download/compile at build time | 2026-06 AUR infection |
| V2 | Install script | `pkginstall` pre/post hooks run as **root** during `makepkg -si`, shown to no one by most helpers | recurring |
| V3 | Rogue source tarball | missing/wrong `sha256sums`, third-party mirrors, `noextract` prebuilt binaries, dead domains re-registered | recurring |
| V4 | Upstream compromise | legitimate `source=` but the upstream release itself is malicious (xz/uuidd-style, via git sources) | general supply chain |
| V5 | Dependency attacks | AUR-only `depends`/`makedepends` that AUR helpers build & install *unreviewed*; typosquats; `provides`/`conflicts` shadowing an official package name | aurorakitty (2018), recurring |
| V6 | Provenance / maintainer | adoption by a new or impersonated maintainer, account takeover, version jumps — the *enabler* of the 2026-06 mass adoption | CHAOS RAT (2025), 2026-06 |
| V7 | Post-install persistence | systemd units, cron, XDG autostart, `ld.so.preload`, rc-file edits, eBPF maps | 2026-06, CHAOS RAT |
| V8 | Toolchain trust | building as root, unvetted third-party helpers, stale helper caches | structural |

Note the shape of the 2026-06 incident specifically: ~1600 packages
**adopted by spam accounts** and updated with an injected
`npm install atomic-lockfile` / `bun install js-digest` build step delivering
an infostealer + eBPF rootkit. Every row of this table has precedent;
Tier 0 is a heuristic net, not a proof.

---

## 2. Tier 0 — the automated pass (`aurvet`)

```sh
aurvet PACKAGE [PACKAGE ...]
```

### Verdicts

| Verdict | Exit code | Meaning |
|---------|-----------|---------|
| `reject` | 2 | Strong indicator (known-bad list match, `curl\|sh`, known-malicious JS dep, malicious dependency). **Do not install** without a hand-read of the exact flagged line, and even then the answer is almost certainly no. |
| `review` | 1 | One or more warnings (setuid chmod, rc-file write, install script, unhashed source, typosquat, orphan+…). A human Tier 1 pass is required. |
| `clean` | 0 | No heuristic fired — **not** "proved safe". Still an unvetted third-party package; do the Tier 1 read before installing anything critical, unusual, or low-vote. |
| `error` | 3 | Fetch failure / unresolvable name. Not a safety statement — fix and re-run. |

**A `reject` says what the AUR revision is — not what your system is.**
The verdict points at the package as it exists in the AUR *now*. If the
flagged revision is the one your installed copy was built from, your
system must be treated as suspect: work §5.4. If you built from an older
revision you had previously cleared (the state file records which mirror
commit that was), a newly-flagged revision does not by itself mean your
installed copy is compromised — but do not update to the flagged
revision, and any doubt about system behavior takes you to §5.4 anyway.
Symmetrically, a `clean` on the AUR revision never means the installed
copy was safe, only that our net caught nothing today.

### Standard flags

- `--deep` — full-vet AUR-only dependencies recursively (default: list check +
  lite metadata only, which is where the 2026-06 dependency-confusion-style
  risk lives).
- `--clear` — after you have *read* the report, record the current state as
  cleared (per-file sha256, mirror commit, committer set, verdict).
- `--watch` — re-vet every cleared package; prints changed files with unified
  diffs, new commits, and new committers since cleared.
- `-j` / `--json` — machine-readable.
- `--no-refresh` — trust cached lists/metadata (offline-ish use).
- `--state PATH` — alternate state file.

### Exit codes and scripting

Chain it into your install flow:

```sh
aurvet --deep <pkg> && yay -S <pkg>   # only build when at worst... (see note)
```

Note: `review` (exit 1) blocks this chain, which is the point. If you want
review to be interactive rather than blocking, handle rc=1 explicitly.

**Optional install wrapper** (drop in `~/.bashrc`/`~/.zshrc`): vets before
calling your AUR helper, so a blocking verdict never reaches `makepkg`:

```sh
vetted-install() {
  local pkg; for p in "$@"; do :; done
  shift  # (keep it simple: one package at a time)
  local rc=0
  aurvet --deep "$@" || rc=$?
  case $rc in
    0) aurvet --clear "$@" ;;
    1) echo "aurvet: REVIEW needed. Build anyway? [y/N]"
       read ans; case $ans in y|Y) aurvet --clear "$@" ;; *) return 1;; esac ;;
    *) echo "aurvet: not installing ($rc)"; return $rc ;;
  esac
  yay -S --noconfirm "${@: -1}"   # adapt to your helper
}
```

---

## 3. Tier 1 — human review (the part the tool does not do for you)

Tier 0 only sorts the work; **no verdict exempts you from this pass** —
`clean` is a "read from here" pointer, not a read-for-you certificate.
For anything you actually care about, you still read the package. With
`review` findings, work through them top-down (BLOCK > WARN > INFO):

1. **Read the flagged line in context.** Fetch the package the normal way
   (`git clone https://aur.archlinux.org/<pkg>.git` or the snapshot tarball)
   and open the file at the reported line. A heuristic is a pointer, not a
   verdict: `systemctl enable x.service` in a desktop app's install script is
   expected; the same line in a "text utility" is not.
2. **Understand what the build does with the network.** Legitimate downloads:
   declared `source=` entries, plus well-known fetches in `pkgver()` probing
   upstream release pages. Anything else (random hosts, JS package installs,
   piped shells) needs a reason. The 2026-06 payload hid in `build()` precisely
   because "the build downloads stuff" is normal-looking.
3. **Verify sources against upstream.** `url=` → the actual project. Check the
   tarball/commit exists upstream, the checksum matches upstream's, the
   version is plausible, and the project has no open advisories
   (GitHub Security Advisories, OSV.dev) — this is your V4 defense.
4. **Check provenance.** AUR page: maintainer since when? Recent commits —
   same committer as always, or a brand-new account? Large diffs vs your last
   build? `aurvet --watch` shows all of this mechanically for cleared
   packages; for new packages use the git log of the cloned package repo.
   Low vote count + fresh adoption + large diff = slow down.
5. **Read the install script** (or note its absence; most AUR packages
   shouldn't have one). It runs as root during `makepkg -si`.
6. **Decide.** Install, or install with eyes open (build it, inspect the
   `.pkg` before `pacman -U` — `bsdtar -t`/`-x` or build in a chroot), or
   skip. Your "why is this fine" for any WARN should be one sentence you'd
   say to a colleague.

---

## 4. Tier 2 — sandboxed build (when build-time trust matters)

Use this for: any `review` that you can't dismiss cleanly, prebuilt
binaries (`noextract`), packages doing unusual build-time networking, and
anything you simply don't trust enough to build on your main system.

### 4.1 Isolate

Fresh VM (preferred) or a clean chroot / container with the same arch.
Minimum: no access to your real `~/.ssh`, keychain, browser profiles, or
CI secrets. The 2026-06 infostealer specifically harvests developer
credentials and CI secrets — the sandbox's job is to make those absent.

### 4.2 Egress allowlist

Legitimate AUR builds only need to reach the URLs in `source=` (and the
registry/CDN those URLs live on). Enforce it and watch:

- Proxy the build (`mitmproxy` or `tinyproxy`) so every connection is
  logged; alert on any host outside the declared source domains, or
- `nftables` allowlist on the sandbox:
  ```sh
  nft add table inet aurvet
  nft add chain inet aurvet egress '{ type filter hook egress priority 0 ; policy drop ; }'
  nft add rule inet aurvet egress ct state established accept
  nft add rule inet aurvet egress tcp dport 53 accept   # adjust for your resolver
  nft add rule inet aurvet egress ip daddr <source-cidr> tcp dport 443 accept
  ```
  Build-time connections to anything else (a JS registry for an unexpected
  package, a pastebin, a raw IP) are your V1/V3 signal.

### 4.3 Inspect the artifact

```sh
# full file inventory
bsdtar -tf <built>.pkg
sha256sum <every payload file>     # compare against what the package claims

# IOC spot-checks from known campaigns
find . -name 'hidden_*'            # eBPF rootkit map names
# any file at unusual paths: ~/.local/bin/sudo, /etc/cron.d/*, autostart dirs
```

### 4.4 Runtime smoke (in the VM)

Install, then run briefly under observation:

```sh
strace -f -e trace=network <app>          # unexpected sockets = flag
systemctl --user list-units --state=running   # new units?
ls ~/.config/autostart /etc/ld.so.preload ~/.bashrc   # persistence?
ls /sys/fs/bpf/                            # unknown BPF maps/programs?
```

Anything the package didn't declare in Tier 0/1: reject.

---

## 5. Tier 3 — ongoing policy (so drift doesn't go unnoticed)

1. **Clear what you install.** After a clean Tier 0/1 pass, `aurvet --clear
   <pkg>`. This is the anchor for all future comparisons.
2. **Watch before updating.** Before any AUR update session:
   ```sh
   aurvet --watch
   ```
   Any changed file gets its diff in front of you; any *new committer* is
   flagged (V6: the adoption/takeover vector is exactly a new committer).
   Read the diff exactly like a human reviewer would — Arch staff's own
   ask during the 2026-06 incident was "review all PKGBUILD and install
   script changes when updating". This is what turns "was clean once"
   into "was it *still* clean now — and if not, here is exactly what
   moved".

   React to two specific outcomes:

   - **A cleared package comes back `reject`** (typically: a new
     campaign-list entry landed for it). That is your early warning
     *about that package*: stop updating it, and if it is installed, go
     to §5.4 and establish which revision you actually built.
   - **A cleared package is `clean` on a watch run** means "nothing our
     net caught since you cleared it" — the same heuristics limit as
     anywhere else, not "still proven safe".
   A daily systemd timer is a good default:
   ```ini
   # ~/.config/systemd/user/aurvet-watch.service
   [Unit]
   Description=aurvet cleared-package watch

   [Service]
   Type=oneshot
   WorkingDirectory=%h/path/to/your/aur-vet-checkout   # adjust to wherever the repo lives
   ExecStart=/usr/bin/python3 -m aurvet --watch --no-color
   ```
   ```ini
   # ~/.config/systemd/user/aurvet-watch.timer
   [Unit]
   Description=Run aurvet --watch daily

   [Timer]
   OnCalendar=daily
   Persistent=true

   [Install]
   WantedBy=timers.target
   ```
   (Wire your notification of choice to the non-zero exit.)
3. **Watch the feeds.** Subscribe to:
   - `aur-general` mailing list (lists.archlinux.org) — security warnings live here
   - Arch security tracker (security.archlinux.org)
   - the campaign-list upstream this tool refreshes from (the community
     repo `aur-malware-check` and its Discussions; new campaigns get
     declared there and `aurvet` picks them up automatically via
     `campaigns.json`)
4. **Incident response** (if you suspect you built one of these, or a
   cleared package just came back `reject`):

   Up front: **aurvet is a pre-install tool.** It tells you what the AUR
   revision looks like *now*; it cannot tell you whether your system is
   compromised. That conclusion comes from the steps below, and only
   from them.

   1. **Don't destroy evidence; don't just reboot and hope.** Rebooting
      first discards volatile evidence (live processes, memory state),
      and a persistent implant simply comes back. Decide on rebooting
      *after* step 4.
   2. **Establish which revision you built.** If you used `--clear`,
      the state file records the mirror commit your installed copy was
      tied to; otherwise compare the installed version
      (`pacman -Qi <pkg>`) against the package's AUR revision history
      (the GitHub mirror, or the commit list `aur-vet` shows). Then take
      the matching case:
      - *You built from the flagged revision — or can't rule it out.*
        Your system is suspect. Rotate (step 3) and forensics (step 4)
        assuming the worst until proven otherwise.
      - *You built from a revision predating the flagged change* (e.g.
        you cleared at commit X; the injection landed at Y > X). The new
        bad AUR content does not by itself mean your installed copy is
        compromised — but **still run step 4**. Do not skip it because
        of a date; dates are easy to get wrong.
   3. **Rotate credentials before assuming anything is quiet.** SSH
      keys, git/CI tokens, cloud creds, browser session cookies — the
      2026-06 payload's target was exactly the developer-credential set,
      and if an attacker got in, waiting for signs is the wrong
      strategy.
   4. **Run the post-breach forensics appropriate to the campaign.** For
      the 2026-06 family, e.g. `aur-malware-check --full` — review that
      tool and its lists yourself before running it, and prefer running
      it from a separate trusted machine/media where possible. Check
      systemd units, cron, `~/.local/bin/sudo`, `/sys/fs/bpf/hidden_*`.
   5. **If eBPF rootkit involvement is confirmed, the kernel state is
      untrustworthy — reinstall from trusted media.** No userspace
      cleanup is sufficient.
   6. **Report what you have** (package name, PKGBUILD revision,
      timeline) to `aur-general@lists.archlinux.org` — Arch staff
      explicitly ask for this.
   7. **Then remove the package** (`<helper> -Rns <pkg>`) — *after*, not
      before, the forensics.

---

## 6. Limitations (read once, then stop being surprised)

- **Heuristics, not proofs.** A clean verdict means "nothing in our net
  caught this", not "this is safe". A malicious build that looks clean and
  phones home weeks later defeats *all* pre-install vetting — Tier 3 exists
  because of that gap.
- **Repo dependencies are not deep-inspected.** Official repo packages are
  built by Arch CI under package maintainer + review; we trust the
  repository layer. Our scope is the AUR layer (V5 attacks ride on
  AUR-only deps, which *are* checked).
- **Lists are only as fresh as their upstream.** `aurvet` refreshes
  campaign lists hourly by default and degrades loudly (a note on every
  report) when a list fails to load.
- **The GitHub mirror is history-only.** Content that is ever judged comes
  from `aur.archlinux.org` itself. Mirror commits/files feed "what changed
  and who touched it", never the verdict on current content.
- **Rate limits:** AUR RPC is capped at 4000 req/day/IP; the GitHub API
  60/h unauthenticated. The tool is polite by design (batched metadata,
  one history call per package, ETag caches, immutable history cached
  aggressively) — don't hammer `--watch` on hundreds of packages in a loop.
- **Proxy trust:** the tool honors your proxy environment variables
  (standard urllib behavior). If a MITM proxy whose CA you trust sits in
  the path, the "content came from aur.archlinux.org" guarantee degrades
  to your trust in that proxy; TLS still pins the certificate to the
  hostname.
- **Its own input channel** is auditable and deliberately strict (TLS
  verification, http(s)-only, same-host-only non-downgrading redirects,
  64 MiB response cap, output scrubbing of ANSI/control characters) —
  see `http.py` and `report.scrub`. This protects against a dirty or
  spoofed *endpoint*; it does not make a legitimately served malicious
  PKGBUILD look benign — that is heuristic territory (Tier 0/1).
- **`pacman` DB staleness:** official-name membership uses your local sync
  DB (`pacman -Ssq` / `.desc` files). After a while without `pacman -Sy`,
  shadowing/typosquat checks are slightly stale.

## 7. Rule reference

| Rule | Severity | Fires when |
|------|----------|------------|
| `known-badlist` | BLOCK | package name is in a known campaign list |
| `bad-dependency` | BLOCK | an AUR-only dependency is in a known campaign list |
| `deep-dependency` | BLOCK/WARN | (only with `--deep`) a recursed dependency is rejected / has warnings |
| `known-bad-npm` | BLOCK | build installs a JS package from the campaign IOC list |
| `net-exec` | BLOCK | download piped to a shell, downloaded file executed by a shell, `sh -c $(curl …)`, `eval $(curl …)` |
| `obfuscated-exec` | BLOCK | base64-decoded content piped to a shell / echoed into `base64 -d` |
| `long-base64` | WARN | ≥300-char base64-looking blob in a script |
| `suspicious-host` | WARN | pastebin/shortener/ngrok/file-host domain referenced |
| `insecure-source` | WARN | `http://` (non-TLS) source |
| `missing-hashes` | WARN | fewer `sha256sums` than URL sources (or none) |
| `js-build-dep` | WARN | named JS package installed at build time and not in `makedepends` |
| `root-acts` | WARN | `systemctl enable`, `crontab`, `useradd`/`visudo`, `/etc`/rc-file writes, `ld.so.preload`, setuid chmod, in any script |
| `shadow-official` | WARN | name/`provides`/`conflicts`/`replaces` collides with an official package |
| `typosquat` | WARN | name is one edit away from an official package name |
| `install-script` | INFO | an `install=` file exists (read it) |
| `vcs-floating` | INFO | source floats on a moving branch head |
| `orphan` | INFO | no maintainer |
| `out-of-date` | INFO | flagged out-of-date |
| `new-committer` | WARN | (cleared state) a committer not present at clear time committed |
| `dep-unresolvable` | WARN | dependency resolves in neither repos nor AUR |

Rules live in `aurvet/rules.py` — each is a small, self-contained function;
extend or tune there (and add a test in `tests/test_rules.py`).
