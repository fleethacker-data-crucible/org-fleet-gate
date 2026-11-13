# fleet-gate

The org-wide PR check for `fleethacker-data-crucible`. It automates the mechanical part of the
merge gate; reviewers still read the change. Windows PowerShell 5.1 only, nothing installed on
the runner, MIT license.

## What it checks

| Check | Scope | FAIL when |
|---|---|---|
| `sensitive` | added lines (merge-base..head) + gitleaks `--redact` over the same range | military hosts, handling or classification markings, distribution statements, private addresses; any gitleaks secret. Export-control words and CIDR ranges WARN |
| `endpoints` | whole repo | a military or service-branch host appears outside test/fixture paths |
| `binaries` | changed files | a new file over 5 MB, an archive/model/WASM/package/executable extension, or executable magic bytes. The message says to publish them as GitHub Release assets on a vN.N.0 release |
| `workflows` | changed workflows (safety) + all workflows (shells) | pull_request_target pwn-request checkouts, untrusted context inside `run:`; a step on a Windows runner whose shell is not `powershell` or that has no `shell:` (jobs on `ubuntu-*`/`linux` runners are skipped, so bash, sh and python are fine there; for an expression `runs-on` see [Runner OS](#runner-os)); a macOS runner |
| `house` | repo + added lines | no MIT `LICENSE`; a retired tool name in an added line, including inside identifiers such as environment variables, function names and item names; a listener bound to anything but loopback. A second scan, `retired-name-repo`, checks every tracked text file (not `CHANGELOG.md`, `docs/reports/` or `ci/fleet-gate/data/`) and reports at the severity in `data/retired-names-repo.setting` |
| `contrast` | CSS + HTML, no browser | a text color against its resolved background is below 4.5:1 (3:1 for large text) in any theme. FAIL when the CSS, its token file or the background's file changed; pre-existing problems WARN. Unresolved pairs WARN |
| `security` | changed paths + added code | never FAILs: WARNs "needs Researcher verdict" and sets the `needs_researcher` and `security_categories` outputs |

Each check is a separate function in `lib/`; the patterns live in `data/` (one letter of each
literal word is bracketed so the data never matches itself).

The output is a PASS/WARN/FAIL table, then `path:line` findings, then (on a binaries FAIL) the
Large assets help. In Actions it also writes annotations, the job summary and step outputs. The
script exits 1 on any FAIL.

## Runner OS

The `workflows` shell rule needs each job's runner OS. fleet-gate reads it from the literal
labels in `runs-on` (labels aren't case-sensitive):

- **Windows:** any label with `windows`, `win10`, `win11`, `headless` or `powershell51`. Windows
  wins when both Windows and Linux labels appear.
- **Linux:** any label with `ubuntu` or `linux` and no Windows label, for example
  `ubuntu-latest` or `[self-hosted, Linux, X64]`.
- **Expression** (`${{ ... }}`): Linux only when no literal in it names Windows or macOS **and**
  either its literal fallback names Linux, or all of its literal labels do (`self-hosted`, `x64`,
  `x86`, `arm`, `arm64` and `docker` fit any OS). JSON literals inside `fromJSON('...')` count
  as labels. This lets a job move between GitHub-hosted and self-hosted Linux runners through an
  Actions variable:

  ```yaml
  runs-on: ${{ vars.MY_RUNS_ON && fromJSON(vars.MY_RUNS_ON) || 'ubuntu-latest' }}   # Linux
  runs-on: ${{ fromJSON('["self-hosted", "linux", "docker"]') }}                    # Linux
  runs-on: ${{ vars.MY_RUNS_ON && fromJSON(vars.MY_RUNS_ON) || 'windows-latest' }}  # Windows rule
  runs-on: ${{ matrix.os }}                                                         # Windows rule (no literals)
  runs-on: ${{ inputs.runner || 'ubuntu-latest' }}                                  # Linux (fallback)
  runs-on: ${{ cond && 'ubuntu-latest' || 'windows-latest' }}                       # Windows rule (mixed)
  ```

  The variable's value isn't known to the gate. Set it (an admin, at org or repo level; a PR
  can't) only to labels of the same OS as the fallback.
- **Anything else** (no literals, such as `${{ matrix.runner }}` or `${{ inputs.runner }}` with no
  Linux literal fallback; unknown labels; mixed) is checked as Windows: every `run:` step
  needs `shell: powershell` (Windows PowerShell 5.1).

A trailing `# comment` on the `runs-on:` line is ignored.

## Retired-name scan of the whole repo

The `retired-name` check only reads lines a PR adds. `retired-name-repo` reads every tracked text file with the same patterns (`data/retired-names.tsv`) and the same allowlist, so names that are already in the code show up too.

Its severity is one line in `data/retired-names-repo.setting`: `WARN` (the default) lists the hits without failing the gate, `FAIL` blocks the PR. Change it once the repos are clean. Only `FAIL`-level pattern hits are re-rated; hits in test and fixture paths stay `WARN`. Findings are listed as `house/retired-name-repo`.

Retired names in identifiers are caught by the patterns that are not word-bounded (an underscore or a camel-case join next to the name). The data file brackets one letter of each pattern so it does not match itself.

## Allowlist

The static contrast check resolves linked stylesheets and local CSS imports per HTML page, keeps `data-skin` variants separate, and recognizes root `.light` / `.dark` theme classes. Direct-child selectors are matched as direct children, not arbitrary descendants. Fully transparent backing text has no visible glyphs; partially transparent text is still composited and checked. Build templates with unresolved stylesheet links retain the repository CSS fallback. Unreferenced stylesheets are still scanned. These context rules do not change the 4.5:1 / 3:1 thresholds or suppress real findings.

`.fleet-gate/allowlist.txt` in the checked repo, merged with `data/allowlist.default.txt`
(org-wide). One entry per line, `<kind>:<regex>`, with an optional trailing `  # why`:

```
path:^tests/fixtures/      # whole path ignored (binaries: FAIL becomes WARN)
match:^build\.internal\.   # the matched text
line:sample-config         # the whole added line
rule:generic-api-key       # a gitleaks rule id
fingerprint:<gitleaks fingerprint>
retired:^scripts/muse/    # repo path; retired-name findings only
```

Built-in ignores: obvious fakes (example, dummy, placeholder ...) and test/fixture paths, where
a FAIL becomes a WARN.

## Repo policy

`.fleet-gate/policy.txt` in the checked repo, read from the **PR base commit** (never the head, so a PR
cannot turn it on for itself; a full scan reads the working tree). One setting:

```
visibility: private-permanent  # approved by @seakintruth 2026-11-01
```

Only the repo owner approves it, for repos that will never be public. It turns the publication-only
`sensitive` kinds (`private-ip`, and any `internal-host`, `private-path` or `personal-email` pattern) from
FAIL into WARN with a note. Secrets and gitleaks, military hosts, handling and classification markings,
distribution statements, `endpoints`, `workflows`, `binaries`, listeners, retired names and `security`
routing are unchanged. If the setting is on and the Actions event payload says the repo is public, the
gate FAILs (`house/policy-public`); when visibility is unknown (local runs) nothing extra happens.
The fallback reviewer reads the same base-commit file and tells its prompt the repo is private-permanent.
`-PolicyPath` points the script at a copy (the reviewer passes its base-commit copy).

## Browser accessibility scan (elevated runner only, off by default)

The job is skipped, with a "disabled pending admin settings" notice, unless the Actions variable
`FLEET_GATE_BROWSER` is `on`. An admin sets it at org or repo level. In a called workflow `vars`
comes from the caller's repo and the org, and a PR cannot set it.

`browser/` runs axe-core 4.14.0 (pinned npm tarball, SHA256-checked, extracted with `tar.exe`)
plus a computed-contrast walk in headless Edge or Chrome, driven over the DevTools protocol from
PowerShell 5.1 with no Node. Pages come from `.fleet-gate/pages.txt` (one repo path per line) or
the tracked `*.html` files. Each entry must be a repo-relative path to a file: rooted or absolute
paths, paths that resolve outside the repo (`..\`) and anything under a symlink or junction are
skipped with a warning. Pages are served from one listener bound to `127.0.0.1` that answers GET
only, refuses other Host headers and refuses files behind reparse points. The browser runs with
`--proxy-server=127.0.0.1:9` (a dead port) and `--proxy-bypass-list=<-loopback>;127.0.0.1:<scan port>`
plus `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`, so the only origin a page can
reach is the scan server (not other loopback ports, not the network). Both themes (`data-theme`
dark and light) are scanned.

The job runs on `[self-hosted, Windows, X64, win11]` only when the PR author is one of the six
team members (agathokakological, BenKenBoy, cyprionceo, nullusperfectus, seakintruth,
sun-of-anton) AND the head branch is in the same repo or in a fork owned by that author. Anyone
else, a member's PR from somebody else's fork, and `merge_group` runs get a notice that it was
skipped. The list lives in the reusable workflow (and `browser/BrowserA11y.psm1`, kept equal by
a test), not in the callers. The static `contrast` check is the always-on baseline.

## Use it in a repo

Call this reusable workflow from `.github/workflows/fleet-gate.yml` in the caller repository.
Set `permissions: contents: read` and pin the full commit SHA:

```yaml
jobs:
  fleet-gate:
    uses: fleethacker-data-crucible/org-fleet-gate/.github/workflows/fleet-gate.yml@<sha>
```

## Run it locally

```powershell
powershell -NoProfile -File ci\fleet-gate\Invoke-FleetGate.ps1 -RepoPath C:\src\Bowerbird -BaseSha origin/main
powershell -NoProfile -File ci\fleet-gate\Invoke-FleetGate.ps1 -RepoPath C:\src\Bowerbird   # full scan
powershell -NoProfile -File ci\fleet-gate\tests\Run-Tests.ps1                                 # Pester 5.7.1
```

`-SkipGitleaks` skips the download; `-GitleaksPath` uses a binary you already verified.

## Pins

- gitleaks 8.30.1: `gitleaks_8.30.1_windows_x64.zip` SHA256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`
- axe-core 4.14.0: `axe-core-4.14.0.tgz` SHA256 `2277b0a3ef47af9b52497faa3e71598e86e0a0e5e6eb295207a5657ede4709af`
- actions/checkout v6.0.3: `df4cb1c069e1874edd31b4311f1884172cec0e10`

### Composite actions in the reusable workflow

`.github/workflows/fleet-gate.yml` references this repo's actions with `$/`, which resolves to
this repository at the same commit as the workflow file:

- job `gate`, step `id: gate`: `uses: $/ci/fleet-gate`
- job `browser-a11y`, second step: `uses: $/ci/fleet-gate/browser`

The `actions/checkout` pin does not change. Callers pin `fleet-gate.yml` at the org-fleet-gate
commit that contains the workflow.
