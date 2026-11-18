# URD proposal: npm package version dataset

This project builds a labelled dataset of npm package versions, then lets
a team share it through a central server that cannot read the sensitive
parts.

It is split into two folders that are run separately:

| Folder | What it does |
|---|---|
| `make_dataset/` | collects npm package versions, labels them and cleans the result |
| `secure_share/` | the server and the client: protects the cleaned dataset and shares it within a team |

The only link between them is one file: `secure_share/` reads the cleaned
dataset that `make_dataset/` wrote. Neither imports the other's code.

The server's scorer is a **placeholder** made of hand-written rules. There
is no trained detector in this project yet.

## Read this before running

- **The default run is safe and offline.** `make_dataset/main.py` uses a
  synthetic dataset: made-up packages that imitate known attacks. They
  contain no malware, nothing is downloaded, and no package file is written
  to disk.
- **The real-data mode downloads packages that had malicious releases**
  (for example `node-ipc`). The collector never installs or runs them, but
  antivirus software may still raise an alert or block a download. Only
  switch to it if you accept that.
- **No package code is ever executed, in either mode.** Tarballs are read
  as text, in memory. A built-in guard stops the run with a
  `ScanSafetyError` if anything tries to write package content to disk,
  start a program, or run code while a tarball is open.
- **Never run `npm install` on any package listed in this project.**
- **Private keys are never printed, logged or committed.** Clients keep
  theirs in the user folder, outside the project, and the server's key
  files are ignored by git.

## Setup

Python 3.12 was used. From the project root, create the environment and
install everything into it (PowerShell):

```
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\Activate.ps1
```

In VS Code, choose `.venv` as the interpreter. The commands below assume
the environment is activated.

---

# Part 1: `make_dataset/`

## Running

```
cd make_dataset
python main.py
```

The mode is set by one line at the top of `main.py`:

| `USE_SYNTHETIC` | Data | Network use | Output folder |
|---|---|---|---|
| `True` (default) | 9 synthetic packages, 67 versions | none | `make_dataset/outputs/synthetic/` |
| `False` | 7 real npm packages, about 790 versions | npm registry, OSV, GitHub | `make_dataset/outputs/original/` |

### Before using real-data mode

- The first run downloads every version's tarball and can take several
  minutes. Results are saved in `make_dataset/cache/`, so later runs are fast.
- GitHub allows 60 anonymous requests an hour. To raise that to 5000, save
  a personal access token in Windows Credential Manager under service
  `URD_proposal`, name `GITHUB_TOKEN`:

  ```
  python -c "import keyring; keyring.set_password('URD_proposal', 'GITHUB_TOKEN', 'your-token')"
  ```

- A version that cannot be downloaded or verified is reported as
  "could not scan" and its scan columns are left empty. The run continues.

## Output files

Each output folder holds the same three files:

| File | Contents |
|---|---|
| `npm_versions_with_publishers.csv` | every version, all columns |
| `github_publishers.csv` | one row per publisher |
| `npm_versions_clean.csv` | versions older than 5 years removed; those older than 4 years have `stale = True` |

`outputs/` and `cache/` are ignored by git.

## Columns

**From the npm registry**

| Column | Meaning |
|---|---|
| `package`, `version`, `published` | which release, and when it was published |
| `publisher` | npm account that published it |
| `maintainers` | npm accounts listed as maintainers at that version |
| `n_deps` | number of dependencies |
| `has_preinstall`, `has_install`, `has_postinstall` | whether that install-time script exists |
| `install_script_text` | the text of those scripts, joined by newlines |
| `tarball`, `shasum`, `integrity` | download address and published hashes |
| `attestations` | provenance attestation, when present |
| `npm_signature` | the registry's own signature |
| `git_head`, `repository` | commit and repository the release claims to come from |

**Compared with the previous version**

The previous version is the highest lower version number that was already
published, so 4.21.3 is compared with 4.21.2 even if 5.1.0 came out in
between. These are empty for a package's first version.

| Column | Meaning |
|---|---|
| `prev_version`, `hours_since_prev` | which version it was compared with, and the time gap |
| `publisher_changed` | a different account published this version |
| `maintainer_added` | a maintainer is listed who was not there before |
| `deps_added` | dependencies that are new in this version |
| `install_script_added` | this version has an install-time script and the previous one did not |

**From scanning the tarball's JavaScript files**

| Column | True when the text mentions |
|---|---|
| `uses_child_process` | `child_process` |
| `uses_eval` | `eval(` or `new Function(` |
| `uses_network` | `http`, `https`, `net`, `dns`, `fetch`, `axios` and similar |
| `reads_env_or_secrets` | `process.env`, `.ssh`, `.npmrc`, `.env`, wallet files |

This is a plain text search. It also matches comments and strings, and it
will miss obfuscated code.

**Publisher profile**

`found_on_github`, `github_url`, `real_name`, `company`, `location`,
`public_repos`, `followers`, `github_created`, `n_packages`.

**Labels**

| Column | Meaning |
|---|---|
| `label` | `malicious`, `benign` or `unknown` |
| `label_source` | where the label came from |

## How labels are assigned

**Synthetic mode.** Every version has an exact label, with a source such
as `synthetic:account_takeover` or `synthetic:benign`.

**Real-data mode**, in three tiers:

1. **Known malicious, by hand.** Listed in
   `make_dataset/collectors/hand_labels.csv`, with version numbers taken
   from the OSV or GitHub advisory. The source is the advisory ID.
2. **Assumed benign.** A version more than 90 days old, of a package with
   at least 100,000 weekly downloads, with no malware advisory. The source
   is `assumed_benign_aged`. This means "nobody has reported it", not
   "proven safe".
3. **Unknown.** Everything else, mainly recent versions.

## The synthetic packages

| Package | Imitates | Malicious versions |
|---|---|---|
| `synth-colorize` | account takeover (chalk, 2025) | 3.4.1 |
| `synth-ua-detect` | hijacked account adds an install script (ua-parser-js, 2021) | 0.7.30, 0.8.1, 1.0.1 |
| `synth-stream-utils` | new maintainer adds a bad dependency (event-stream, 2018) | 3.3.6 |
| `synth-flatmap` | the bad dependency itself | 0.1.1 |
| `synth-expresss-helper` | typosquat from a brand-new account | 1.0.0, 1.0.1 |
| `synth-ipc-bus` | maintainer sabotage (node-ipc, 2022) | 10.1.1, 10.1.2 |
| `synth-native-build`, `synth-http-kit`, `synth-tiny-util` | benign controls | none |

A "malicious" synthetic version only contains comments that mention what
real attacks do, so the scanner's patterns match. The benign controls
include legitimate uses of the same signals (an install script, a real
maintainer handover, a quick hotfix), so no single column separates the
two groups.

---

# Part 2: `secure_share/`

A team shares the dataset through a central server. The server stores the
data and passes it to team members, but cannot read the sensitive parts.

Everything about this part, including how each step works and which
lecture it comes from, is in [secure_share/README.md](secure_share/README.md).

## Running it

Run `make_dataset/main.py` first, then from `secure_share/`:

Terminal 1, the server:

```
python server.py keygen
python server.py run
```

Terminal 2, the clients:

```
python client.py alice keygen
python client.py alice register
python client.py bob keygen
python client.py bob register

python client.py alice create-team blue
python client.py alice invite bob
python client.py bob join blue

python client.py alice send
python client.py bob fetch
```

Or run the whole flow at once with `.\demo.ps1`.

## Tests

```
cd secure_share
python -m pytest test_system.py -q
```

---

# Project layout

| Path | Purpose |
|---|---|
| `make_dataset/main.py` | runs collect and clean, writes the output files |
| `make_dataset/collectors/` | builds one row per package version, scans tarballs, assigns labels |
| `make_dataset/cleaning/` | stale flag and 5-year filter |
| `make_dataset/synthetic/` | the synthetic packages |
| `make_dataset/outputs/` | generated datasets (ignored by git) |
| `secure_share/crypto.py` | RSA signatures, Diffie-Hellman, AES-GCM, HMAC |
| `secure_share/protect.py` | protects one dataset row before it is sent |
| `secure_share/server.py` | the central server |
| `secure_share/client.py` | the command-line client |
| `secure_share/test_system.py` | the tests |
| `secure_share/demo.ps1` | runs the whole flow once |
| `docs/how-it-works.txt` | a plain-language description of the flow |
