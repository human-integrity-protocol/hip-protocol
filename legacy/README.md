# legacy/ — local pre-change snapshots

One folder per session that touches `worker.js`, `index.html`, or `SECURITY-POSTURE.md`.
Each holds the exact files as they were at the last commit *before* that session's edits
(i.e. what was live on Cloudflare at session start). Cloudflare keeps its own deploy history;
this is the local, offline copy. Git `HEAD` at the session's start has the same bytes.

| Folder | Snapshot of | Last live deploy before change |
|---|---|---|
| `pre-S210/` | fcf61fb-era hip-protocol HEAD (b5dbed2) | hip-tier1-worker as deployed S171CC (worker.js 8886 lines) |
| `pre-S210b/` | S210 interim (4c5325f) | S210 interim worker (8904 lines) |
| `pre-S211/` | f5ceee7 | S210b worker (8846 lines) — still live until the S211 deploy |

Convention for future sessions: before editing, `git show HEAD:<file> > legacy/pre-S<N>/<file>`.

S211: snapshot folders are git-ignored (`.gitignore`: `legacy/*`, `!legacy/README.md`). They are byte-identical to git history and this repo's root is served by Cloudflare Pages, so committing them would publish stale `index.html` copies on hipprotocol.org. Only this README is tracked.
