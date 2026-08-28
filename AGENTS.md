# OPTICLab Publication Repository — Scope Warning

This directory is an **independent publication repository**, not a subdirectory of the OPTIC application repository for Git purposes.

- Repository root: `C:\Users\Home\OPTIC\opticlab`
- Remote: `https://github.com/RubiksTwist/opticLab.git`
- Public site: `https://opticlab.net/`
- Purpose: static pages, public release metadata, public schema snapshot, and publication assets.
- Canonical application source lives one level up in `C:\Users\Home\OPTIC` and is tracked by a different Git repository.
- `schema.sql` mirrors `..\src\optic\database\schema.sql` only when deliberately synchronized for a public release.

Before staging or committing, run `git status --short --branch` from this directory and preserve unrelated article, release, and carousel work. A commit here may deploy the public site when pushed to `main`; it does not include application-repository changes.
