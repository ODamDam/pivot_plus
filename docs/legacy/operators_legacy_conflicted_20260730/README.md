# Conflicted Legacy Operators

These three files were imported from the frozen data-pipeline repository.

They contained unresolved Git conflict markers or invalid Python syntax and
were located under `src/operators_legacy/`. Repository-wide reference checks
confirmed that the active pipeline and tests use the corresponding operators
under `src/operators/`, not these legacy files.

The files were moved without changing their bytes and renamed from `.py` to
`.py.txt` so that Python import discovery and `compileall` do not treat them as
executable modules.

The exact original versions remain available from:

- Tag: `pre-monorepo-data-pipeline-20260730`
- Commit: `adef409ccba5c192b037b41a96e12c7fcca61c52`
