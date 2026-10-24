# Contributing

## AI-generated contributions

Code, tests, issues, pull requests, and documentation generated or assisted
by AI tools are welcome. The bar is the same as for anything else:
it must be correct, and it must be tested.

- **You are the author.** Submitting it makes you responsible for it.
  "The model wrote that" is not an answer to a review question. If you
  can't explain a change, don't submit it.
- **Tests must test something.** Tests that assert nothing, assert on mocks,
  or were adjusted until they pass will be rejected.
- **Issues must be real.** Reproduce the problem before filing. Hallucinated
  APIs, invented CVEs, and unverified "security findings" will be closed
  without discussion.
- **Docs must match the code.** Generated documentation that describes
  behavior the code doesn't have is a bug, not a contribution.
- **Volume is not value.** Bulk-generated PRs and drive-by "cleanup" churn
  may be closed in bulk.
- **Disclosure is optional.** If you want to credit the tool, add a commit
  trailer such as `Assisted-by: <tool/model>`. Nobody is penalized either way.

## Testing

Fast edit loop (about 40-55 s; skips the doc-walkthrough modules listed in
`SLOW` in `tests/conftest.py`):

```sh
uv run --with pytest --with pytest-xdist --with jsonschema --with referencing --with pynacl --with rfc3339-validator --with rfc3986-validator python -m pytest -q -n 6 -m "not slow" tests
```

Before pushing, run the same command without `-m "not slow"` (about 2.5
minutes), plus `ruff check`, `ruff format --check` and
`uv run --with mypy mypy --python-version 3.10 git-vouch`. mypy needs 3.10
as its target version; the code itself still supports Python 3.9. A new doc
walkthrough module must be added to `SLOW`.

## Developer Certificate of Origin

Signing off your commits (`git commit -s`) under the
[Developer Certificate of Origin](https://developercertificate.org/) is
welcome and encouraged, but not required. Submitting a contribution is an
implied `Signed-off-by`: you certify that you wrote it or otherwise have
the right to submit it under this project's license.
