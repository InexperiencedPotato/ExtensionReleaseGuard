# Contributing

Thanks for helping improve ExtensionRelease Guard. Bug reports, feature ideas,
and pull requests are welcome.

## Reporting a problem

Open an issue using the templates. Include the app version (from the release
name), what you expected, what happened, and the exact finding text. **Do not
attach an extension ZIP you are not allowed to share.** A minimal made-up ZIP
that reproduces the problem is ideal.

## Development setup

Python 3.12+ on Windows:

```bash
pip install -e ".[gui]"
python -m unittest discover -s tests
```

GUI tests need a desktop session. One real-world test is skipped unless the
`REAL_EXTENSION_ZIP` environment variable points to a local extension ZIP.

## Pull requests

- Keep changes focused and add or update tests for new behaviour.
- The full test suite must pass; CI runs it on every pull request.
- Do not weaken a validator's severity or message just to make a test pass.
- The tool must stay local: no network access, no extracting archives to disk,
  and no running of extension code.
- By contributing you agree your work is released under the MIT license.

See the [Code of Conduct](CODE_OF_CONDUCT.md).
