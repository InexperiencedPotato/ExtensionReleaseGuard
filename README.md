# ExtensionRelease Guard – Phase 1

This repository contains the **Phase 1** of the ExtensionRelease Guard
project.  The goal of Phase 1 is to provide a *safe* ZIP inspector that
examines a Chrome‑extension ZIP archive without extracting or executing
any of its contents.

## Features (Phase 1)

* Enumerate archive entries using :class:`zipfile.ZipFile`.
* Detect malformed archives (raises an error on ``zipfile.BadZipFile``).
* Flag **absolute paths** or **path‑traversal** entry names.
* Detect **duplicate entry names**.
* Enforce limits on:
  - Maximum entry count (`MAX_ENTRIES = 1000`).
  - Maximum total uncompressed size (`MAX_UNCOMPRESSED_SIZE = 50 MiB`).
* Return structured results with three categories:
  - ``errors`` – critical problems.
  - ``warnings`` – suspicious or non‑fatal issues.
  - ``info`` – informational notes.

All logic resides in :mod:`extension_guard.zip_inspector`.

## Requirements

* Python **3.12** or newer.
* No external runtime dependencies.

## Running the Tests

The test suite uses the standard library ``unittest`` and can be run with
the following command from the project root:

```bash
python -m unittest discover -s tests
```

All Phase 1 tests should pass.

---

Future phases will add manifest validation, artifact detection, and a
Tkinter GUI.  Those are not part of this release.
