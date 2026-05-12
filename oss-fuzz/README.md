# OSS-Fuzz onboarding

Scaffolding for submitting go-seccure to [OSS-Fuzz](https://google.github.io/oss-fuzz/) —
Google's continuous fuzzing infrastructure for open-source projects with
security-relevant code. Once accepted, OSS-Fuzz runs each of the six
fuzz targets defined in [`fuzz_test.go`](../fuzz_test.go) for hours per
day across many cores. Any crash or panic gets filed as a confidential
issue (90-day disclosure) for the maintainer to fix.

## Files

| File           | Role |
|----------------|------|
| `project.yaml` | OSS-Fuzz project metadata: language, contacts, sanitizers. |
| `Dockerfile`   | Build environment. Clones the latest `main` from this repo at runtime. |
| `build.sh`     | Compiles each `Fuzz*` target into a libFuzzer binary via OSS-Fuzz's `compile_native_go_fuzzer` helper. |

## Onboarding steps

1. Fork [`google/oss-fuzz`](https://github.com/google/oss-fuzz).
2. Copy this entire directory into `projects/go-seccure/` in the fork:

       cp -r oss-fuzz/* /path/to/oss-fuzz-fork/projects/go-seccure/

3. From the OSS-Fuzz repo, smoke-test locally before submitting:

       python infra/helper.py build_image go-seccure
       python infra/helper.py build_fuzzers --sanitizer address go-seccure
       python infra/helper.py check_build go-seccure

   All three should pass.

4. Open a PR against `google/oss-fuzz` titled "Add go-seccure project".
   Mention the homepage and primary-contact email. Approval typically
   takes 1-3 business days.

5. Once merged, OSS-Fuzz starts running the targets within ~24 hours.
   Crash reports land in the `primary_contact` inbox.

## Local reproduction

To reproduce an OSS-Fuzz finding without going through the OSS-Fuzz
infrastructure, run the same fuzz target directly against the corpus
attached to the issue:

```sh
go test -run '^$' -fuzz='^FuzzDecryptNeverPanics$' -fuzztime=30s \
  -fuzzminimizetime=10s ./...
# Then feed the reported failing input via go test -run TestFuzz
```
