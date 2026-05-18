# Continuous fuzzing

Build scaffolding for running go-seccure's six native Go fuzz
targets (defined in [`fuzz_test.go`](../fuzz_test.go)) under a
libFuzzer harness. The triplet here (`Dockerfile`, `build.sh`,
`project.yaml`) follows the schema shared by
[OSS-Fuzz](https://google.github.io/oss-fuzz/) and
[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/).

## Files

| File           | Role |
|----------------|------|
| `Dockerfile`   | Build environment. Clones the latest `main` from this repo at runtime. |
| `build.sh`     | Compiles each `Fuzz*` target into a libFuzzer binary via `compile_native_go_fuzzer`. |
| `project.yaml` | Project metadata (language, contacts, sanitizers, engines). |

## Local reproduction

To reproduce a fuzz finding without the CI harness, run the target
directly against the corpus attached to the issue:

```sh
go test -run '^$' -fuzz='^FuzzDecryptNeverPanics$' -fuzztime=30s \
  -fuzzminimizetime=10s ./...
# Then feed the reported failing input via go test -run TestFuzz
```
