#!/bin/bash -eu
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# OSS-Fuzz build script. Compiles each of go-seccure's native Go fuzz
# targets (defined in fuzz_test.go) into a libFuzzer-compatible binary
# using compile_native_go_fuzzer, then OSS-Fuzz harnesses run them
# continuously on Google's infrastructure.

cd "${SRC}/go-seccure"

# Each target gets its own binary. The seed corpora are pulled from
# Go's f.Add() entries automatically by the compile_native_go_fuzzer
# wrapper.
for target in \
    FuzzDecodeCompactNeverPanics \
    FuzzEncodeDecodeCompactRoundTrip \
    FuzzPassphraseToPubkeyNeverPanics \
    FuzzDecryptNeverPanics \
    FuzzVerifyBinaryNeverPanics \
    FuzzCurveByNameNeverPanics
do
    compile_native_go_fuzzer github.com/invenity-labs/go-seccure "${target}" "${target}"
done
