# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Build container for go-seccure's continuous-fuzzing harness.
# Compatible with OSS-Fuzz and ClusterFuzzLite.

FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/invenity-labs/go-seccure $SRC/go-seccure
WORKDIR $SRC/go-seccure

COPY build.sh $SRC/
