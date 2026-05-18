# SPDX-License-Identifier: LGPL-3.0-or-later
#
# ClusterFuzzLite build container for go-seccure.

FROM gcr.io/oss-fuzz-base/base-builder-go

COPY . $SRC/go-seccure
WORKDIR $SRC/go-seccure
COPY ./.clusterfuzzlite/build.sh $SRC/
