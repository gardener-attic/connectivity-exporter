#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

if [ -n "${IGNORE_CHECKS}" ]; then
   exit 0
fi

if [ "$(uname -s)" = "Darwin" ]; then
    tar_cmd="gtar"
else
    tar_cmd="tar"
fi

is_at_least_at() {
    [ "$(printf "%s\n%s" "$1" "$2" | sort -V | head -1)" = "$2" ]
}

gtar_line="$($tar_cmd --version | head -1)"
gzip_line="$(gzip --version | head -1)"
gtar_intro="$(echo "${gtar_line}" | cut -f-3 -d' ')"
gzip_intro="$(echo "${gzip_line}" | cut -f-1 -d' ')"
gtar_version="$(echo "${gtar_line}" | cut -f4- -d' ')"
gzip_version="$(echo "${gzip_line}" | cut -f2- -d' ')"

min_gtar_version='1.34'
min_gzip_version='1.10'

if [ "$gtar_intro" != 'tar (GNU tar)' ] ||
   [ "$gzip_intro" != 'gzip' ] ||
   ! is_at_least_at "${gtar_version}" "${min_gtar_version}" ||
   ! is_at_least_at "${gzip_version}" "${min_gzip_version}"; then
   echo >&2 "
Please install the GNU version of tar ${min_gtar_version} and gzip ${min_gzip_version}:

  brew install gnu-tar gzip

They can produce byte-to-byte equivalent .tgz files for the same content,
independent of the access time or the PID of the tar process.
"
  exit 1
fi
