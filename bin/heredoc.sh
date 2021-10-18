#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

if [ "$(uname -s)" = "Darwin" ]; then
    tar_cmd="gtar"
else
    tar_cmd="tar"
fi

# shellcheck disable=SC2139
alias tar="$tar_cmd --sort=name                      \
                --mtime='1970-01-01 00:00:00'        \
                --owner=0 --group=0 --numeric-owner"

eval "
cat <<EOF
$(sed '/^# SPDX/d
       s/^#//
       s/#\$/$/' "$@")
EOF"
