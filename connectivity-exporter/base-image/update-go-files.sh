#!/bin/bash

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "$(realpath "$0")")" || exit 1

pushd .. >/dev/null

declare -a new_packages=( . )
declare -A visited_packages
declare -A all_imports

rm_cap_o=0
if [[ ! -e packet/c/cap.o ]]; then
    rm_cap_o=1
    touch packet/c/cap.o
fi

while [[ ${#new_packages[@]} -gt 0 ]]; do
    packages="${new_packages[@]}"
    new_packages=()

    for package in ${packages}; do
        if [[ -n "${visited_packages["${package}"]+abc}" ]]; then
            continue
        fi
        visited_packages["$package"]='1'
        for field in 'Imports' 'TestImports'; do
            imports=($(go list -f "{{.${field}}}" "${package}" | sed -e 's/^\[//' -e 's/\]$//'))
            for import in "${imports[@]}"; do
                if [[ "${import}" == 'C' ]]; then
                    # ignore cgo
                    continue
                fi
                all_imports["${import}"]='1'
                if [[ "${import}" = m/* ]]; then
                    new_packages+=("${import}")
                fi
            done
        done
    done
done

declare -a std_imports
declare -a other_imports

declare -a all_imports_array=( "${!all_imports[@]}" )

standard_results=( $(go list -f '{{.Standard}}' "${all_imports_array[@]}") )
[[ ${#all_imports_array[@]} -eq ${#standard_results[@]} ]] || exit 1
for idx in $(seq 0 $((${#standard_results[@]}-1))); do
    import="${all_imports_array[${idx}]}"
    result="${standard_results[${idx}]}"
    if [[ "${result}" = 'true' ]]; then
        std_imports+=( "${import}" )
    elif [[ "${import}" = m/* ]]; then
        :
    else
        other_imports+=( "${import}" )
    fi
done

popd >/dev/null

cat <<MAIN_GO >main.go
// By building this program, go can cache the build artifacts of the package dependencies.
package main

import (
MAIN_GO
printf '\t_ "%s"\n' "${std_imports[@]}" >>main.go
printf '\n' >>main.go
printf '\t_ "%s"\n' "${other_imports[@]}" >>main.go
cat <<MAIN_GO >>main.go
)

func main() {}
MAIN_GO

gofmt -s -w main.go

cp ../go.mod ./go.mod

if [[ ${rm_cap_o} -eq 1 ]]; then
    rm -f packet/c/cap.o
fi
