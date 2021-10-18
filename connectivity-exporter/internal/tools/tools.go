// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Do not build this file by default, it's only parsed by go mod to
// pull the dependencies.

// +build tools

package tools


import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
)
