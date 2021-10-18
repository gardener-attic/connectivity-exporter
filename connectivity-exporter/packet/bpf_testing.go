// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +build testing

package packet

import (
	_ "embed"
)

//go:embed c/cap-testing.o
var capProg []byte
