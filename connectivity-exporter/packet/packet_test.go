// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package packet

import (
	"reflect"
	"strings"
	"testing"
)

func TestFlag(t *testing.T) {
	s := make([]string, 0, 16)
	for i := 1; i < 256; i = i << 1 {
		s = append(s, flagsString(byte(i)))
		s = append(s, flagsString(byte(i)|0x10))
	}
	assert(t, strings.Join(s, " "),
		"[F] [F.] [S] [S.] [R] [R.] [P] [P.] [.] [.] [U] [.U] [E] [.E] [W] [.W]")
}

func assert(t *testing.T, got interface{}, expected interface{}) {
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("Got %+v\nwant %+v", got, expected)
	}
}
