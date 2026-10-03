package node

import (
	"encoding/json"
	"testing"
)

func TestSnapshotHasPrevious(t *testing.T) {
	for _, tc := range []struct {
		name string
		data json.RawMessage
		want bool
	}{
		{"missing", nil, false},
		{"null", json.RawMessage("null"), false},
		{"saved configuration", json.RawMessage(`{"automatic":true}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (recoverySnapshot{Previous: tc.data}).hasPrevious(); got != tc.want {
				t.Fatalf("hasPrevious() = %v, want %v", got, tc.want)
			}
		})
	}
}
