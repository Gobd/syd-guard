package backend

import "testing"

func TestSelect(t *testing.T) {
	for _, tc := range []struct {
		os        string
		requested Kind
		want      Kind
		wantError bool
	}{
		{"linux", Auto, Native, false},
		{"darwin", Auto, Lima, false},
		{"linux", Lima, Lima, false},
		{"darwin", Native, "", true},
		{"windows", Auto, "", true},
		{"freebsd", Auto, "", true},
		{"linux", "invalid", "", true},
	} {
		t.Run(tc.os+"/"+string(tc.requested), func(t *testing.T) {
			got, err := Select(tc.os, tc.requested)
			if (err != nil) != tc.wantError || got != tc.want {
				t.Fatalf("got %q/%v, want %q error=%v", got, err, tc.want, tc.wantError)
			}
		})
	}
}
