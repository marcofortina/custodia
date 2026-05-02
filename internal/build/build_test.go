package build

import "testing"

func TestCurrentBuildInfoUsesDefaults(t *testing.T) {
	info := Current()
	if info.Version == "" || info.Commit == "" || info.Date == "" {
		t.Fatalf("expected non-empty build info: %+v", info)
	}
}
