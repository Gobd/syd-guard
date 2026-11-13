package guest

import (
	"os"
	"path/filepath"

	"github.com/Gobd/syd-guard/internal/system"
)

func overlaySource(project, rel string) string {
	// A folder first added live keeps the same storage on a later launch.
	live := filepath.Join(dynamicOverlayRoot(), system.HashBytes([]byte(filepath.Join(project, rel))))
	if fi, err := os.Stat(live); err == nil && fi.IsDir() {
		return live
	}
	dir := filepath.Join(system.Home(), ".cache", "sydguard", "overlay", system.HashBytes([]byte(project))[:16], rel)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}
