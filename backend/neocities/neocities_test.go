package neocities_test

import (
	"testing"

	"github.com/rclone/rclone/backend/neocities"
	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs the integration tests against this backend.
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestNeocities:",
		NilObject:  (*neocities.Object)(nil),
	})
}
