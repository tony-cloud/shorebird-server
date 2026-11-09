// Package version holds the build identity of the server binary.
//
// Release builds set both values with -ldflags, for example
//
//	-X github.com/shorebird-server/internal/version.Version=v1.2.3
//	-X github.com/shorebird-server/internal/version.BuildTime=2026-11-09T12:00:00Z
//
// (scripts/build_update_zip.py and the release CI do this). A plain
// `go build` or `go run` leaves Version empty: such a binary is reported as
// unversioned and never takes part in self-update.
package version

import "golang.org/x/mod/semver"

// Version is the semantic version (vMAJOR.MINOR.PATCH[-pre]) set at link time.
var Version = ""

// BuildTime is the UTC build time set at link time (informational only).
var BuildTime = ""

// Unversioned is reported by builds without a link-time version.
const Unversioned = "v0.0.0-unversioned"

// Current returns the link-time version, or Unversioned.
func Current() string {
	if Versioned() {
		return Version
	}
	return Unversioned
}

// Versioned reports whether the binary carries a valid link-time version.
func Versioned() bool { return Version != "" && semver.IsValid(Version) && semver.Build(Version) == "" }
