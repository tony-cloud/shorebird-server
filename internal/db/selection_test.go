package db

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shorebird-server/internal/selection"
)

func TestSelectionNamespaceAndStateSurviveSQLiteReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "selection.db")
	s, e := NewSqliteStore(path)
	if e != nil {
		t.Fatal(e)
	}
	org, e := s.CreateOrganization(ctx, "org", "team")
	if e != nil {
		t.Fatal(e)
	}
	app, e := s.CreateApp(ctx, org, "test")
	if e != nil {
		t.Fatal(e)
	}
	legacy, e := s.CreateRelease(ctx, app.ID, "legacy", "rev", nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	if legacy.SelectionProtocol != 1 {
		t.Fatal("legacy release not protocol 1")
	}
	release, e := s.CreateReleaseWithProtocol(ctx, app.ID, "v2", "rev", nil, nil, 2)
	if e != nil {
		t.Fatal(e)
	}
	scope := selection.Scope{AppID: app.ID.String(), ReleaseVersion: release.Version, Platform: "ios", Arch: "aarch64", ClientIDHash: selection.ClientHash("device"), BaseArtifactHash: strings.Repeat("a", 64), RuntimeProfile: "native-aot"}
	key := selection.InstallKey("ios", "aarch64", scope.ClientIDHash)
	descriptor := selection.Base(scope, "stable", "9223372036854775806", "policy", "0")
	number, hash := "2", strings.Repeat("b", 64)
	descriptor.VariantID = "pro"
	descriptor.LicenseType = "pro"
	descriptor.Target = selection.Target{Kind: "patch", PatchNumber: &number, ArtifactHash: &hash, Encryption: "transport-aes-256-gcm"}
	digest, e := descriptor.Digest()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SelectionTransaction(ctx, release.ID, func(state *selection.State, cat *SelectionCatalog) error {
		state.Selections[key] = selection.Result{Selection: descriptor, SelectionDigest: digest}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = NewSqliteStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.SelectionTransaction(ctx, release.ID, func(state *selection.State, cat *SelectionCatalog) error {
		if state.Selections[key].Selection.Epoch != descriptor.Epoch {
			return fmt.Errorf("epoch lost on reopen")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if changed, e := s.SetPatchRolledBack(ctx, release.ID, 2, true); e != nil || !changed {
		t.Fatalf("rollback %v %v", changed, e)
	}
	if changed, e := s.SetPatchRolledBack(ctx, release.ID, 2, true); e != nil || changed {
		t.Fatalf("repeated rollback changed grants %v %v", changed, e)
	}
	if e = s.SelectionTransaction(ctx, release.ID, func(state *selection.State, cat *SelectionCatalog) error {
		d := state.Selections[key].Selection
		if d.Epoch != "9223372036854775807" || d.Target.Kind != "base" {
			return fmt.Errorf("64-bit epoch lost")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// A grant at epoch max cannot be invalidated by wrapping. The complete rollback
	// transaction must abort, including the authoritative content-revocation row.
	if _, e = s.SetPatchRolledBack(ctx, release.ID, 2, false); e != nil {
		t.Fatal(e)
	}
	if e = s.SelectionTransaction(ctx, release.ID, func(state *selection.State, cat *SelectionCatalog) error {
		d := descriptor
		d.Epoch = "9223372036854775807"
		digest, _ := d.Digest()
		state.Selections[key] = selection.Result{Selection: d, SelectionDigest: digest}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SetPatchRolledBack(ctx, release.ID, 2, true); e == nil {
		t.Fatal("exhausted epoch wrapped")
	}
	revoked, e := s.GetRolledBackPatchNumbers(ctx, release.ID)
	if e != nil || len(revoked) != 0 {
		t.Fatal("failed rollback partially committed")
	}
	if e = s.DeleteRelease(ctx, release.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.CreateReleaseWithProtocol(ctx, app.ID, "v2", "rev", nil, nil, 1); !errors.Is(e, ErrReleaseReserved) {
		t.Fatalf("namespace reset: %v", e)
	}
}
