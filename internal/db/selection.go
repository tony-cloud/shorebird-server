package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shorebird-server/internal/selection"
)

var ErrReleaseReserved = errors.New("release namespace is permanently reserved")
var ErrSelectionImmutable = errors.New("selection_scope_immutable")
var ErrSelectionProtocol = errors.New("selection_protocol_mismatch")
var ErrPatchImmutable = errors.New("patch_content_immutable")

type SelectionCatalog struct {
	Release        ReleaseRow
	Artifacts      map[int]ArtifactRow
	Patches        map[string]PatchWithArtifactRow
	Revoked        map[int]bool
	Statuses       map[string]string
	StatusMetadata map[string]string
}

func (c *SelectionCatalog) Patch(platform, arch, number string) (PatchWithArtifactRow, bool) {
	p, ok := c.Patches[platform+"/"+arch+"/"+number]
	return p, ok
}

// SelectionTransaction locks the authoritative release before reading either
// revocation or selection state. The callback must not call Store methods.
type SelectionStore interface {
	SelectionTransaction(context.Context, int, func(*selection.State, *SelectionCatalog) error) error
	CreateReleaseWithProtocol(context.Context, uuid.UUID, string, string, *string, *string, int) (*ReleaseRow, error)
}
type scanRow interface{ Scan(...any) error }
type selectionRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}
type selectionTx interface {
	row(context.Context, string, ...any) scanRow
	rows(context.Context, string, ...any) (selectionRows, error)
	exec(context.Context, string, ...any) error
}
type sqliteSelectionTx struct{ *sql.Tx }

func (t sqliteSelectionTx) row(c context.Context, q string, a ...any) scanRow {
	return t.QueryRowContext(c, q, a...)
}
func (t sqliteSelectionTx) rows(c context.Context, q string, a ...any) (selectionRows, error) {
	r, e := t.QueryContext(c, q, a...)
	return sqliteRows{r}, e
}
func (t sqliteSelectionTx) exec(c context.Context, q string, a ...any) error {
	_, e := t.ExecContext(c, q, a...)
	return e
}

type sqliteRows struct{ *sql.Rows }

func (r sqliteRows) Close() { _ = r.Rows.Close() }

type pgSelectionTx struct{ pgx.Tx }

func (t pgSelectionTx) row(c context.Context, q string, a ...any) scanRow {
	return t.QueryRow(c, q, a...)
}
func (t pgSelectionTx) rows(c context.Context, q string, a ...any) (selectionRows, error) {
	return t.Query(c, q, a...)
}
func (t pgSelectionTx) exec(c context.Context, q string, a ...any) error {
	_, e := t.Exec(c, q, a...)
	return e
}

func (s *SqliteStore) SelectionTransaction(c context.Context, id int, f func(*selection.State, *SelectionCatalog) error) error {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = selectionTransaction(c, sqliteSelectionTx{tx}, id, f); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *PgStore) SelectionTransaction(c context.Context, id int, f func(*selection.State, *SelectionCatalog) error) error {
	tx, e := s.pool.Begin(c)
	if e != nil {
		return e
	}
	defer tx.Rollback(c)
	if e = selectionTransaction(c, pgSelectionTx{tx}, id, f); e != nil {
		return e
	}
	return tx.Commit(c)
}
func loadSelectionState(c context.Context, t selectionTx, id int) (*selection.State, error) {
	state := selection.NewState()
	var raw string
	e := t.row(c, `SELECT state FROM release_selection_states WHERE release_id=$1`, id).Scan(&raw)
	if e == sql.ErrNoRows || e == pgx.ErrNoRows {
		return state, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal([]byte(raw), state); e != nil {
		return nil, e
	}
	return state, nil
}
func selectionTransaction(c context.Context, t selectionTx, id int, f func(*selection.State, *SelectionCatalog) error) error {
	// A write before the first read also acquires SQLite's writer lock, avoiding
	// deferred read-to-write upgrades under contention.
	if e := t.exec(c, `UPDATE releases SET id=id WHERE id=$1`, id); e != nil {
		return e
	}
	cat := &SelectionCatalog{Artifacts: map[int]ArtifactRow{}, Patches: map[string]PatchWithArtifactRow{}, Revoked: map[int]bool{}, Statuses: map[string]string{}, StatusMetadata: map[string]string{}}
	r := &cat.Release
	if e := t.row(c, `SELECT id,app_id,version,selection_protocol FROM releases WHERE id=$1`, id).Scan(&r.ID, &r.AppID, &r.Version, &r.SelectionProtocol); e != nil {
		return e
	}
	state, e := loadSelectionState(c, t, id)
	if e != nil {
		return e
	}
	rows, e := t.rows(c, `SELECT id,release_id,platform,arch,hash,storage_key,signing_mode,signing_key_id FROM release_artifacts WHERE release_id=$1`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var a ArtifactRow
		if e := rows.Scan(&a.ID, &a.ReleaseID, &a.Platform, &a.Arch, &a.Hash, &a.StorageKey, &a.SigningMode, &a.SigningKeyID); e != nil {
			rows.Close()
			return e
		}
		cat.Artifacts[a.ID] = a
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = t.rows(c, `SELECT p.id,p.number,a.platform,a.arch,a.hash,a.storage_key,a.hash_signature,a.offline_expires_at FROM patches p JOIN patch_artifacts a ON p.id=a.patch_id WHERE p.release_id=$1 ORDER BY a.id`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var p PatchWithArtifactRow
		var platform, arch string
		if e := rows.Scan(&p.ID, &p.Number, &platform, &arch, &p.Hash, &p.StorageKey, &p.HashSignature, &p.OfflineExpiresAt); e != nil {
			rows.Close()
			return e
		}
		p.ReleaseID = id
		cat.Patches[fmt.Sprintf("%s/%s/%d", platform, arch, p.Number)] = p
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = t.rows(c, `SELECT patch_number FROM rolled_back_patches WHERE release_id=$1`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var n int
		if e := rows.Scan(&n); e != nil {
			rows.Close()
			return e
		}
		cat.Revoked[n] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = t.rows(c, `SELECT platform,status,COALESCE(metadata,'{}') FROM release_platform_statuses WHERE release_id=$1`, id)
	if e != nil {
		return e
	}
	for rows.Next() {
		var p, s, metadata string
		if e := rows.Scan(&p, &s, &metadata); e != nil {
			rows.Close()
			return e
		}
		cat.Statuses[p] = s
		cat.StatusMetadata[p] = metadata
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	beforeState, _ := json.Marshal(state)
	beforeMetadata := map[string]string{}
	for p, m := range cat.StatusMetadata {
		beforeMetadata[p] = m
	}
	before := map[string]string{}
	for p, s := range cat.Statuses {
		before[p] = s
	}
	if e = f(state, cat); e != nil {
		return e
	}
	raw, e := json.Marshal(state)
	if e != nil {
		return e
	}
	if !bytes.Equal(beforeState, raw) {
		if e = t.exec(c, `INSERT INTO release_selection_states(release_id,state) VALUES($1,$2) ON CONFLICT(release_id) DO UPDATE SET state=excluded.state`, id, string(raw)); e != nil {
			return e
		}
	}
	for p, s := range cat.Statuses {
		if s != before[p] || cat.StatusMetadata[p] != beforeMetadata[p] {
			meta := cat.StatusMetadata[p]
			if meta == "" {
				meta = "{}"
			}
			if e = t.exec(c, `INSERT INTO release_platform_statuses(release_id,platform,status,metadata) VALUES($1,$2,$3,$4) ON CONFLICT(release_id,platform) DO UPDATE SET status=excluded.status,metadata=excluded.metadata`, id, p, s, meta); e != nil {
				return e
			}
		}
	}
	return nil
}
func createReservedRelease(c context.Context, t selectionTx, app uuid.UUID, version, revision string, fv, dn *string, protocol int) (*ReleaseRow, error) {
	var existing int
	e := t.row(c, `INSERT INTO release_namespace_reservations(app_id,version,selection_protocol) VALUES($1,$2,$3) ON CONFLICT(app_id,version) DO NOTHING RETURNING selection_protocol`, app.String(), version, protocol).Scan(&existing)
	if e == sql.ErrNoRows || e == pgx.ErrNoRows {
		return nil, ErrReleaseReserved
	}
	if e != nil {
		return nil, e
	}
	r := &ReleaseRow{AppID: app, Version: version, FlutterRevision: revision, FlutterVersion: fv, DisplayName: dn, SelectionProtocol: protocol}
	e = t.row(c, `INSERT INTO releases(app_id,version,flutter_revision,flutter_version,display_name,selection_protocol) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,notes,created_at,updated_at`, app.String(), version, revision, fv, dn, protocol).Scan(&r.ID, &r.Notes, &r.CreatedAt, &r.UpdatedAt)
	return r, e
}
func (s *SqliteStore) CreateReleaseWithProtocol(c context.Context, app uuid.UUID, v, rev string, fv, dn *string, p int) (*ReleaseRow, error) {
	tx, e := s.db.BeginTx(c, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	r, e := createReservedRelease(c, sqliteSelectionTx{tx}, app, v, rev, fv, dn, p)
	if e != nil {
		return nil, e
	}
	return r, tx.Commit()
}
func (s *PgStore) CreateReleaseWithProtocol(c context.Context, app uuid.UUID, v, rev string, fv, dn *string, p int) (*ReleaseRow, error) {
	tx, e := s.pool.Begin(c)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(c)
	r, e := createReservedRelease(c, pgSelectionTx{tx}, app, v, rev, fv, dn, p)
	if e != nil {
		return nil, e
	}
	return r, tx.Commit(c)
}

func guardReleaseArtifact(c context.Context, t selectionTx, id int, platform, key string, mode *string, keyID *int) error {
	if e := t.exec(c, `UPDATE releases SET id=id WHERE id=$1`, id); e != nil {
		return e
	}
	var protocol int
	if e := t.row(c, `SELECT selection_protocol FROM releases WHERE id=$1`, id).Scan(&protocol); e != nil {
		return e
	}
	if e := claimArtifactStorageKey(c, t, key, protocol); e != nil {
		return e
	}
	if protocol != 2 {
		return nil
	}
	if mode == nil || *mode != "managed" || keyID == nil {
		return ErrSigningPolicyConflict
	}
	state, e := loadSelectionState(c, t, id)
	if e != nil {
		return e
	}
	if state.Published[platform] {
		return ErrSelectionImmutable
	}
	// Storage keys derive from immutable app/version/platform/arch. Reject every
	// duplicate allocation in v2 so a new grant cannot overwrite a bound object.
	var count int
	if e = t.row(c, `SELECT COUNT(*) FROM release_artifacts WHERE storage_key=$1`, key).Scan(&count); e != nil {
		return e
	}
	if count > 0 {
		return ErrSelectionImmutable
	}
	return nil
}
func guardPatchArtifact(c context.Context, t selectionTx, patchID int, arch, platform, key string) error {
	if e := t.exec(c, `UPDATE releases SET id=id WHERE id=(SELECT release_id FROM patches WHERE id=$1)`, patchID); e != nil {
		return e
	}
	var releaseID int
	if e := t.row(c, `SELECT release_id FROM patches WHERE id=$1`, patchID).Scan(&releaseID); e != nil {
		return e
	}
	var protocol int
	if e := t.row(c, `SELECT selection_protocol FROM releases WHERE id=$1`, releaseID).Scan(&protocol); e != nil {
		return e
	}
	if e := claimArtifactStorageKey(c, t, key, protocol); e != nil {
		return e
	}
	if protocol != 2 {
		return nil
	}
	var n int
	if e := t.row(c, `SELECT COUNT(*) FROM patch_artifacts WHERE (patch_id=$1 AND arch=$2 AND platform=$3) OR storage_key=$4`, patchID, arch, platform, key).Scan(&n); e != nil {
		return e
	}
	if n != 0 {
		return ErrPatchImmutable
	}
	return nil
}
func setRevocation(c context.Context, t selectionTx, id, n int, revoked bool) (bool, error) {
	if e := t.exec(c, `UPDATE releases SET id=id WHERE id=$1`, id); e != nil {
		return false, e
	}
	var previous int
	if e := t.row(c, `SELECT COUNT(*) FROM rolled_back_patches WHERE release_id=$1 AND patch_number=$2`, id, n).Scan(&previous); e != nil {
		return false, e
	}
	q := `DELETE FROM rolled_back_patches WHERE release_id=$1 AND patch_number=$2`
	if revoked {
		q = `INSERT INTO rolled_back_patches(release_id,patch_number) VALUES($1,$2) ON CONFLICT(release_id,patch_number) DO NOTHING`
	}
	if e := t.exec(c, q, id, n); e != nil {
		return false, e
	}
	if revoked && previous == 0 {
		state, e := loadSelectionState(c, t, id)
		if e != nil {
			return false, e
		}
		changed := false
		rollbackSecond := fmt.Sprint(time.Now().UTC().Unix())
		for key, result := range state.Selections {
			d := result.Selection
			if d.Target.Kind != "patch" || d.Target.PatchNumber == nil || *d.Target.PatchNumber != fmt.Sprint(n) {
				continue
			}
			epoch, e := selection.Decimal(d.Epoch, 1, 9223372036854775807)
			if e != nil {
				return false, e
			}
			if epoch == 9223372036854775807 {
				return false, fmt.Errorf("selection_epoch_exhausted")
			}
			next := fmt.Sprint(epoch + 1)
			base := selection.Base(d.Scope, d.Channel, next, "server-free-"+next, rollbackSecond)
			digest, e := base.Digest()
			if e != nil {
				return false, e
			}
			state.Selections[key] = selection.Result{Selection: base, SelectionDigest: digest}
			changed = true
		}
		if changed {
			raw, e := json.Marshal(state)
			if e != nil {
				return false, e
			}
			if e = t.exec(c, `UPDATE release_selection_states SET state=$1 WHERE release_id=$2`, string(raw), id); e != nil {
				return false, e
			}
		}
	}
	return (previous > 0) != revoked, nil
}

// This retained global registry serializes allocation even when caller-chosen
// legacy path labels collide with a different release's v2 storage namespace.
// V1/V1 reuse retains legacy behavior; a v2 key can never receive another grant.
func claimArtifactStorageKey(c context.Context, t selectionTx, key string, protocol int) error {
	var protected bool
	e := t.row(c, `INSERT INTO artifact_storage_namespaces(storage_key,selection_protected) VALUES($1,$2) ON CONFLICT(storage_key) DO NOTHING RETURNING selection_protected`, key, protocol == 2).Scan(&protected)
	if e == nil {
		return nil
	}
	if e != sql.ErrNoRows && e != pgx.ErrNoRows {
		return e
	}
	if e = t.row(c, `UPDATE artifact_storage_namespaces SET storage_key=storage_key WHERE storage_key=$1 RETURNING selection_protected`, key).Scan(&protected); e != nil {
		return e
	}
	if protected || protocol == 2 {
		return ErrSelectionImmutable
	}
	return nil
}
