-- +goose Up
ALTER TABLE releases ADD COLUMN selection_protocol INTEGER NOT NULL DEFAULT 1 CHECK(selection_protocol IN (1,2));
-- Reservations intentionally have no cascading foreign key: a deleted release
-- namespace must never reset protocol, immutable identity, or epochs.
CREATE TABLE release_namespace_reservations(app_id UUID NOT NULL,version TEXT NOT NULL,selection_protocol INTEGER NOT NULL CHECK(selection_protocol IN (1,2)),PRIMARY KEY(app_id,version));
INSERT INTO release_namespace_reservations(app_id,version,selection_protocol) SELECT app_id,version,selection_protocol FROM releases ON CONFLICT DO NOTHING;
CREATE TABLE release_selection_states(release_id INTEGER PRIMARY KEY REFERENCES releases(id) ON DELETE CASCADE,state TEXT NOT NULL);
CREATE TABLE artifact_storage_namespaces(storage_key TEXT PRIMARY KEY,selection_protected BOOLEAN NOT NULL);
INSERT INTO artifact_storage_namespaces(storage_key,selection_protected)
SELECT storage_key,MAX(selection_protocol)=2 FROM (
 SELECT a.storage_key,r.selection_protocol FROM release_artifacts a JOIN releases r ON a.release_id=r.id
 UNION ALL SELECT a.storage_key,r.selection_protocol FROM patch_artifacts a JOIN patches p ON a.patch_id=p.id JOIN releases r ON p.release_id=r.id
) existing GROUP BY storage_key;
-- +goose Down
DROP TABLE artifact_storage_namespaces;
DROP TABLE release_selection_states;
DROP TABLE release_namespace_reservations;
ALTER TABLE releases DROP COLUMN selection_protocol;
