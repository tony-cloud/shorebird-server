-- +goose Up
-- +goose StatementBegin
ALTER TABLE patch_events ADD COLUMN event_id UUID;
ALTER TABLE patch_events ADD COLUMN failure_category TEXT;
CREATE UNIQUE INDEX idx_patch_events_event_id
    ON patch_events (app_id, client_id, event_id)
    WHERE event_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_patch_events_event_id;
ALTER TABLE patch_events DROP COLUMN failure_category;
ALTER TABLE patch_events DROP COLUMN event_id;
-- +goose StatementEnd
