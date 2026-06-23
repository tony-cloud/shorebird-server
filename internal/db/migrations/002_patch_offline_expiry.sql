-- +goose Up
-- +goose StatementBegin
ALTER TABLE patch_artifacts ADD COLUMN IF NOT EXISTS offline_expires_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE patch_artifacts DROP COLUMN IF EXISTS offline_expires_at;
-- +goose StatementEnd
