-- +goose Up
-- +goose StatementBegin
CREATE TABLE managed_signing_keys (
    id SERIAL PRIMARY KEY,
    app_id UUID NOT NULL UNIQUE REFERENCES apps(id) ON DELETE CASCADE,
    public_key_pem TEXT NOT NULL,
    wrapped_private_key TEXT NOT NULL
);
ALTER TABLE release_artifacts ADD COLUMN signing_mode TEXT;
ALTER TABLE release_artifacts ADD COLUMN signing_key_id INTEGER REFERENCES managed_signing_keys(id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE release_artifacts DROP COLUMN signing_key_id;
ALTER TABLE release_artifacts DROP COLUMN signing_mode;
DROP TABLE managed_signing_keys;
-- +goose StatementEnd
