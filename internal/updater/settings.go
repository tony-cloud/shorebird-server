package updater

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Settings is the on-disk and administrator-facing update configuration.
// Repository, token and mirror URL are deployment configuration (environment)
// and deliberately not editable through the API.
type Settings struct {
	Channel              string `json:"channel"`
	UseMirror            bool   `json:"use_mirror"`
	AutoUpdate           bool   `json:"auto_update"`
	CheckIntervalSeconds int    `json:"check_interval_seconds"`
}

// DefaultSettings: stable channel, manual updates, one-day interval.
func DefaultSettings() Settings {
	return Settings{CheckIntervalSeconds: 24 * 60 * 60, Channel: "stable"}
}

// Validate bounds the interval to one minute .. one week.
func (s Settings) Validate() error {
	if s.Channel != "stable" && s.Channel != "dev" {
		return errors.New("invalid_channel")
	}
	if s.CheckIntervalSeconds < 60 || s.CheckIntervalSeconds > 7*24*60*60 {
		return errors.New("invalid_interval")
	}
	return nil
}

func loadSettings(path string) (Settings, error) {
	s := DefaultSettings()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, errors.New("config_read_failed")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(data) > 16384 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return s, errors.New("invalid_config")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, errors.New("invalid_config")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return s, errors.New("invalid_config")
	}
	return s, s.Validate()
}

// saveSettings persists atomically before live settings change.
func saveSettings(path string, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, append(data, '\n'), 0o600); err != nil {
		return errors.New("config_write_failed")
	}
	return nil
}

// writeFileAtomic writes a small file through a synced temporary on the same
// filesystem and renames it into place.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".shorebird-server-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = replaceFile(f.Name(), path)
	}
	return err
}
