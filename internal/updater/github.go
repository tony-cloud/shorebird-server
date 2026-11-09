package updater

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Source discovers and downloads signed releases.
type Source interface {
	Latest(ctx context.Context, current string) (*Release, error)
	Download(ctx context.Context, release *Release, w io.Writer) error
}

// DefaultRepository publishes the signed server releases.
const DefaultRepository = "tony-cloud/shorebird-server"

// DefaultMirrorURL is a GitHub transport mirror. It is untrusted: it never
// receives the API token and every manifest is still signature-checked.
const DefaultMirrorURL = "https://mirrors.tonycloud.cn/"

type githubSource struct {
	repository, token, baseURL string
	platform                   Platform
	trust                      *Trust
	client                     *http.Client
	channel                    string
	useMirror                  bool
	mirrorURL                  string
	tempDir                    string
}

var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// GitHubOptions configures release discovery.
type GitHubOptions struct {
	Repository string // owner/name; default DefaultRepository
	Token      string // optional GitHub API token, never sent to the mirror
	MirrorURL  string // "" disables the mirror; "default" selects DefaultMirrorURL
	TempDir    string // download temporaries ("" = OS temp dir)
	Trust      *Trust
	Platform   Platform
}

// NewGitHubSource returns a source reading GitHub releases of opts.Repository.
func NewGitHubSource(opts GitHubOptions) (Source, error) {
	if opts.Repository == "" {
		opts.Repository = DefaultRepository
	}
	if !repositoryPattern.MatchString(opts.Repository) {
		return nil, errors.New("invalid_repository")
	}
	mirror := opts.MirrorURL
	if mirror == "default" {
		mirror = DefaultMirrorURL
	}
	mirrorHost := ""
	if mirror != "" {
		u, err := url.Parse(mirror)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("invalid_mirror_url")
		}
		if !strings.HasSuffix(mirror, "/") {
			mirror += "/"
		}
		mirrorHost = strings.ToLower(u.Hostname())
	}
	client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("redirect_refused")
		}
		host := strings.ToLower(req.URL.Hostname())
		if host != "github.com" && host != "api.github.com" && (mirrorHost == "" || host != mirrorHost) && !strings.HasSuffix(host, ".githubusercontent.com") {
			return errors.New("redirect_refused")
		}
		// GitHub asset redirects use signed URLs. Never forward the API credential.
		req.Header.Del("Authorization")
		return nil
	}}
	return &githubSource{repository: opts.Repository, token: opts.Token, baseURL: "https://api.github.com", platform: opts.Platform,
		trust: opts.Trust, client: client, channel: "stable", mirrorURL: mirror, tempDir: opts.TempDir}, nil
}

// WithSettings returns an immutable policy snapshot for one operation.
func (s *githubSource) WithSettings(settings Settings) Source {
	c := *s
	c.channel = settings.Channel
	c.useMirror = settings.UseMirror
	return &c
}

func (s *githubSource) targets(suffix string) []string {
	origin := s.baseURL + "/repos/" + s.repository + suffix
	if s.mirrorURL == "" {
		return []string{origin}
	}
	mirror := s.mirrorURL + strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	if s.useMirror {
		return []string{mirror, origin}
	}
	return []string{origin, mirror}
}

func (s *githubSource) request(ctx context.Context, target, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("release_request_failed")
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "shorebird-server-updater")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.token != "" && strings.HasPrefix(target, s.baseURL+"/") {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("release_request_failed")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New("release_request_failed")
	}
	return resp, nil
}

func (s *githubSource) get(ctx context.Context, suffix, accept string) (*http.Response, error) {
	for _, target := range s.targets(suffix) {
		if resp, err := s.request(ctx, target, accept); err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("release_request_failed")
}

func (s *githubSource) asset(ctx context.Context, id int64, limit int64) ([]byte, error) {
	resp, err := s.get(ctx, "/releases/assets/"+strconv.FormatInt(id, 10), "application/octet-stream")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readBounded(resp.Body, limit)
}

type githubAsset struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	State string `json:"state"`
}

type githubRelease struct {
	Tag        string        `json:"tag_name"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

// Latest returns the newest signed release of the selected channel that is
// newer than current, or nil. Stable reads /releases/latest; dev lists the
// newest 100 releases, prereleases included.
func (s *githubSource) Latest(ctx context.Context, current string) (*Release, error) {
	name, err := AssetName(s.platform)
	if err != nil {
		return nil, err
	}
	suffix := "/releases/latest"
	if s.channel == "dev" {
		suffix = "/releases?per_page=100"
	}
	resp, err := s.get(ctx, suffix, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	data, err := readBounded(resp.Body, 4<<20)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var releases []githubRelease
	if s.channel == "dev" {
		err = json.Unmarshal(data, &releases)
	} else {
		var r githubRelease
		err = json.Unmarshal(data, &r)
		releases = []githubRelease{r}
	}
	if err != nil {
		return nil, errors.New("invalid_release")
	}
	var selected *githubRelease
	for n := range releases {
		r := &releases[n]
		if r.Draft || !semver.IsValid(r.Tag) || semver.Build(r.Tag) != "" || (s.channel != "dev" && (r.Prerelease || semver.Prerelease(r.Tag) != "")) {
			continue
		}
		if semver.IsValid(current) && semver.Compare(r.Tag, current) <= 0 {
			continue
		}
		if selected == nil || semver.Compare(r.Tag, selected.Tag) > 0 {
			selected = r
		}
	}
	if selected == nil {
		return nil, nil
	}
	assets := map[string]githubAsset{}
	for _, a := range selected.Assets {
		if _, ok := assets[a.Name]; ok {
			return nil, errors.New("invalid_release")
		}
		assets[a.Name] = a
	}
	for _, needed := range []string{name, "VERSION", name + ".manifest.json", name + ".sig"} {
		a, ok := assets[needed]
		if !ok || a.ID <= 0 || a.State != "uploaded" || a.Size <= 0 {
			return nil, errors.New("missing_release_asset")
		}
	}
	manifest, err := s.asset(ctx, assets[name+".manifest.json"].ID, maxManifestBytes)
	if err != nil {
		return nil, err
	}
	signature, err := s.asset(ctx, assets[name+".sig"].ID, maxSignatureBytes)
	if err != nil {
		return nil, err
	}
	release, err := verifyManifest(s.trust, manifest, signature, s.platform)
	if err != nil {
		return nil, err
	}
	version, err := s.asset(ctx, assets["VERSION"].ID, maxVersionBytes)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(version)) != release.Version || selected.Tag != release.Version || assets[name].Size != release.Size {
		return nil, errors.New("version_mismatch")
	}
	if s.channel != "dev" && release.Channel != "stable" {
		return nil, errors.New("invalid_release")
	}
	release.assetID = assets[name].ID
	return release, nil
}

// Download streams the binary through a temporary file and hands it to dst
// only after its size and hash match the signed manifest. A failed origin is
// retried from the start on the next target, never appended to.
func (s *githubSource) Download(ctx context.Context, release *Release, dst io.Writer) error {
	if err := verifyRelease(s.trust, release, s.platform); err != nil {
		return err
	}
	for _, target := range s.targets("/releases/assets/" + strconv.FormatInt(release.assetID, 10)) {
		destinationStarted := false
		err := func() error {
			resp, err := s.request(ctx, target, "application/octet-stream")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			f, err := os.CreateTemp(s.tempDir, ".shorebird-server-download-*")
			if err != nil {
				return errors.New("download_failed")
			}
			defer os.Remove(f.Name())
			defer f.Close()
			hash := sha256.New()
			n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, release.Size+1))
			if err != nil || n != release.Size || [sha256.Size]byte(hash.Sum(nil)) != release.Checksum {
				return errors.New("checksum_mismatch")
			}
			if _, err = f.Seek(0, io.SeekStart); err != nil {
				return errors.New("download_failed")
			}
			destinationStarted = true
			_, err = io.Copy(dst, f)
			return err
		}()
		if err == nil {
			return nil
		}
		if destinationStarted {
			return errors.New("download_failed")
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errors.New("download_failed")
}
