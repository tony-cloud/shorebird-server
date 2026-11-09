package updater

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type fakeGitHub struct {
	mu       sync.Mutex
	releases []githubRelease
	assets   map[int64][]byte
	fail     bool
	tokens   []string
	hits     int
}

func (g *fakeGitHub) add(k testKey, t *testing.T, tag string, prerelease bool, platform Platform, binary []byte, mutate func(map[string][]byte)) {
	channel := "stable"
	if prerelease {
		channel = "dev"
	}
	entries := k.zipEntries(t, tag, channel, platform, binary)
	if mutate != nil {
		mutate(entries)
	}
	r := githubRelease{Tag: tag, Prerelease: prerelease}
	for name, data := range entries {
		id := int64(len(g.assets) + 1)
		g.assets[id] = data
		r.Assets = append(r.Assets, githubAsset{ID: id, Name: name, Size: int64(len(data)), State: "uploaded"})
	}
	g.releases = append(g.releases, r)
}

func (g *fakeGitHub) handler(prefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.hits++
		g.tokens = append(g.tokens, r.Header.Get("Authorization"))
		if g.fail {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, prefix)
		switch {
		case path == "/repos/o/r/releases/latest":
			var latest *githubRelease
			for n := range g.releases {
				if !g.releases[n].Prerelease {
					latest = &g.releases[n]
				}
			}
			_ = json.NewEncoder(w).Encode(latest)
		case path == "/repos/o/r/releases":
			_ = json.NewEncoder(w).Encode(g.releases)
		case strings.HasPrefix(path, "/repos/o/r/releases/assets/"):
			var id int64
			fmt.Sscan(strings.TrimPrefix(path, "/repos/o/r/releases/assets/"), &id)
			data, ok := g.assets[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	})
}

func (g *fakeGitHub) do(f func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f()
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *httptest.Server) {
	g := &fakeGitHub{assets: map[int64][]byte{}}
	server := httptest.NewServer(g.handler(""))
	t.Cleanup(server.Close)
	return g, server
}

func testSource(server *httptest.Server, k testKey, channel string) *githubSource {
	return &githubSource{repository: "o/r", token: "secret-token", baseURL: server.URL, platform: linuxAMD64, trust: k.trust,
		client: server.Client(), channel: channel}
}

func TestGitHubDiscoveryAndDownload(t *testing.T) {
	k := newTestKey(t)
	g, server := newFakeGitHub(t)
	g.add(k, t, "v1.1.0", false, linuxAMD64, []byte("binary 1.1.0"), nil)
	g.add(k, t, "v1.2.0", false, linuxAMD64, []byte("binary 1.2.0"), nil)
	g.add(k, t, "v1.3.0-dev.1", true, linuxAMD64, []byte("binary 1.3.0-dev.1"), nil)

	stable := testSource(server, k, "stable")
	r, err := stable.Latest(t.Context(), "v1.0.0")
	if err != nil || r == nil || r.Version != "v1.2.0" || r.Channel != "stable" {
		t.Fatalf("stable: %+v %v", r, err)
	}
	var out bytes.Buffer
	if err := stable.Download(t.Context(), r, &out); err != nil || out.String() != "binary 1.2.0" {
		t.Fatalf("download: %v", err)
	}
	if r, err := stable.Latest(t.Context(), "v1.2.0"); err != nil || r != nil {
		t.Fatalf("up to date: %+v %v", r, err)
	}
	dev := stable.WithSettings(Settings{Channel: "dev"}).(*githubSource)
	if r, err := dev.Latest(t.Context(), "v1.2.0"); err != nil || r == nil || r.Version != "v1.3.0-dev.1" || r.Channel != "dev" {
		t.Fatalf("dev: %+v %v", r, err)
	}
	g.do(func() {
		for _, token := range g.tokens {
			if token != "Bearer secret-token" {
				t.Errorf("origin request without the configured token: %q", token)
			}
		}
	})
}

func TestGitHubDiscoveryRejects(t *testing.T) {
	k := newTestKey(t)
	stranger := newTestKey(t)
	name, _ := AssetName(linuxAMD64)
	for _, tc := range []struct {
		name   string
		tag    string
		mutate func(map[string][]byte)
		want   string
	}{
		{"unknown signer", "v1.1.0", func(e map[string][]byte) {
			e[name+".sig"] = EncodeSignature(stranger.private, e[name+".manifest.json"])
		}, "untrusted_signer"},
		{"missing signature", "v1.1.0", func(e map[string][]byte) { delete(e, name+".sig") }, "missing_release_asset"},
		{"VERSION disagrees", "v1.1.0", func(e map[string][]byte) { e["VERSION"] = []byte("v1.1.1\n") }, "version_mismatch"},
		{"other platform only", "v1.1.0", func(e map[string][]byte) {
			other := k.zipEntries(t, "v1.1.0", "stable", Platform{"linux", "arm64"}, []byte("arm"))
			for key := range e {
				delete(e, key)
			}
			for key, value := range other {
				e[key] = value
			}
		}, "missing_release_asset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, server := newFakeGitHub(t)
			g.add(k, t, tc.tag, false, linuxAMD64, []byte("binary"), tc.mutate)
			if _, err := testSource(server, k, "stable").Latest(t.Context(), "v1.0.0"); err == nil || err.Error() != tc.want {
				t.Fatalf("err %v, want %s", err, tc.want)
			}
		})
	}
	t.Run("tag differs from signed version", func(t *testing.T) {
		g, server := newFakeGitHub(t)
		g.add(k, t, "v1.1.0", false, linuxAMD64, []byte("binary"), nil)
		g.releases[0].Tag = "v1.9.0"
		if _, err := testSource(server, k, "stable").Latest(t.Context(), "v1.0.0"); err == nil || err.Error() != "version_mismatch" {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("tampered binary", func(t *testing.T) {
		g, server := newFakeGitHub(t)
		g.add(k, t, "v1.1.0", false, linuxAMD64, []byte("binary"), nil)
		source := testSource(server, k, "stable")
		r, err := source.Latest(t.Context(), "v1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		g.do(func() { g.assets[r.assetID] = []byte("binarX") })
		if err := source.Download(t.Context(), r, &bytes.Buffer{}); err == nil || err.Error() != "download_failed" {
			t.Fatalf("err %v", err)
		}
	})
}

func TestMirrorFallbackNeverReceivesToken(t *testing.T) {
	k := newTestKey(t)
	origin, originServer := newFakeGitHub(t)
	origin.add(k, t, "v1.1.0", false, linuxAMD64, []byte("binary"), nil)
	host := strings.TrimPrefix(originServer.URL, "http://")
	mirror := &fakeGitHub{releases: origin.releases, assets: origin.assets}
	mirrorServer := httptest.NewServer(mirror.handler("/" + host))
	t.Cleanup(mirrorServer.Close)

	source := testSource(originServer, k, "stable")
	source.mirrorURL = mirrorServer.URL + "/"
	origin.do(func() { origin.fail = true })
	r, err := source.Latest(t.Context(), "v1.0.0")
	if err != nil || r.Version != "v1.1.0" {
		t.Fatalf("mirror fallback: %+v %v", r, err)
	}
	if err := source.Download(t.Context(), r, &bytes.Buffer{}); err != nil {
		t.Fatalf("mirror download: %v", err)
	}
	mirror.do(func() {
		for _, token := range mirror.tokens {
			if token != "" {
				t.Error("the mirror received the API token")
			}
		}
	})
	// use_mirror tries the mirror first.
	origin.do(func() { origin.fail, origin.hits = false, 0 })
	mirror.do(func() { mirror.hits = 0 })
	preferred := source.WithSettings(Settings{Channel: "stable", UseMirror: true}).(*githubSource)
	_, err = preferred.Latest(t.Context(), "v1.0.0")
	var originHits, mirrorHits int
	origin.do(func() { originHits = origin.hits })
	mirror.do(func() { mirrorHits = mirror.hits })
	if err != nil || originHits != 0 || mirrorHits == 0 {
		t.Fatalf("mirror preference: origin %d mirror %d %v", originHits, mirrorHits, err)
	}
	// A mirror serving a forged manifest is caught by the signature.
	mirror.do(func() {
		forged := map[int64][]byte{}
		for id, data := range origin.assets {
			forged[id] = bytes.ReplaceAll(data, []byte(`"size":6`), []byte(`"size":7`))
		}
		mirror.assets = forged
	})
	origin.do(func() { origin.fail = true })
	if _, err := source.Latest(t.Context(), "v1.0.0"); err == nil || err.Error() != "signature_invalid" {
		t.Fatalf("forged mirror manifest: %v", err)
	}
}

func TestSourceConfigurationAndRedirectPolicy(t *testing.T) {
	k := newTestKey(t)
	for _, repo := range []string{"o", "o/r/x", "o/r?x"} {
		if _, err := NewGitHubSource(GitHubOptions{Repository: repo, Trust: k.trust, Platform: linuxAMD64}); err == nil {
			t.Fatalf("repository %q accepted", repo)
		}
	}
	for _, mirror := range []string{"http://mirror.example/", "https://user:pw@mirror.example/", "https://mirror.example/?q=1"} {
		if _, err := NewGitHubSource(GitHubOptions{MirrorURL: mirror, Trust: k.trust, Platform: linuxAMD64}); err == nil {
			t.Fatalf("mirror %q accepted", mirror)
		}
	}
	source, err := NewGitHubSource(GitHubOptions{MirrorURL: "default", Trust: k.trust, Platform: linuxAMD64})
	if err != nil {
		t.Fatal(err)
	}
	gs := source.(*githubSource)
	if gs.repository != DefaultRepository || gs.mirrorURL != DefaultMirrorURL {
		t.Fatalf("defaults %+v", gs)
	}
	check := func(target string) error {
		u, _ := url.Parse(target)
		req := &http.Request{URL: u, Header: http.Header{"Authorization": {"Bearer x"}}}
		err := gs.client.CheckRedirect(req, []*http.Request{{}})
		if err == nil && req.Header.Get("Authorization") != "" {
			t.Fatalf("credential forwarded to %s", target)
		}
		return err
	}
	for _, ok := range []string{"https://objects.githubusercontent.com/x", "https://github.com/o/r", "https://mirrors.tonycloud.cn/x"} {
		if err := check(ok); err != nil {
			t.Fatalf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://github.com/x", "https://evil.example/x", "https://u:p@github.com/x"} {
		if err := check(bad); err == nil {
			t.Fatalf("%s allowed", bad)
		}
	}
}
