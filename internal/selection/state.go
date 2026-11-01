package selection

type ScopeRecord struct {
	Scope                Scope `json:"scope"`
	ReleaseArtifactID    int   `json:"release_artifact_id"`
	SupplementArtifactID *int  `json:"supplement_artifact_id"`
	Published            bool  `json:"published"`
}

// StoredScope retains publisher provenance hashes separately from runtime hashes.
type StoredScope struct {
	Record         ScopeRecord `json:"record"`
	ReleaseHash    string      `json:"release_hash"`
	SupplementHash *string     `json:"supplement_hash"`
}
type Mapping struct {
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	Channel     string `json:"channel"`
	LicenseType string `json:"license_type"`
	Target      Target `json:"target"`
}
type Result struct {
	Selection       Descriptor `json:"selection"`
	SelectionDigest string     `json:"selection_digest"`
}
type Idempotent struct {
	Body   string `json:"body"`
	Result Result `json:"result"`
}

// State is one durable aggregate per release. The parent release lock makes all
// map key uniqueness, epoch/CAS and idempotency decisions atomic in both stores.
type State struct {
	Scopes      map[string]StoredScope `json:"scopes"`
	Published   map[string]bool        `json:"published"`
	Mappings    map[string]Mapping     `json:"mappings"`
	Selections  map[string]Result      `json:"selections"`
	Idempotency map[string]Idempotent  `json:"idempotency"`
}

func NewState() *State {
	return &State{map[string]StoredScope{}, map[string]bool{}, map[string]Mapping{}, map[string]Result{}, map[string]Idempotent{}}
}
func ScopeKey(platform, arch string) string { return platform + "/" + arch }
func InstallKey(platform, arch, clientHash string) string {
	return ScopeKey(platform, arch) + "/" + clientHash
}
func MappingKey(platform, arch, channel, variant string) string {
	return ScopeKey(platform, arch) + "/" + channel + "/" + variant
}
