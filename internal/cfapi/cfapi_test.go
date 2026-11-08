package cfapi

import "testing"

func profile(name string, prec int, enabled bool, include, exclude []string) Profile {
	p := Profile{Name: name, Precedence: prec, Enabled: enabled, Match: `identity.email == "warp_connector@team.cloudflareaccess.com"`, Tunnel: "masque"}
	p.Mode.Mode = "warp"
	for _, a := range include {
		p.Include = append(p.Include, struct {
			Address string `json:"address"`
		}{a})
	}
	for _, a := range exclude {
		p.Exclude = append(p.Exclude, struct {
			Address string `json:"address"`
		}{a})
	}
	return p
}

func TestEffectiveProfile(t *testing.T) {
	mesh := profile("Mesh", 1000, true, []string{"100.96.0.0/12"}, nil)
	full := profile("Full", 900, true, nil, []string{"172.31.255.0/29"})
	if !mesh.SafeForMesh() || full.SafeForMesh() {
		t.Fatal("include-only Mesh profile is safe, full tunnel is not")
	}
	if e := EffectiveProfile([]Profile{mesh, full}, "team"); e == nil || e.Name != "Full" {
		t.Fatal("lower precedence wins")
	}
	full.Enabled = false
	if e := EffectiveProfile([]Profile{mesh, full}, "team"); e == nil || e.Name != "Mesh" {
		t.Fatal("disabled profiles are ignored")
	}
	wide := profile("Wide", 1, true, []string{"100.96.0.0/12", "0.0.0.0/1"}, nil)
	if wide.SafeForMesh() {
		t.Fatal("profile that includes Internet ranges is not safe")
	}
}

func TestNormalizeTeam(t *testing.T) {
	for in, want := range map[string]string{
		"Team":                               "team",
		"team.cloudflareaccess.com":          "team",
		"https://team.cloudflareaccess.com/": "team",
	} {
		if got := NormalizeTeam(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
