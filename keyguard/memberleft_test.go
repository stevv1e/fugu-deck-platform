package keyguard

import (
	"strings"
	"testing"
)

// Участника исключили из общего пространства: его разрешения отозваны, из чужих он убран.
func TestMemberLeft(t *testing.T) {
	k := newRig(t)
	c := &check{t: t}
	put := func(id, space, sponsor string, members ...string) {
		if ok, err := k.srv.Grants.Put(&Grant{ID: id, Space: space, Chat: "c-1", Sponsor: sponsor, Members: members, Active: true}); !ok || err != nil {
			t.Fatal(id, err)
		}
	}
	put("g-bob", "t-shop", "bob", "anna", "bob")
	put("g-anna", "t-shop", "anna", "anna", "bob", "carol")
	put("g-other", "t-home", "bob", "bob")
	body := j(map[string]string{"space": "t-shop", "member": "bob"})
	st, _ := k.do("POST", "/v1/grants/member-left", "tok-anna", body, nil)
	c.ok("L1 не control-plane — 403", st == 403, st)
	st, b := k.do("POST", "/v1/grants/member-left", "tok-cp", j(map[string]string{"space": "u-anna", "member": "bob"}), nil)
	c.ok("L2 только общие пространства", st == 400, st, b)
	st, b = k.do("POST", "/v1/grants/member-left", "tok-cp", body, nil)
	c.ok("L3 исключение принято", st == 200 && strings.Contains(b, `"revoked":1`) && strings.Contains(b, `"trimmed":1`), st, b)
	gb, _ := k.srv.Grants.Get("g-bob")
	ga, _ := k.srv.Grants.Get("g-anna")
	go_, _ := k.srv.Grants.Get("g-other")
	c.ok("L4 разрешение Боба в этом пространстве отозвано", gb.Revoked, gb)
	c.ok("L5 из разрешения Анны Боб убран, остальные на месте", strings.Join(ga.Members, ",") == "anna,carol" && !ga.Revoked, ga.Members)
	c.ok("L6 другое пространство не тронуто", !go_.Revoked && len(go_.Members) == 1, go_)
	if c.f > 0 {
		t.Fatalf("%d проверок не прошли", c.f)
	}
}
