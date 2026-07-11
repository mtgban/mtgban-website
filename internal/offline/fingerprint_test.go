package offline

import "testing"

func TestFingerprintOrderIndependent(t *testing.T) {
	var a, b Fingerprint
	a.Add("u1", "CK", "NM", 99, 5)
	a.Add("u2", "SCG", "SP", 80, 1)
	b.Add("u2", "SCG", "SP", 80, 1)
	b.Add("u1", "CK", "NM", 99, 5)
	if a.Sum() != b.Sum() {
		t.Error("insertion order changed the fingerprint")
	}
}

func TestFingerprintSensitive(t *testing.T) {
	base := func() *Fingerprint {
		var f Fingerprint
		f.Add("u1", "CK", "NM", 99, 5)
		return &f
	}
	mutations := []func(f *Fingerprint){
		func(f *Fingerprint) { f.Add("u1", "CK", "NM", 99, 5) },  // duplicate
		func(f *Fingerprint) { f.Add("u1", "CK", "NM", 100, 5) }, // price
		func(f *Fingerprint) { f.Add("u1", "CK", "NM", 99, 6) },  // qty
		func(f *Fingerprint) { f.Add("u1", "CK", "SP", 99, 5) },  // tag
		func(f *Fingerprint) { f.Add("u1", "TCG", "NM", 99, 5) }, // store
		func(f *Fingerprint) { f.Add("u2", "CK", "NM", 99, 5) },  // uuid
	}
	ref := base().Sum()
	for i, mut := range mutations {
		f := base()
		mut(f)
		if f.Sum() == ref {
			t.Errorf("mutation %d did not change the fingerprint", i)
		}
	}
}

func TestFingerprintFieldBoundaries(t *testing.T) {
	var a, b Fingerprint
	a.Add("u1x", "CK", "NM", 99, 5)
	b.Add("u1", "xCK", "NM", 99, 5)
	if a.Sum() == b.Sum() {
		t.Error("field boundary collision")
	}
}
