package main

import "testing"

// These are go-mtgban's workflow names; its workflows_test.go pins the other side.
func TestNewBantoolWorkflow(t *testing.T) {
	tests := []struct {
		game, store string
		want        bantoolWorkflow
	}{
		{"magic", "cardkingdom", bantoolWorkflow{
			EventType: "magic-cardkingdom",
			File:      "bantool-magic-cardkingdom.yml",
			RunName:   "magic / cardkingdom",
		}},
		{"lorcana", "tcg_index", bantoolWorkflow{
			EventType: "lorcana-tcg_index",
			File:      "bantool-lorcana-tcg_index.yml",
			RunName:   "lorcana / tcg_index",
		}},
	}
	for _, tt := range tests {
		got := newBantoolWorkflow(tt.game, tt.store)
		if got != tt.want {
			t.Errorf("newBantoolWorkflow(%q, %q) = %+v, want %+v", tt.game, tt.store, got, tt.want)
		}
	}
}
