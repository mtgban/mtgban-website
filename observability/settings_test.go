package observability

import "testing"

// The type is the roadmap's; the table is empty until phase 2e fills it.
func TestSettingHasTheRoadmapsFields(t *testing.T) {
	s := Setting{Name: "UploadSorting", Storage: "cookie", Mirror: "", Path: "upload", Kind: "enum", Enum: []string{"a"},
		Default: "a", Class: "preference", Area: "upload", Fact: "upload.sorting", FactScope: "", FactValue: ""}
	if s.Name == "" || s.Fact == "" {
		t.Fatal("a setting keeps what it is given")
	}
	for _, e := range Settings() {
		if e.Name == "" {
			t.Error("a setting with no name")
		}
	}
}
