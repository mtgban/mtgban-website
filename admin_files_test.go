package main

import (
	"regexp"
	"testing"
)

// Every editable file sits under the one Files tab: a file's ?page= opens the
// tab with that file showing and marked in the column, and any other page
// leaves the tab closed with the first file ready behind it.
func TestAdminFilesColumn(t *testing.T) {
	activeTab := regexp.MustCompile(`class="admin-tab active"[^>]*>([^<]+)<`)
	activePanel := regexp.MustCompile(`class="admin-panel[^"]* active" id="panel-([a-z]+)"`)
	activeFile := regexp.MustCompile(`class="admin-file active" id="file-([a-z]+)"`)
	allFiles := regexp.MustCompile(`class="admin-file[^"]*" id="file-([a-z]+)"`)
	activeLink := regexp.MustCompile(`class="admin-file-link active" data-file="([a-z]+)"`)
	allLinks := regexp.MustCompile(`class="admin-file-link[^"]*" data-file="([a-z]+)"`)

	tests := []struct {
		page, tab, panel, file string
	}{
		{"config", "Files", "files", "config"},
		{"checkpoints", "Files", "files", "checkpoints"},
		{"acl", "Files", "files", "acl"},
		{"affiliates", "Files", "files", "affiliates"},
		{"datasets", "Files", "files", "datasets"},
		{"infrastructure", "Files", "files", "infrastructure"},
		{"overrides", "Files", "files", "overrides"},
		{"", "Dashboard", "dashboard", "config"},
		{"tools", "Tools", "tools", "config"},
	}
	for _, tt := range tests {
		t.Run("page="+tt.page, func(t *testing.T) {
			pv := PageVars{UserNav: &NavElem{Short: "b"}, Page: tt.page, AdminVars: AdminVars{ACLText: "{}"}}
			out := renderPage(t, "admin.html", false, pv)
			if out == "" {
				t.Fatal("the page rendered empty")
			}

			got := activeTab.FindAllStringSubmatch(out, -1)
			if len(got) != 1 || got[0][1] != tt.tab {
				t.Errorf("active tabs %v, want %s", got, tt.tab)
			}
			got = activePanel.FindAllStringSubmatch(out, -1)
			if len(got) != 1 || got[0][1] != tt.panel {
				t.Errorf("active panels %v, want %s", got, tt.panel)
			}
			got = activeFile.FindAllStringSubmatch(out, -1)
			if len(got) != 1 || got[0][1] != tt.file {
				t.Errorf("active files %v, want %s", got, tt.file)
			}
			got = activeLink.FindAllStringSubmatch(out, -1)
			if len(got) != 1 || got[0][1] != tt.file {
				t.Errorf("marked in the column %v, want %s", got, tt.file)
			}

			// The column lists exactly the files on the page, in their order.
			links := allLinks.FindAllStringSubmatch(out, -1)
			files := allFiles.FindAllStringSubmatch(out, -1)
			if len(links) != len(files) {
				t.Fatalf("column lists %v, the page holds %v", links, files)
			}
			for i := range files {
				if links[i][1] != files[i][1] {
					t.Errorf("link %d is %s, file %d is %s", i, links[i][1], i, files[i][1])
				}
			}
		})
	}
}
