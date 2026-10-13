package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

// The store lists decode from the stores section, from the top level of a
// config that has none, and only from the section when a config has both.
func TestStoresConfigSupportsNestedAndLegacyKeys(t *testing.T) {
	tests := []struct {
		name, config string
		want         []string
	}{
		{"nested", `{"stores": {"search_block_list": ["NESTED"]}}`, []string{"NESTED"}},
		{"top level", `{"search_block_list": ["FLAT"]}`, []string{"FLAT"}},
		{"both", `{"stores": {"search_block_list": ["NESTED"]}, "search_block_list": ["FLAT"]}`, []string{"NESTED"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config ConfigType
			err := json.Unmarshal([]byte(test.config), &config)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(config.Stores.SearchRetailBlockList, test.want) {
				t.Errorf("got %v, want %v", config.Stores.SearchRetailBlockList, test.want)
			}
		})
	}
}

// The admin editor writes the config back from the decoded value, so a save
// moves top-level store lists into the stores section.
func TestStoresConfigWritesTheSection(t *testing.T) {
	var config ConfigType
	err := json.Unmarshal([]byte(`{"global_allow_list": ["CK"]}`), &config)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = writeConfigFile(config, &out)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	err = json.Unmarshal(out.Bytes(), &keys)
	if err != nil {
		t.Fatal(err)
	}
	_, flat := keys["global_allow_list"]
	if flat {
		t.Error("the written config still has a top-level global_allow_list")
	}
	var stores StoresConfig
	err = json.Unmarshal(keys["stores"], &stores)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stores.GlobalAllowList, []string{"CK"}) {
		t.Errorf("stores section holds %+v, want the global allow list", stores)
	}
}
