package main

import (
	"errors"
	"testing"
)

func TestShouldWriteMarker(t *testing.T) {
	if !shouldWriteMarker("", nil) {
		t.Error("full successful run must write the marker")
	}
	if shouldWriteMarker("NEO", nil) {
		t.Error("sets-filtered run must not write the marker")
	}
	if shouldWriteMarker("", errors.New("3 fetches failed")) {
		t.Error("failed run must not write the marker")
	}
}
