package offlineapi

import (
	"testing"
)

func TestRequestRefreshDoesNotBlock(t *testing.T) {
	s := &Service{refreshSignal: make(chan struct{}, 1)}
	// No reader drains the channel; extra sends must not block.
	for i := 0; i < 100; i++ {
		s.RequestRefresh()
	}
}
