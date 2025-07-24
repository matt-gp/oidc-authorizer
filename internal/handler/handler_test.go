package handler

import (
	"testing"
)

func TestNewHandler(t *testing.T) {
	s := &MockService{}
	h := NewHandler(s)
	if h == nil {
		t.Errorf("expected handler to be non-nil")
	}
}
