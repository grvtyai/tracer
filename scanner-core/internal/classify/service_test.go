package classify

import (
	"reflect"
	"testing"
)

func TestFromPort(t *testing.T) {
	if got := FromPort(22); got != "remote_access" {
		t.Fatalf("expected remote_access, got %q", got)
	}

	if got := FromPort(631); got != "printing" {
		t.Fatalf("expected printing, got %q", got)
	}

	if got := FromPort(9999); got != "general" {
		t.Fatalf("expected general fallback, got %q", got)
	}
}

func TestFromPortsAndAllFromPorts(t *testing.T) {
	ports := []int{22, 25, 631}

	if got := FromPorts(ports); got != "remote_access" {
		t.Fatalf("expected primary remote_access, got %q", got)
	}

	want := []string{"remote_access", "messaging", "printing"}
	if got := AllFromPorts(ports); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected classes\nwant: %#v\ngot:  %#v", want, got)
	}
}
