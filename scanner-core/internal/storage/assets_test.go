package storage

import "testing"

func TestInferDeviceTypePrefersStrongWorkstationSignals(t *testing.T) {
	item := observedAsset{
		Hostname:  "blackrock.fritz.box",
		OSName:    "Windows 11 21H2",
		OpenPorts: []int{80, 135, 443},
	}

	deviceType, confidence := inferDeviceType(item)
	if deviceType != "workstation" {
		t.Fatalf("expected workstation, got %q", deviceType)
	}
	if confidence == "" {
		t.Fatalf("expected confidence to be set")
	}
}

func TestInferDeviceTypeStillDetectsRouterFromNetworkSignals(t *testing.T) {
	item := observedAsset{
		Hostname:  "fritz.box",
		Product:   "Home Router",
		OpenPorts: []int{53, 80, 443},
	}

	deviceType, confidence := inferDeviceType(item)
	if deviceType != "router" {
		t.Fatalf("expected router, got %q", deviceType)
	}
	if confidence == "" {
		t.Fatalf("expected confidence to be set")
	}
}
