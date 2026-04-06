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

func TestInferDeviceTypeDetectsPrinterFromPorts(t *testing.T) {
	item := observedAsset{
		Hostname:  "office-printer",
		OpenPorts: []int{631, 9100},
	}

	deviceType, confidence := inferDeviceType(item)
	if deviceType != "printer" {
		t.Fatalf("expected printer, got %q", deviceType)
	}
	if confidence != "probable" && confidence != "confirmed" {
		t.Fatalf("expected stronger confidence, got %q", confidence)
	}
}

func TestInferConnectionTypePrefersWifiForPhones(t *testing.T) {
	item := observedAsset{
		Hostname: "pixel-8",
		OSName:   "Android 15",
	}

	connectionType, confidence := inferConnectionType(item)
	if connectionType != "wifi" {
		t.Fatalf("expected wifi, got %q", connectionType)
	}
	if confidence == "" {
		t.Fatalf("expected confidence to be set")
	}
}
