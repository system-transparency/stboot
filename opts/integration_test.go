package opts

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOptsLoader(t *testing.T) {
	tmp, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	sc := Security{
		ValidSignatureThreshold: 2,
		BootMode:                NetworkBoot,
		UsePkgCache:             true,
	}
	scPath := filepath.Join(tmp, "securityconfig.json")

	provURL, _ := url.Parse("https://server.com")
	hc := HostCfg{
		IPAddrMode:       IPDynamic,
		ProvisioningURLs: []*url.URL{provURL},
	}
	hcPath := filepath.Join(tmp, "hostconfig.json")

	scb, err := json.Marshal(&sc)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(scPath, scb, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}
	hcb, err := json.Marshal(&hc)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(hcPath, hcb, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	want := &Opts{
		Security: sc,
		HostCfg:  hc,
	}
	got, err := NewOpts(NewSecurityFile(scPath), NewHostCfgFile(hcPath))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
