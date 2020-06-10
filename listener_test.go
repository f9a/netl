package netl_test

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/f9a/netl"
	"github.com/stretchr/testify/require"
)

func TestListen(t *testing.T) {
	addr, err := netl.AddrFromString(":0")
	if err != nil {
		t.Fatal(err)
	}

	cfg := netl.Config{
		Addr: addr,
	}

	listener, err := cfg.Listen()
	require.Nil(t, err)

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
			return
		}))
	}()

	rp, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if rp.StatusCode != http.StatusOK {
		t.Fatalf("Want status-code %v, got %v", http.StatusOK, rp.StatusCode)
	}

	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}
}

const certPem = `-----BEGIN CERTIFICATE-----
MIICJTCCAasCCQC2CZPi68r5sTAKBggqhkjOPQQDAjB8MQswCQYDVQQGEwJkZTEQ
MA4GA1UECAwHQmFXw4PCvDESMBAGA1UEBwwJU3R1dHRnYXJ0MRMwEQYDVQQKDAph
bnRzLmhvdXNlMRIwEAYDVQQDDAlsb2NhbGhvc3QxHjAcBgkqhkiG9w0BCQEWD2Z1
bmNAYW50cy5ob3VzZTAeFw0yMDA2MTAxODM0MzZaFw0zMDA2MDgxODM0MzZaMHwx
CzAJBgNVBAYTAmRlMRAwDgYDVQQIDAdCYVfDg8K8MRIwEAYDVQQHDAlTdHV0dGdh
cnQxEzARBgNVBAoMCmFudHMuaG91c2UxEjAQBgNVBAMMCWxvY2FsaG9zdDEeMBwG
CSqGSIb3DQEJARYPZnVuY0BhbnRzLmhvdXNlMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEjXeDucpD5js+I/Ei3fmXclvemH3dZqE5FzOAUSpEAV1MZsrji5QBiQfROMRy
7XBOryfRTSKD8KYHcQg1SbkiU7FULdU8b+tqnyBGTmGdElqO/6Edeen/ovdkVjqJ
tT8OMAoGCCqGSM49BAMCA2gAMGUCMDHfee4ED32+fg4lJmi0UPxx+a9p8XUcnr5h
9I3jLTrbh2jOmgIdGLrq8X8lhhONewIxAOBdvC/P7msb4xtMjW1vqSA+3VDEVClm
pQrC0Z1rQDMewz4gu54YwiNXmfTAPGvYuQ==
-----END CERTIFICATE-----`

const keyPem = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCRD0hSq6R9ed0bg0dzGUiAu72Eqgwn3EvzhOB71QdvogRNxB7/RxZ/
LT2697pQ3nOgBwYFK4EEACKhZANiAASNd4O5ykPmOz4j8SLd+ZdyW96Yfd1moTkX
M4BRKkQBXUxmyuOLlAGJB9E4xHLtcE6vJ9FNIoPwpgdxCDVJuSJTsVQt1Txv62qf
IEZOYZ0SWo7/oR156f+i92RWOom1Pw4=
-----END EC PRIVATE KEY-----`

func createTempFile(t *testing.T, content string) (name string, remove func()) {
	fh, err := ioutil.TempFile(".", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.WriteString(fh, content)
	if err != nil {
		t.Fatal(err)
	}
	err = fh.Close()
	if err != nil {
		t.Fatal(err)
	}

	return fh.Name(), func() {
		err = os.Remove(fh.Name())
		if err != nil {
			t.Fatal(err)
		}
	}

}

func TestListenTLS(t *testing.T) {
	addr, err := netl.AddrFromString(":52352")
	if err != nil {
		t.Fatal(err)
	}

	certFile, removeCertFile := createTempFile(t, certPem)
	defer removeCertFile()

	keyFile, removeKeyFile := createTempFile(t, keyPem)
	defer removeKeyFile()

	cfg := netl.Config{
		Addr:    addr,
		TLSCert: certFile,
		TLSKey:  keyFile,
	}

	listener, err := cfg.Listen()
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			return
		}))
	}()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	rp, err := client.Get("https://localhost:52352")
	if err != nil {
		t.Fatal(err)
	}
	if rp.StatusCode != http.StatusOK {
		t.Fatalf("Want status-code %v, got %v", http.StatusOK, rp.StatusCode)
	}

	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}
}
