package netl

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

var (
	// ErrFieldIsMissing is used with FieldError when a required field is missing.
	ErrFieldIsMissing = errors.New("field is required")

	// ErrFieldWrongFormat is used with FieldError when a field has not the required format.
	ErrFieldWrongFormat = errors.New("field input has wrong format")
)

// FieldError is returned when Listener is not valid.
type FieldError struct {
	Field string
	Err   error
	Value interface{}
}

// Error satisfies error interface
func (err FieldError) Error() string {
	val := ""
	if err.Value != nil {
		val = fmt.Sprintf(" (value: %s)", err.Value)
	}
	return fmt.Sprintf("%s: %s%s", err.Field, err.Err, val)
}

var matchSocketActivation = regexp.MustCompile(`socket-activation(@([a-zA-Z-_]{1,50})|)$`)

// Addr represents a listener address
type Addr string

func (addr Addr) String() string {
	return string(addr)
}

// Set satisfies the flag.Value interface.
// Also used by https://github.com/kelseyhightower/envconfig..
func (addr *Addr) Set(value string) (err error) {
	*addr, err = AddrFromString(value)
	if err != nil {
		return
	}

	return
}

// IsSocketActivation checks if the Addr is a systemd-socket-activation
func (addr Addr) IsSocketActivation() bool {
	return matchSocketActivation.MatchString(string(addr))
}

// AddrFromString creates a new Addr from given string.
// Addr can be used in different variations. First, a simple ip-port combination (127.0.0.1:30221).
// To specify only the port, simply specify :$PORT. Then the daemon binds to all IP addresses and listen and $PORT.
// If you want to use the next free port you can specify port 0.
// If you pass the string "socket-activation" the socket activation of systemd is used.
// Additionally it is possible to define a socket name, which is separated by @ (socket-activation@nice-socket-name)
func AddrFromString(m string) (addr Addr, err error) {
	if m == "" {
		err = FieldError{
			Field: "Addr",
			Err:   ErrFieldIsMissing,
			Value: addr,
		}

		return
	}

	if matchSocketActivation.MatchString(m) {
		addr = Addr(m)
		return
	}

	_, _, err = net.SplitHostPort(m)
	if err != nil {
		err = FieldError{
			Field: "Addr",
			Err:   ErrFieldWrongFormat,
			Value: addr,
		}

		return
	}

	addr = Addr(m)
	return
}

// AddrFromNetAddr creates a new Addr from net.Addr
func AddrFromNetAddr(addr net.Addr) Addr {
	return Addr(addr.String())
}

// ValidateTLSFiles checks that cert and key are valid X509 certificates.
func ValidateTLSFiles(cert, key string) (err error) {
	_, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		err = FieldError{
			Field: "TLSCert,TLSKey",
			Err:   fmt.Errorf("certificate or key file is incorrect: %s", err),
		}

		return
	}

	return nil
}

// LetsEncryptDomains defines a list of domains for which a certificate should be requested or managed by Let's encrypt.
type LetsEncryptDomains []string

func (dd LetsEncryptDomains) String() string {
	return strings.Join(dd, ",")
}

// Set satisfies the flag.Value interface.
// Also used by https://github.com/kelseyhightower/envconfig..
func (dd *LetsEncryptDomains) Set(value string) (err error) {
	*dd, err = LetsEncryptDomainsFromString(value)
	if err != nil {
		return
	}

	return
}

// LetsEncryptDomainsFromString takes a list of comma seperated domains
// and creates a new LetsEncryptDomains list out of it.
func LetsEncryptDomainsFromString(value string) (domains LetsEncryptDomains, err error) {
	if value == "" {
		err = errors.New("at least one domain is required")
		return
	}

	dd := strings.Split(value, ",")
	domains = LetsEncryptDomains(dd)

	return
}

// Config defines possible configuration for the http daemon
type Config struct {
	// See comment for NewAddrFromString for possible configurations.
	Addr                Addr               `envconfig:"ADDR" ini:"addr" json:"addr" yaml:"addr"`
	TLSCert             string             `envconfig:"TLS_CERT" ini:"tls-cert" json:"tlsCert" yaml:"tlsCert"`
	TLSKey              string             `envconfig:"TLS_KEY" ini:"tls-key" json:"tlsKey" yaml:"tlsKey"`
	LetsEncryptEmail    string             `envconfig:"LETS_ENCRYPT_EMAIL" ini:"lets-encrypt-email" json:"letsEncryptEmail" yaml:"letsEncryptEmail"`
	LetsEncryptCacheDir string             `envconfig:"LETS_ENCRYPT_CACHE_DIR" ini:"lets-encrypt-cache-dir" json:"letsEncryptCacheDir" yaml:"letsEncryptCacheDir"`
	LetsEncryptDomains  LetsEncryptDomains `envconfig:"LETS_ENCRYPT_DOMAINS" ini:"lets-encrypt-domains" json:"letsEncryptDomains" yaml:"letsEncryptDomains"`
}

// Validate verifies if Listener is valid.
func (cfg Config) Validate() error {
	if cfg.Addr == "" {
		return FieldError{
			Field: "addr",
			Err:   ErrFieldIsMissing,
		}
	}

	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		return ValidateTLSFiles(cfg.TLSCert, cfg.TLSKey)
	}

	if (cfg.TLSCert != "" || cfg.TLSKey != "") &&
		(cfg.LetsEncryptEmail != "" ||
			cfg.LetsEncryptCacheDir != "" ||
			len(cfg.LetsEncryptDomains) != 0) {
		return errors.New("tls-* and lets-encrypt-* settings cannot be used together")
	}

	return nil
}

// SocketName returns the socket name specified by the user.
// It is possible to define a socket name by appending it separated by an @ to SocketActivationPrefix in Config.Addr.
// If socket activation is not used, name will be empty a string and ok will be false.
func (cfg Config) SocketName() (string, bool) {
	if cfg.Addr.IsSocketActivation() {
		ss := strings.Split(cfg.Addr.String(), "@")
		if len(ss) == 1 {
			return "", true
		}

		return ss[1], true
	}

	return "", false
}

func tlsListener(addr Addr, tlsCert, tlsKey string) (net.Listener, error) {
	cert, _ := tls.LoadX509KeyPair(tlsCert, tlsKey)

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: []tls.Certificate{cert},
	}

	return tls.Listen("tcp", addr.String(), tlsCfg)
}

// Listen creates a new net.Listner based on the configuration
func (cfg Config) Listen() (l net.Listener, err error) {
	if err = cfg.Validate(); err != nil {
		return
	}

	if cfg.Addr.IsSocketActivation() {
		socketName, _ := cfg.SocketName()
		l, err = receiveSocketFromSystemd(socketName)
		if err != nil {
			return
		}
	} else if cfg.TLSCert != "" {
		l, err = tlsListener(cfg.Addr, cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return
		}
	} else if len(cfg.LetsEncryptDomains) > 0 {
		m := &autocert.Manager{
			Email:      cfg.LetsEncryptEmail,
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.LetsEncryptDomains...),
		}

		if cfg.LetsEncryptCacheDir != "" {
			m.Cache = autocert.DirCache(cfg.LetsEncryptCacheDir)
		}

		l = m.Listener()
	} else {
		l, err = net.Listen("tcp", cfg.Addr.String())
		if err != nil {
			return
		}
	}

	return
}

// FlagSet applies flags to given flag-set
func FlagSet(f *flag.FlagSet, cfg *Config) {
	f.Var(&cfg.Addr, "addr", "Addr for http daemon.\nPossible values [$ip:$port|socket-activation@$socket-name|$ip:0].\n$ip and $socket-name is optional")
	f.StringVar(&cfg.TLSCert, "tls-cert", "", "Path to tls-cert for http daemon.")
	f.StringVar(&cfg.TLSKey, "tls-key", "", "Path to tls-key for http daemon")
	f.StringVar(&cfg.LetsEncryptEmail, "lets-encrypt-email", "", "Let's encrypt account email")
	f.StringVar(&cfg.LetsEncryptCacheDir, "lets-encrypt-cache-dir", "", "Let's encrypt cache-dir")
	f.Var(&cfg.LetsEncryptDomains, "lets-encrypt-domains", "List of domains (comma seperated)")

	return
}

// Flag applies default flags and parse it
func Flag() (cfg Config, err error) {
	f := flag.NewFlagSet("httpd", flag.ExitOnError)
	FlagSet(f, &cfg)

	err = f.Parse(os.Args)
	if err != nil {
		return
	}

	err = cfg.Validate()

	return
}
