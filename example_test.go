package netl_test

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/f9a/netl"
	"github.com/kelseyhightower/envconfig"
)

var hello = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello %s", r.RemoteAddr)
})

func ExampleNew_flag() {
	f := flag.NewFlagSet("listener", flag.ExitOnError)
	cfg := netl.Config{}
	netl.FlagSet(f, &cfg)
	err := f.Parse([]string{"-addr", ":7331"})
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(cfg.Addr)
	// Output: :7331

	listener, err := cfg.Listen()
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Listen on", listener.Addr())
	go http.Serve(listener, hello)
}

func ExampleNew_env() {
	os.Setenv("DELPHINE_MEN_ADDR", "127.0.0.1:0")

	cfg := netl.Config{}
	err := envconfig.Process("DELPHINE_MEN", &cfg)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(cfg.Addr)
	// Output: 127.0.0.1:0

	listener, err := cfg.Listen()
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Listen on", listener.Addr())
	go http.Serve(listener, hello)
}
