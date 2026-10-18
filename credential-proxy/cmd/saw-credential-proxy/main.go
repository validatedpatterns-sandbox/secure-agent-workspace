package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/ca"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/config"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/kube"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/proxy"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: saw-credential-proxy serve|init-ca")
	}
	switch os.Args[1] {
	case "init-ca":
		return kube.InitCA(os.Getenv("POD_NAMESPACE"),
			env("SAW_CA_SECRET_NAME", "saw-credential-proxy-ca"),
			env("SAW_CA_CONFIGMAP_NAME", "saw-proxy-ca"))
	case "serve":
		store, err := config.New(env("SAW_CONFIG", "/etc/saw-proxy/config.json"),
			env("SAW_SECRETS", "/var/run/saw/secrets"))
		if err != nil {
			return err
		}
		s := &proxy.Server{Store: store, CA: ca.New(
			env("SAW_CA_CERT", "/var/run/saw/ca/tls.crt"),
			env("SAW_CA_KEY", "/var/run/saw/ca/tls.key"))}
		if err := s.CA.Ready(); err != nil {
			return err
		}
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", s.Health)
			if err := (&http.Server{Addr: env("SAW_HEALTH_ADDR", ":8081"), Handler: mux,
				ReadHeaderTimeout: 5 * time.Second}).ListenAndServe(); err != nil {
				log.Printf("health listener stopped: %v", err)
			}
		}()
		return (&http.Server{Addr: env("SAW_PROXY_ADDR", ":3128"), Handler: s,
			ReadHeaderTimeout: 10 * time.Second}).ListenAndServe()
	default:
		return fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
