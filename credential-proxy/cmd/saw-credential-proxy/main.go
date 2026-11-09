package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/ca"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/config"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/kube"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/oauth"
	"github.com/validatedpatterns-sandbox/secure-agent-workspace/credential-proxy/internal/proxy"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func healthAddress() (string, error) {
	address := env("SAW_HEALTH_ADDR", "127.0.0.1:8081")
	host, port, err := net.SplitHostPort(address)
	number, parseErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || number < 1 || number > 65535 || (host != "127.0.0.1" && host != "::1") {
		return "", fmt.Errorf("health listener must use a loopback IP and valid port")
	}
	return address, nil
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: saw-credential-proxy serve|init-ca|healthcheck")
	}
	switch os.Args[1] {
	case "healthcheck":
		address, err := healthAddress()
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
		defer client.CloseIdleConnections()
		resp, err := client.Get("http://" + address + "/healthz")
		if err != nil {
			return fmt.Errorf("health check unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("health check failed")
		}
		return nil
	case "init-ca":
		return kube.InitCA(os.Getenv("POD_NAMESPACE"),
			env("SAW_CA_SECRET_NAME", "saw-credential-proxy-ca"),
			env("SAW_CA_CONFIGMAP_NAME", "saw-proxy-ca"))
	case "serve":
		address, err := healthAddress()
		if err != nil {
			return err
		}
		store, err := config.New(env("SAW_CONFIG", "/etc/saw-proxy/config.json"),
			env("SAW_SECRETS", "/var/run/saw/secrets"))
		if err != nil {
			return err
		}
		store.Broker = &oauth.Broker{}
		s := &proxy.Server{Store: store, CA: ca.New(
			env("SAW_CA_CERT", "/var/run/saw/ca/tls.crt"),
			env("SAW_CA_KEY", "/var/run/saw/ca/tls.key"))}
		if err := s.CA.Ready(); err != nil {
			return err
		}
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /healthz", s.Health)
			if err := (&http.Server{Addr: address, Handler: mux,
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
