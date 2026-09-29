//go:build linux

// Transparent byte relay: SPIRE TLS authentication remains end to end.
package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	upstream := os.Getenv("SPIRE_SERVER")
	if upstream == "" {
		log.Fatal("SPIRE_SERVER must be explicit")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		log.Fatal("VSOCK socket unavailable")
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 18081}); err != nil {
		log.Fatal("VSOCK bind failed; another listener may own this port")
	}
	if err = unix.Listen(fd, 128); err != nil {
		log.Fatal("VSOCK listen failed")
	}
	go func() {
		server := &http.Server{Addr: ":18082", ReadHeaderTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(http.StatusOK)
			})}
		log.Fatal(server.ListenAndServe())
	}()
	connections := make(chan struct{}, 128)
	for {
		client, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			log.Fatal("VSOCK accept failed")
		}
		select {
		case connections <- struct{}{}:
			go func() {
				defer func() { <-connections }()
				guest := os.NewFile(uintptr(client), "vsock")
				defer guest.Close()
				server, err := net.DialTimeout("tcp", upstream, 10*time.Second)
				if err != nil {
					return
				}
				defer server.Close()
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(server, guest)
					_ = server.(*net.TCPConn).CloseWrite()
					close(done)
				}()
				_, _ = io.Copy(guest, server)
				_ = unix.Shutdown(client, unix.SHUT_RDWR)
				<-done
			}()
		default:
			_ = unix.Close(client)
		}
	}
}
