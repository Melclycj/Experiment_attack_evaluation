// Command engine-frontend is the in-cell HTTP frontend in Go, standard library only: the same contract as
// frontend/engine_frontend.py (agent-rm-model 4.2 代理口的形状, 6.3 TLS 行; validation.md F-01 to F-04).
//
// Not in the TCB. It runs inside the cell as uid_i under the agent's seccomp policy, started by the child before the
// agent with  argv: [options...] <proxy socket path> <port> <ready file>  (child.c start_helper). It listens on
// 127.0.0.1:<port> as a regular HTTP/1.1 proxy, terminates TLS after CONNECT with the execution's CA, turns each
// fully-read request into one canonical REQUEST frame on the row's proxy path (SPEC-canonical-form.md §3.1), and turns
// the RESP_* frames back into a streamed HTTP/1.1 response. Nothing here reads policy or holds a credential: the
// connector validates the frame as untrusted input, so an agent speaking canonical form to the path directly is
// equivalent to going through here.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	fs := flag.NewFlagSet("engine-frontend", flag.ContinueOnError)
	caDir := fs.String("ca-dir", "", "directory with ca.pem and ca.key (the cell files)")
	confdir := fs.String("confdir", "/tmp/.w2-frontend", "where mitmproxy-ca.pem is kept")
	fs.Int("translator-port", 0, "accepted for the Python frontend's command line; there is no translator port here")
	fs.String("log-level", "WARNING", "accepted for the Python frontend's command line; this log is always on")
	if err := fs.Parse(argv); err != nil || fs.NArg() != 3 {
		fmt.Fprintln(os.Stderr, "usage: engine-frontend [options] <proxy socket> <port> <ready file>")
		return 2
	}
	proxySocket, readyFile := fs.Arg(0), fs.Arg(2)
	port, err := strconv.Atoi(fs.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "engine-frontend: port must be an integer")
		return 2
	}
	log.SetPrefix("engine-frontend ")
	certs, err := prepareCA(*confdir, *caDir)
	if err != nil {
		log.Printf("ERROR certificate authority: %v", err)
		return 1
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		log.Printf("ERROR listen: %v", err)
		return 1
	}
	f := &front{path: &proxyPath{path: proxySocket}, certs: certs, inner: newConnQueue(listener.Addr())}
	var protocols http.Protocols
	protocols.SetHTTP1(true) // HTTP/1.1 only: no h2, no h2c (ALPN offers HTTP/1 only, see pickALPN)
	srv := &http.Server{
		Handler:   f,
		Protocols: &protocols,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if t, ok := c.(*tunnelConn); ok {
				return context.WithValue(ctx, tunnelKey{}, t.dest)
			}
			return ctx
		},
		ErrorLog: log.Default(),
	}
	go srv.Serve(f.inner)
	// the listener is up before 'ready' is said: the child waits for this file (child.c wait_ready)
	ready, err := os.OpenFile(readyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		log.Printf("ERROR ready file: %v", err)
		return 1
	}
	ready.Close()
	log.Printf("INFO ready: proxy on 127.0.0.1:%d", port)
	err = srv.Serve(listener)
	log.Printf("ERROR serve: %v", err)
	return 1
}
