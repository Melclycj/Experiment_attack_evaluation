// Command engine-mcp is the in-cell MCP server for host-file reads, in Go with the standard library only.
//
// Not in the TCB, utility only. The child starts it inside the cell as uid_i under the agent's seccomp policy, before
// the agent, with  argv: [options...] <file socket path> <port> <ready file>  (the same tail as the frontend). It
// listens on 127.0.0.1:<port> for MCP's Streamable HTTP transport (mcp.go) and offers three tools (tools.go) that map
// an absolute host path to a registered object and ask the row's file worker over the file port (wire.go). It holds
// no file descriptor of the host and decides nothing: the worker and the core check every request as untrusted input,
// so an agent speaking the file port directly is equivalent to going through here.
package main

import (
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
	fs := flag.NewFlagSet("engine-mcp", flag.ContinueOnError)
	if err := fs.Parse(argv); err != nil || fs.NArg() != 3 {
		fmt.Fprintln(os.Stderr, "usage: engine-mcp <file socket> <port> <ready file>")
		return 2
	}
	socket, readyFile := fs.Arg(0), fs.Arg(2)
	port, err := strconv.Atoi(fs.Arg(1))
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintln(os.Stderr, "engine-mcp: port must be an integer in 1..65535")
		return 2
	}
	log.SetPrefix("engine-mcp ")
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		log.Printf("ERROR listen: %v", err)
		return 1
	}
	srv := &http.Server{Handler: newServer(socket, port), ErrorLog: log.Default()}
	// the listener is up before 'ready' is said: the child waits for this file before it starts the agent
	ready, err := os.OpenFile(readyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		log.Printf("ERROR ready file: %v", err)
		return 1
	}
	ready.Close()
	log.Printf("INFO ready: MCP on http://127.0.0.1:%d/mcp, file port %s", port, socket)
	err = srv.Serve(listener)
	log.Printf("ERROR serve: %v", err)
	return 1
}
