package jrpc2

import (
	"os"
	"testing"
	"time"
)

func TestServer_StartUp(t *testing.T) {
	t.Parallel()
	in, err := os.CreateTemp("", "input")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(in.Name())
	defer in.Close()

	out, err := os.CreateTemp("", "output")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(out.Name())
	defer out.Close()

	server := NewServer()
	err = server.StartUp(in, out)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestServer_Shutdown(t *testing.T) {
	t.Parallel()
	server := NewServer()
	resultChan := make(chan error)

	go func() {
		resultChan <- server.StartUp(os.Stdin, os.Stdout)
	}()

	time.Sleep(5 * time.Second) // Give some time for the server to start

	server.Shutdown()
	select {
	case err := <-resultChan:
		if err != nil {
			t.Fatalf("Server startup failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Server startup timed out")
	}
}
