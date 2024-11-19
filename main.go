package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"turret/internal/config"
	"turret/internal/handlers"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/git"
	"github.com/charmbracelet/wish/logging"
	"github.com/charmbracelet/wish/scp"
)

const (
	host    = "0.0.0.0"
	port    = "23235"
	repoDir = ".repos"
)

func main() {
	if err := os.MkdirAll(filepath.Dir(config.AccessPath), 0755); err != nil {
		log.Error("Could not create access directory", "error", err)
		return
	}

	a := handlers.App{}
	root, _ := filepath.Abs("./secrets")
	handler := scp.NewFileSystemHandler(root)
	s, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort(host, port)),
		wish.WithHostKeyPath(".ssh/id_ed25519"),
		wish.WithAuthorizedKeys(".ssh/authorized_keys"),
		ssh.PasswordAuth(func(ssh.Context, string) bool { return false }),
		wish.WithSubsystem("sftp", handlers.SftpSubsystem(root)),
		wish.WithMiddleware(
			scp.Middleware(handler, handler),
			git.Middleware(repoDir, a),
			handlers.GitListMiddleware,
			logging.Middleware(),
		),
	)
	if err != nil {
		log.Error("Could not start server", "error", err)
		return
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	log.Info("Starting SSH server", "host", host, "port", port)
	go func() {
		if err = s.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			log.Error("Could not start server", "error", err)
			done <- nil
		}
	}()

	<-done
	log.Info("Stopping SSH server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		log.Error("Could not stop server", "error", err)
	}
}
