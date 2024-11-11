package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/git"
	"github.com/charmbracelet/wish/logging"
	"github.com/charmbracelet/wish/scp"
	"github.com/pkg/sftp"
)

const (
	host    = "localhost"
	port    = "23235"
	repoDir = ".repos"
)

var (
	errInvalidPath = errors.New("access denied: only /secrets and /access paths are allowed")
	allowedFolders = []string{
		"secrets",
		"access",
	}
)

type app struct {
	access git.AccessLevel
}

func (a app) AuthRepo(asss string, dd ssh.PublicKey) git.AccessLevel {
	println("HEY I AM HERE", asss)
	return a.access
}

func (a app) Push(repo string, _ ssh.PublicKey) {
	log.Info("push", "repo", repo)
}

func (a app) Fetch(repo string, _ ssh.PublicKey) {
	log.Info("fetch", "repo", repo)
}

type sftpHandler struct {
	baseRoot string
}

func newSFTPHandler(baseRoot string) *sftpHandler {
	return &sftpHandler{
		baseRoot: baseRoot,
	}
}

func (s *sftpHandler) validateAndResolvePath(reqPath string) (string, error) {
	// Clean the path to remove any '..' or multiple slashes
	cleanPath := filepath.Clean(reqPath)

	// Extract the first component of the path
	parts := strings.Split(cleanPath, string(filepath.Separator))
	if len(parts) < 2 { // Must have at least "/folder"
		return "", errInvalidPath
	}

	// Check if the first folder is allowed
	firstFolder := parts[1]
	isAllowed := false
	for _, allowed := range allowedFolders {
		if firstFolder == allowed {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return "", errInvalidPath
	}

	// If allowed, resolve to the actual path
	return filepath.Join(s.baseRoot, cleanPath), nil
}

func (s *sftpHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path, err := s.validateAndResolvePath(r.Filepath)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (s *sftpHandler) Filecmd(r *sftp.Request) error {
	path, err := s.validateAndResolvePath(r.Filepath)
	if err != nil {
		return err
	}

	var targetPath string
	if r.Target != "" {
		targetPath, err = s.validateAndResolvePath(r.Target)
		if err != nil {
			return err
		}
	}

	switch r.Method {
	case "Setstat":
		return nil
	case "Remove":
		return os.Remove(path)
	case "Rename":
		return os.Rename(path, targetPath)
	case "Mkdir":
		return os.MkdirAll(path, 0755)
	case "Rmdir":
		return os.Remove(path)
	case "Symlink":
		return os.Symlink(targetPath, path)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (s *sftpHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path, err := s.validateAndResolvePath(r.Filepath)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}

type listerAt []fs.FileInfo

func (l listerAt) ListAt(ls []fs.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func (s *sftpHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path, err := s.validateAndResolvePath(r.Filepath)
	if err != nil {
		return nil, err
	}

	switch r.Method {
	case "List":
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("sftp: %w", err)
		}
		infos := make([]fs.FileInfo, len(entries))
		for i, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			infos[i] = info
		}
		return listerAt(infos), nil
	case "Stat":
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

func sftpSubsystem(root string) ssh.SubsystemHandler {
	return func(s ssh.Session) {
		log.Info("sftp root", "path", root)
		fs := newSFTPHandler(root)
		srv := sftp.NewRequestServer(s, sftp.Handlers{
			FileGet:  fs,
			FilePut:  fs,
			FileCmd:  fs,
			FileList: fs,
		})
		if err := srv.Serve(); err == io.EOF {
			if err := srv.Close(); err != nil {
				wish.Fatalln(s, "sftp:", err)
			}
		} else if err != nil {
			wish.Fatalln(s, "sftp:", err)
		}
	}
}

func main() {
	a := app{git.ReadWriteAccess}
	root, _ := filepath.Abs("./testdata")
	handler := scp.NewFileSystemHandler(root)
	s, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort(host, port)),
		wish.WithHostKeyPath(".ssh/id_ed25519"),
		ssh.PublicKeyAuth(func(c ssh.Context, k ssh.PublicKey) bool {
			println("AAXCHI", base64.StdEncoding.EncodeToString(k.Marshal()))
			return true
		}),
		ssh.PasswordAuth(func(ssh.Context, string) bool { return false }),
		wish.WithSubsystem("sftp", sftpSubsystem(root)),
		wish.WithMiddleware(
			scp.Middleware(handler, handler),
			git.Middleware(repoDir, a),
			gitListMiddleware,
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

func gitListMiddleware(next ssh.Handler) ssh.Handler {
	return func(sess ssh.Session) {
		if len(sess.Command()) != 0 {
			next(sess)
			return
		}

		dest, err := os.ReadDir(repoDir)
		if err != nil && err != fs.ErrNotExist {
			log.Error("Invalid repository", "error", err)
		}
		if len(dest) > 0 {
			fmt.Fprintf(sess, "\n### Repo Menu ###\n\n")
		}
		for _, dir := range dest {
			wish.Println(sess, fmt.Sprintf("• %s - ", dir.Name()))
			wish.Println(sess, fmt.Sprintf("git clone ssh://%s/%s", net.JoinHostPort(host, port), dir.Name()))
		}
		wish.Printf(sess, "\n\n### Add some repos! ###\n\n")
		wish.Printf(sess, "> cd some_repo\n")
		wish.Printf(sess, "> git remote add wish_test ssh://%s/some_repo\n", net.JoinHostPort(host, port))
		wish.Printf(sess, "> git push wish_test\n\n\n")
		next(sess)
	}
}
