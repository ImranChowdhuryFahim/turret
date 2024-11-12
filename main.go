package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	host       = "0.0.0.0"
	port       = "23235"
	repoDir    = ".repos"
	accessPath = "access/access.json"
)

var (
	errInvalidPath = errors.New("access denied: only /secrets and /access paths are allowed")
)

type RepoAccess struct {
	Owner     string   `json:"owner"`
	ReadKeys  []string `json:"read_keys"`
	WriteKeys []string `json:"write_keys"`
}

type app struct{}

func readAccessConfig() (map[string]RepoAccess, error) {
	repos := make(map[string]RepoAccess)

	data, err := os.ReadFile(accessPath)
	if err != nil {
		if os.IsNotExist(err) {
			return repos, nil
		}
		return nil, fmt.Errorf("failed to read access file: %w", err)
	}

	if err := json.Unmarshal(data, &repos); err != nil {
		return nil, fmt.Errorf("failed to parse access config: %w", err)
	}

	return repos, nil
}

func saveConfig(repos map[string]RepoAccess) error {
	data, err := json.MarshalIndent(repos, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(accessPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

func (a app) AuthRepo(repo string, key ssh.PublicKey) git.AccessLevel {
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())
	log.Debug("checking auth", "repo", repo, "key", keyStr)

	repos, err := readAccessConfig()
	if err != nil {
		log.Error("failed to read access config", "error", err)
		return git.NoAccess
	}

	access, exists := repos[repo]
	if !exists {

		repos[repo] = RepoAccess{
			Owner:     keyStr,
			ReadKeys:  []string{},
			WriteKeys: []string{},
		}

		if err := saveConfig(repos); err != nil {
			log.Error("failed to save config", "error", err)
		}

		log.Info("created new repo", "repo", repo, "owner", keyStr)
		return git.ReadWriteAccess
	}

	if access.Owner == keyStr {
		return git.ReadWriteAccess
	}

	for _, writeKey := range access.WriteKeys {
		if writeKey == keyStr {
			return git.ReadWriteAccess
		}
	}

	for _, readKey := range access.ReadKeys {
		if readKey == keyStr {
			return git.ReadOnlyAccess
		}
	}

	return git.NoAccess
}

func (a app) AddRepoAccess(repo, ownerKeyStr, newKeyStr string, level git.AccessLevel) error {
	repos, err := readAccessConfig()
	if err != nil {
		return fmt.Errorf("failed to read access config: %w", err)
	}

	access, exists := repos[repo]
	if !exists {
		return fmt.Errorf("repository %s does not exist", repo)
	}

	if access.Owner != ownerKeyStr {
		return fmt.Errorf("only repository owner can modify access")
	}

	switch level {
	case git.ReadOnlyAccess:
		access.ReadKeys = append(access.ReadKeys, newKeyStr)
	case git.ReadWriteAccess:
		access.WriteKeys = append(access.WriteKeys, newKeyStr)
	default:
		return fmt.Errorf("invalid access level")
	}

	repos[repo] = access

	if err := saveConfig(repos); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

func (a app) RemoveRepoAccess(repo, ownerKeyStr, keyToRemove string) error {
	repos, err := readAccessConfig()
	if err != nil {
		return fmt.Errorf("failed to read access config: %w", err)
	}

	access, exists := repos[repo]
	if !exists {
		return fmt.Errorf("repository %s does not exist", repo)
	}

	if access.Owner != ownerKeyStr {
		return fmt.Errorf("only repository owner can modify access")
	}

	newReadKeys := make([]string, 0, len(access.ReadKeys))
	for _, k := range access.ReadKeys {
		if k != keyToRemove {
			newReadKeys = append(newReadKeys, k)
		}
	}
	access.ReadKeys = newReadKeys

	newWriteKeys := make([]string, 0, len(access.WriteKeys))
	for _, k := range access.WriteKeys {
		if k != keyToRemove {
			newWriteKeys = append(newWriteKeys, k)
		}
	}
	access.WriteKeys = newWriteKeys

	repos[repo] = access

	if err := saveConfig(repos); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

func (a app) Push(repo string, key ssh.PublicKey) {
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())
	log.Info("push event", "repo", repo, "key", keyStr)
}

func (a app) Fetch(repo string, key ssh.PublicKey) {
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())
	log.Info("fetch event", "repo", repo, "key", keyStr)
}

type sftpHandler struct {
	baseRoot string
	session  ssh.Session
}

func newSFTPHandler(baseRoot string, session ssh.Session) *sftpHandler {
	return &sftpHandler{
		baseRoot: baseRoot,
		session:  session,
	}
}

func checkSecretAccess(repo string, key ssh.PublicKey) bool {
	println("REEPOO", repo)
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())

	repos, err := readAccessConfig()
	if err != nil {
		log.Error("failed to read access config", "error", err)
		return false
	}

	access, exists := repos[repo]
	if !exists {
		return false
	}

	if access.Owner == keyStr {
		return true
	}

	for _, writeKey := range access.WriteKeys {
		if writeKey == keyStr {
			return true
		}
	}

	return false
}

func (s *sftpHandler) validateAndResolvePath(reqPath string, session ssh.Session) (string, error) {

	cleanPath := filepath.Clean(reqPath)

	parts := strings.Split(cleanPath, string(filepath.Separator))

	if len(parts) < 2 {
		return "", errInvalidPath
	}

	repoName := parts[1]
	if !checkSecretAccess(repoName, session.PublicKey()) {
		return "", fmt.Errorf("access denied: no write access to repository %s", repoName)
	}

	return filepath.Join(s.baseRoot, cleanPath), nil
}

func (s *sftpHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path, err := s.validateAndResolvePath(r.Filepath, s.session)
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
	path, err := s.validateAndResolvePath(r.Filepath, s.session)
	if err != nil {
		return err
	}

	var targetPath string
	if r.Target != "" {
		targetPath, err = s.validateAndResolvePath(r.Target, s.session)
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
	path, err := s.validateAndResolvePath(r.Filepath, s.session)
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
	path, err := s.validateAndResolvePath(r.Filepath, s.session)
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
		fs := newSFTPHandler(root, s)
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
	if err := os.MkdirAll(filepath.Dir(accessPath), 0755); err != nil {
		log.Error("Could not create access directory", "error", err)
		return
	}

	a := app{}
	root, _ := filepath.Abs("./secrets")
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
