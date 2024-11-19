package handlers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"turret/internal/config"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/pkg/sftp"
)

var (
	errInvalidPath = errors.New("access denied: only /secrets and /access paths are allowed")
)

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

func (s *sftpHandler) validateAndResolvePath(reqPath string, session ssh.Session) (string, error) {

	cleanPath := filepath.Clean(reqPath)

	parts := strings.Split(cleanPath, string(filepath.Separator))

	if len(parts) < 2 {
		return "", errInvalidPath
	}

	repoName := parts[1]
	if !config.CheckSecretAccess(repoName, session.PublicKey()) {
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

func SftpSubsystem(root string) ssh.SubsystemHandler {
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
