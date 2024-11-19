package handlers

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"turret/internal/config"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/git"
)

const (
	host = "0.0.0.0"
	port = "23235"
)
const (
	RepoDir = ".repos"
)

type App struct{}

func (a App) AuthRepo(repo string, key ssh.PublicKey) git.AccessLevel {
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())
	log.Debug("checking auth", "repo", repo, "key", keyStr)

	repos, err := config.ReadAccessConfig()
	if err != nil {
		log.Error("failed to read access config", "error", err)
		return git.NoAccess
	}

	access, exists := repos[repo]
	if !exists {

		repos[repo] = config.RepoAccess{
			Owner:     keyStr,
			ReadKeys:  []string{},
			WriteKeys: []string{},
		}

		if err := config.SaveConfig(repos); err != nil {
			log.Error("failed to save config", "error", err)
		}

		log.Info("created new repo", "repo", repo, "owner", keyStr)

		if err := os.MkdirAll(filepath.Join("secrets", repo), 0755); err != nil {
			log.Error("Failed to create secrets dir", "error", err)
		}

		log.Info("created secrets dir for repo: ", repo)
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

func (a App) Push(repo string, key ssh.PublicKey) {
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())
	log.Info("push event", "repo", repo, "key", keyStr)
}

func (a App) Fetch(repo string, key ssh.PublicKey) {
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())
	log.Info("fetch event", "repo", repo, "key", keyStr)
}

func GitListMiddleware(next ssh.Handler) ssh.Handler {
	return func(sess ssh.Session) {
		if len(sess.Command()) != 0 {
			next(sess)
			return
		}

		dest, err := os.ReadDir(RepoDir)
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
