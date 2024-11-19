package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
)

const (
	AccessPath = "access/access.json"
)

type RepoAccess struct {
	Owner     string   `json:"owner"`
	ReadKeys  []string `json:"read_keys"`
	WriteKeys []string `json:"write_keys"`
}

func ReadAccessConfig() (map[string]RepoAccess, error) {
	repos := make(map[string]RepoAccess)

	data, err := os.ReadFile(AccessPath)
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

func SaveConfig(repos map[string]RepoAccess) error {
	data, err := json.MarshalIndent(repos, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(AccessPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

func CheckSecretAccess(repo string, key ssh.PublicKey) bool {
	keyStr := base64.StdEncoding.EncodeToString(key.Marshal())

	repos, err := ReadAccessConfig()
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
