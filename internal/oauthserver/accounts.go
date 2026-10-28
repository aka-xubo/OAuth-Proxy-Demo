package oauthserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const DefaultDatabasePath = "./oauth-users.db"

type account struct {
	TenantID     string
	Username     string
	PasswordHash []byte
}

type accountStore struct {
	db        *sql.DB
	dummyHash []byte
}

func openAccountStore(ctx context.Context, path string, bootstrap []Account) (*accountStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// A single connection keeps the connection-local busy timeout consistent.
	db.SetMaxOpenConns(1)
	store := &accountStore{db: db}
	if _, err = db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err == nil {
		err = store.initialize(ctx, bootstrap)
	}
	if err == nil {
		store.dummyHash, err = bcrypt.GenerateFromPassword([]byte("dummy-password-not-a-real-account"), bcrypt.DefaultCost)
	}
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize account database: %w", err)
	}
	return store, nil
}

func (s *accountStore) initialize(ctx context.Context, bootstrap []Account) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Schema, seed, and marker commit together. The marker is independent of
	// account count, so deleting even all accounts does not trigger reseeding.
	_, err = tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS accounts (
 tenant_id TEXT NOT NULL CHECK (length(tenant_id) > 0 AND instr(tenant_id, ':') = 0 AND instr(tenant_id, ' ') = 0 AND instr(tenant_id, char(9)) = 0 AND instr(tenant_id, char(10)) = 0 AND instr(tenant_id, char(13)) = 0),
 username TEXT NOT NULL CHECK (length(username) > 0 AND instr(username, ':') = 0 AND instr(username, ' ') = 0 AND instr(username, char(9)) = 0 AND instr(username, char(10)) = 0 AND instr(username, char(13)) = 0),
 password_hash BLOB NOT NULL CHECK (length(password_hash) > 0),
 PRIMARY KEY (tenant_id, username)
);
CREATE TABLE IF NOT EXISTS account_initialization (
 id INTEGER PRIMARY KEY CHECK (id = 1)
);`)
	if err != nil {
		return err
	}
	var initialized int
	err = tx.QueryRowContext(ctx, "SELECT id FROM account_initialization WHERE id = 1").Scan(&initialized)
	if err == nil {
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if len(bootstrap) == 0 {
		bootstrap = defaultAccounts()
	}
	if err := validateAccounts(bootstrap); err != nil {
		return err
	}
	for _, item := range bootstrap {
		hash, err := bcrypt.GenerateFromPassword([]byte(item.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash bootstrap password: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO accounts (tenant_id, username, password_hash) VALUES (?, ?, ?)", item.TenantID, item.Username, hash); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO account_initialization (id) VALUES (1)"); err != nil {
		return err
	}
	return tx.Commit()
}

func validateAccounts(configured []Account) error {
	seen := make(map[string]struct{}, len(configured))
	for _, item := range configured {
		if item.TenantID == "" || item.Username == "" || item.Password == "" {
			return errors.New("account tenant, username, and password are required")
		}
		if strings.ContainsAny(item.TenantID, ": \t\r\n") || strings.ContainsAny(item.Username, ": \t\r\n") {
			return errors.New("account tenant and username must not contain ':' or whitespace")
		}
		key := item.TenantID + "\x00" + item.Username
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate account %s:%s", item.TenantID, item.Username)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func defaultAccounts() []Account {
	return []Account{
		{TenantID: "acme", Username: "demo", Password: "demo"},
		{TenantID: "globex", Username: "demo", Password: "demo"},
	}
}

func (s *accountStore) lookup(ctx context.Context, tenantID, username string) (account, bool, error) {
	var found account
	err := s.db.QueryRowContext(ctx, "SELECT tenant_id, username, password_hash FROM accounts WHERE tenant_id = ? AND username = ?", tenantID, username).Scan(&found.TenantID, &found.Username, &found.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return account{}, false, nil
	}
	return found, err == nil, err
}

func (s *accountStore) tenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT DISTINCT tenant_id FROM accounts ORDER BY tenant_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}
