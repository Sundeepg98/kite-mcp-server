package main

import (
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "", "SQLite database path")
	oldSecret := flag.String("old-secret", "", "Current OAUTH_JWT_SECRET")
	newSecret := flag.String("new-secret", "", "New OAUTH_JWT_SECRET")
	flag.Parse()

	if *dbPath == "" || *oldSecret == "" || *newSecret == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Open DB directly
	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatal("open db: ", err)
	}
	defer db.Close()

	// Load HKDF salt from config table (may be empty for pre-salt databases).
	var salt []byte
	var saltHex string
	err = db.QueryRow(`SELECT value FROM config WHERE key = 'hkdf_salt'`).Scan(&saltHex)
	if err == nil && saltHex != "" {
		salt, err = hex.DecodeString(saltHex)
		if err != nil {
			log.Fatal("decode stored salt: ", err)
		}
		fmt.Printf("Using HKDF salt from database (%d bytes)\n", len(salt))
	} else {
		fmt.Println("No HKDF salt found in database, using nil salt (legacy)")
	}

	// Derive both keys with the same salt
	oldKey, err := alerts.DeriveEncryptionKeyWithSalt(*oldSecret, salt)
	if err != nil {
		log.Fatal("derive old key: ", err)
	}
	newKey, err := alerts.DeriveEncryptionKeyWithSalt(*newSecret, salt)
	if err != nil {
		log.Fatal("derive new key: ", err)
	}

	// Re-encrypt each table's sensitive columns
	// Tables: kite_tokens (access_token), kite_credentials (api_key, api_secret),
	// oauth_clients (client_secret), mcp_sessions (session_id_enc)
	tables := []struct {
		table   string
		pkCol   string
		columns []string
	}{
		{"kite_tokens", "email", []string{"access_token"}},
		{"kite_credentials", "email", []string{"api_key", "api_secret"}},
		{"oauth_clients", "client_id", []string{"client_secret"}},
		{"mcp_sessions", "session_id", []string{"session_id_enc"}},
	}

	for _, t := range tables {
		count, err := rotateTable(db, oldKey, newKey, t.table, t.pkCol, t.columns)
		if err != nil {
			log.Printf("ERROR rotating %s: %v", t.table, err)
		} else {
			fmt.Printf("Rotated %d rows in %s\n", count, t.table)
		}
	}

	fmt.Println("Key rotation complete. Update OAUTH_JWT_SECRET on the server.")
}

// rotateTable re-encrypts all encrypted columns in a table from oldKey to newKey.
// It reads each row by primary key, decrypts with the old key, re-encrypts with
// the new key, and updates the row.
func rotateTable(db *sql.DB, oldKey, newKey []byte, table, pkCol string, columns []string) (int, error) {
	// Build SELECT query: pk + all encrypted columns
	selectCols := pkCol
	for _, col := range columns {
		selectCols += ", " + col
	}
	query := fmt.Sprintf("SELECT %s FROM %s", selectCols, table)

	rows, err := db.Query(query)
	if err != nil {
		return 0, fmt.Errorf("query %s: %w", table, err)
	}
	defer rows.Close()

	type row struct {
		pk     string
		values []string
	}

	var allRows []row
	for rows.Next() {
		r := row{values: make([]string, len(columns))}
		// Build scan destinations: pk + each column
		scanDest := make([]interface{}, 1+len(columns))
		scanDest[0] = &r.pk
		for i := range columns {
			scanDest[i+1] = &r.values[i]
		}
		if err := rows.Scan(scanDest...); err != nil {
			return 0, fmt.Errorf("scan %s: %w", table, err)
		}
		allRows = append(allRows, r)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate %s: %w", table, err)
	}

	// Re-encrypt and update each row
	count := 0
	for _, r := range allRows {
		newValues := make([]string, len(columns))
		for i, encVal := range r.values {
			// Decrypt with old key (returns plaintext; falls back to as-is if not encrypted)
			plaintext := alerts.Decrypt(oldKey, encVal)
			// Re-encrypt with new key
			reEncrypted, err := alerts.Encrypt(newKey, plaintext)
			if err != nil {
				return count, fmt.Errorf("encrypt %s.%s for pk=%s: %w", table, columns[i], r.pk, err)
			}
			newValues[i] = reEncrypted
		}

		// Build UPDATE query
		setClauses := ""
		args := make([]interface{}, 0, len(columns)+1)
		for i, col := range columns {
			if i > 0 {
				setClauses += ", "
			}
			setClauses += col + " = ?"
			args = append(args, newValues[i])
		}
		args = append(args, r.pk)
		updateQuery := fmt.Sprintf("UPDATE %s SET %s WHERE %s = ?", table, setClauses, pkCol)

		if _, err := db.Exec(updateQuery, args...); err != nil {
			return count, fmt.Errorf("update %s pk=%s: %w", table, r.pk, err)
		}
		count++
	}

	return count, nil
}
