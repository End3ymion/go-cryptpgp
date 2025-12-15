package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/diamondburned/gotk4/pkg/glib/v2"
)

// Algorithm constants to match UI combo box indices
const (
	AlgoRSA3072    = 0
	AlgoRSA4096    = 1
	AlgoCurve25519 = 2
	AlgoCurve448   = 3
)

// loadKeyring initializes the keyring directory and loads all valid keys into memory.
// It skips duplicate keys and handles locked private keys by loading their public components
// to ensure they are visible in the UI.
// This function is designed to run in a background goroutine to avoid blocking the UI.
func (m *PGPManager) loadKeyring() {
	if err := os.MkdirAll(keyringPath, 0700); err != nil {
		fmt.Printf("Error creating keyring dir: %v\n", err)
		return
	}

	m.keyring, _ = crypto.NewKeyRing(nil)
	keyFiles, _ := filepath.Glob(filepath.Join(keyringPath, "*.key"))

	fmt.Printf("Found %d key files in %s\n", len(keyFiles), keyringPath)

	for _, keyFile := range keyFiles {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			continue
		}
		
		keyObj, err := crypto.NewKeyFromArmored(string(data))
		if err != nil {
			keyObj, err = crypto.NewKey(data)
			if err != nil {
				continue
			}
		}

		// Attempt to add key to keyring. If it fails (e.g., locked private key),
		// fall back to adding the public key component so it remains listable.
		if err := m.keyring.AddKey(keyObj); err != nil {
			pubKey, err := keyObj.ToPublic()
			if err == nil {
				m.keyring.AddKey(pubKey)
			}
		}
	}

	// UI updates must happen on the main GTK thread
	glib.IdleAdd(func() {
		m.refreshCombos()
		m.refreshKeyList()
	})
}

// GetKeyStatus inspects the on-disk key file to determine if a key is private and locked.
// This is necessary because the in-memory keyring may only hold the public part of a locked key.
func (m *PGPManager) GetKeyStatus(id string) (isPrivate bool, isLocked bool, err error) {
	keyPath, err := findKeyFile(id)
	if err != nil {
		return false, false, err
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return false, false, err
	}

	key, err := crypto.NewKeyFromArmored(string(data))
	if err != nil {
		key, err = crypto.NewKey(data)
		if err != nil {
			return false, false, err
		}
	}

	isPrivate = key.IsPrivate()
	isLocked, _ = key.IsLocked()
	return isPrivate, isLocked, nil
}

// saveKeyToFile writes an armored PGP key to the keyring directory.
// The filename is constructed from the sanitized email address and key ID.
func (m *PGPManager) saveKeyToFile(key *crypto.Key) error {
	if err := os.MkdirAll(keyringPath, 0700); err != nil {
		return err
	}

	id := key.GetHexKeyID()
	email := "unknown"
	
	// Attempt to extract email for filename, defaulting to "unknown" if missing.
	if key.GetEntity() != nil {
		_, ident := key.GetEntity().PrimaryIdentity(time.Now(), nil)
		if ident != nil && ident.UserId != nil {
			email = ident.UserId.Email
		}
	}

	safeEmail := strings.ReplaceAll(email, "/", "_")
	safeEmail = strings.ReplaceAll(safeEmail, "\\", "_")
	filename := filepath.Join(keyringPath, fmt.Sprintf("%s_%s.key", safeEmail, id))
	
	serialized, err := key.Armor()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(serialized), 0600)
}

// generateKey creates a new PGP key pair based on the specified parameters.
// It supports creating expired keys for testing by accepting a negative lifetime.
func (m *PGPManager) generateKey(name, email, passphrase string, algoIndex int, lifetime int) error {
	var pgpHandle *crypto.PGPHandle
	var securityLevel int8

	// Configure profile and security level based on selected algorithm
	switch algoIndex {
	case AlgoRSA3072:
		pgpHandle = crypto.PGPWithProfile(profile.RFC4880())
		securityLevel = constants.StandardSecurity
	case AlgoRSA4096:
		pgpHandle = crypto.PGPWithProfile(profile.RFC4880())
		securityLevel = constants.HighSecurity
	case AlgoCurve25519:
		pgpHandle = crypto.PGPWithProfile(profile.RFC9580())
		securityLevel = constants.StandardSecurity
	case AlgoCurve448:
		pgpHandle = crypto.PGPWithProfile(profile.RFC9580())
		securityLevel = constants.HighSecurity
	default:
		pgpHandle = crypto.PGPWithProfile(profile.Default())
		securityLevel = constants.StandardSecurity
	}

	builder := pgpHandle.KeyGeneration().AddUserId(name, email)

	// Configure lifetime. Negative lifetime indicates a test case for expired keys.
	if lifetime < 0 {
		// Create a key that appears expired by backdating its creation time.
		pastTime := time.Now().AddDate(0, 0, -2).Unix()
		builder = builder.
			GenerationTime(pastTime).
			Lifetime(86400) // Valid for 1 day, so it expired yesterday
	} else {
		builder = builder.Lifetime(int32(lifetime))
	}
	
	// Generate the key using the configured profile security level
	key, err := builder.New().GenerateKeyWithSecurity(securityLevel)
	if err != nil {
		return err
	}

	// Encrypt the private key if a passphrase is provided, then save to disk.
	if passphrase != "" {
		lockedKey, err := pgpHandle.LockKey(key, []byte(passphrase))
		if err != nil {
			return err
		}
		if err := m.saveKeyToFile(lockedKey); err != nil {
			return err
		}
		
		// Add public version to memory since locked keys cannot be added directly
		pubKey, _ := lockedKey.ToPublic()
		m.keyring.AddKey(pubKey)
	} else {
		if err := m.saveKeyToFile(key); err != nil {
			return err
		}
		m.keyring.AddKey(key)
	}

	m.refreshCombos()
	m.refreshKeyList() 
	return nil
}

// deleteKey removes a key from both the in-memory keyring and the disk storage.
func (m *PGPManager) deleteKey(targetKeyID string) error {
	// Rebuild in-memory keyring excluding the target key
	newKeyring, _ := crypto.NewKeyRing(nil)
	for _, key := range m.keyring.GetKeys() {
		if key.GetHexKeyID() != targetKeyID {
			newKeyring.AddKey(key)
		}
	}
	m.keyring = newKeyring

	// Delete corresponding file(s) from disk
	files, _ := filepath.Glob(filepath.Join(keyringPath, "*.key"))
	for _, f := range files {
		if strings.Contains(f, targetKeyID) {
			os.Remove(f)
		}
	}
	
	m.refreshCombos()
	m.refreshKeyList()
	return nil
}

// encryptFile encrypts a file for a specific recipient using their public key.
func (m *PGPManager) encryptFile(inputFile, recipientSelector string) error {
	targetID := ""
	if idx := strings.LastIndex(recipientSelector, "["); idx != -1 {
		if endIdx := strings.LastIndex(recipientSelector, "]"); endIdx != -1 && endIdx > idx {
			targetID = recipientSelector[idx+1 : endIdx]
		}
	}

	var foundKey *crypto.Key
	for _, key := range m.keyring.GetKeys() {
		if key.GetHexKeyID() == targetID {
			foundKey = key
			break
		}
	}
	if foundKey == nil {
		return fmt.Errorf("recipient key not found")
	}

	encryptionHandle, err := m.pgp.Encryption().
		Recipient(foundKey).
		New()
	if err != nil { return err }

	data, err := os.ReadFile(inputFile)
	if err != nil { return err }

	pgpMessage, err := encryptionHandle.Encrypt(data)
	if err != nil { return err }

	armored, err := pgpMessage.Armor()
	if err != nil { return err }
	
	return os.WriteFile(inputFile+".pgp", []byte(armored), 0644)
}

// EncryptFileSymmetric encrypts a file using a passphrase (symmetric encryption).
func (m *PGPManager) EncryptFileSymmetric(inputFile, password string) error {
	encryptionHandle, err := m.pgp.Encryption().
		Password([]byte(password)).
		New()
	if err != nil { return err }

	data, err := os.ReadFile(inputFile)
	if err != nil { return err }

	pgpMessage, err := encryptionHandle.Encrypt(data)
	if err != nil { return err }

	armored, err := pgpMessage.Armor()
	if err != nil { return err }

	return os.WriteFile(inputFile+".pgp", []byte(armored), 0644)
}

// findKeyFile locates the file path for a given key ID within the keyring directory.
func findKeyFile(keyID string) (string, error) {
	files, _ := filepath.Glob(filepath.Join(keyringPath, "*.key"))
	for _, f := range files {
		if strings.Contains(f, keyID) {
			return f, nil
		}
	}
	return "", fmt.Errorf("key file not found for ID: %s", keyID)
}

// decryptBytes decrypts binary data using either a passphrase or a private key.
// It handles loading and unlocking private keys from disk if required.
func (m *PGPManager) decryptBytes(ciphertext []byte, passphrase, keySelector string) ([]byte, error) {
	// Symmetric decryption
	if keySelector == "" {
		decHandle, err := m.pgp.Decryption().Password([]byte(passphrase)).New()
		if err != nil { return nil, err }
		
		msg, err := decHandle.Decrypt(ciphertext, 0)
		if err != nil {
			return nil, fmt.Errorf("symmetric decryption failed: %v", err)
		}
		return msg.Bytes(), nil
	}

	// Asymmetric decryption
	targetID := ""
	if idx := strings.LastIndex(keySelector, "["); idx != -1 {
		if endIdx := strings.LastIndex(keySelector, "]"); endIdx != -1 && endIdx > idx {
			targetID = keySelector[idx+1 : endIdx]
		}
	}

	// Find key in memory
	var targetKey *crypto.Key
	for _, key := range m.keyring.GetKeys() {
		if key.GetHexKeyID() == targetID {
			targetKey = key
			break
		}
	}
	if targetKey == nil {
		return nil, fmt.Errorf("key not found in keyring")
	}

	// Load full private key from disk if memory only has the public part
	if !targetKey.IsPrivate() {
		keyPath, err := findKeyFile(targetID)
		if err != nil {
			return nil, fmt.Errorf("private key file missing: %v", err)
		}
		
		fileData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		
		fileKey, err := crypto.NewKeyFromArmored(string(fileData))
		if err != nil {
			return nil, err
		}
		
		targetKey = fileKey
	}

	// Unlock key if needed
	isLocked, err := targetKey.IsLocked()
	if err != nil { return nil, err }

	if isLocked {
		if passphrase == "" { return nil, fmt.Errorf("passphrase required") }
		targetKey, err = targetKey.Unlock([]byte(passphrase))
		if err != nil { return nil, fmt.Errorf("incorrect passphrase") }
	}

	if !targetKey.IsPrivate() {
		return nil, fmt.Errorf("decryption requires a private key")
	}

	decHandle, err := m.pgp.Decryption().DecryptionKey(targetKey).New()
	if err != nil { return nil, err }

	decrypted, err := decHandle.Decrypt(ciphertext, 0)
	if err != nil {
		return nil, err
	}

	return decrypted.Bytes(), nil
}

// decryptFile reads a file and decrypts its content to a .decrypted output file.
func (m *PGPManager) decryptFile(encryptedFile, passphrase, keySelector string) error {
	data, err := os.ReadFile(encryptedFile)
	if err != nil { return err }
	
	plaintext, err := m.decryptBytes(data, passphrase, keySelector)
	if err != nil { return err }
	
	outputFile := strings.TrimSuffix(encryptedFile, filepath.Ext(encryptedFile)) + ".decrypted"
	return os.WriteFile(outputFile, plaintext, 0644)
}

// exportKey exports a public or private key to a file.
// If exporting a locked private key, it prompts for a passphrase to verify ownership before export.
func (m *PGPManager) exportKey(targetKeyID string, isPrivate bool, filename, passphrase string) error {
	keyPath, err := findKeyFile(targetKeyID)
	if err != nil {
		return err
	}
	
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	
	key, err := crypto.NewKeyFromArmored(string(data))
	if err != nil {
		return err
	}

	if isPrivate {
		if !key.IsPrivate() {
			return fmt.Errorf("selected key is Public Only (no private key found)")
		}

		// Verify passphrase for locked keys before allowing export
		isLocked, _ := key.IsLocked()
		if isLocked {
			if passphrase == "" {
				return fmt.Errorf("passphrase required to export private key")
			}
			_, err := key.Unlock([]byte(passphrase))
			if err != nil {
				return fmt.Errorf("incorrect passphrase")
			}
		}

		armored, err := key.Armor()
		if err != nil { return err }
		return os.WriteFile(filename, []byte(armored), 0644)
	} else {
		armored, err := key.GetArmoredPublicKey()
		if err != nil { return err }
		return os.WriteFile(filename, []byte(armored), 0644)
	}
}

// importKey reads a key file and adds it to the keyring manager.
func (m *PGPManager) importKey(keyFile string) error {
	data, err := os.ReadFile(keyFile)
	if err != nil { return err }

	key, err := crypto.NewKeyFromArmored(string(data))
	if err != nil {
		key, err = crypto.NewKey(data)
		if err != nil {
			return fmt.Errorf("invalid key format: %v", err)
		}
	}

	if err := m.saveKeyToFile(key); err != nil {
		return err
	}

	if err := m.keyring.AddKey(key); err != nil {
		pubKey, _ := key.ToPublic()
		m.keyring.AddKey(pubKey)
	}
	
	m.refreshCombos()
	m.refreshKeyList()
	return nil
}
