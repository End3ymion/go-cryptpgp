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
	// Only check IsLocked if it is private to avoid "public key cannot be lock" error
	if isPrivate {
		isLocked, _ = key.IsLocked()
	}
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
			// Try to add key to new keyring
			if err := newKeyring.AddKey(key); err != nil {
				// If adding fails (e.g., locked private key), add public part
				pub, _ := key.ToPublic()
				newKeyring.AddKey(pub)
			}
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

// encryptFile encrypts a file for a specific recipient using Key ID.
// Optionally signs it if signKeyID is provided.
func (m *PGPManager) encryptFile(inputFile, recipientKeyID, signKeyID, signPassphrase, outputDir string) error {
	// Determine mode: If no recipient is selected, we are in "Sign Only" mode.
	isSignOnly := (recipientKeyID == "")

	// 1. Find Recipient Key (Only if we are encrypting)
	var foundKey *crypto.Key
	if !isSignOnly {
		for _, key := range m.keyring.GetKeys() {
			if key.GetHexKeyID() == recipientKeyID {
				foundKey = key
				break
			}
		}
		if foundKey == nil {
			return fmt.Errorf("recipient key not found")
		}
	}

	// 2. Prepare Signing Key (Common for both modes if signing is requested)
	var signKey *crypto.Key
	if signKeyID != "" {
		keyPath, err := findKeyFile(signKeyID)
		if err != nil { return fmt.Errorf("signing key file not found: %v", err) }
		
		keyData, err := os.ReadFile(keyPath)
		if err != nil { return err }

		signKey, err = crypto.NewKeyFromArmored(string(keyData))
		if err != nil {
			signKey, err = crypto.NewKey(keyData)
			if err != nil { return fmt.Errorf("bad signing key format: %v", err) }
		}

		if !signKey.IsPrivate() {
			return fmt.Errorf("selected signing key does not contain a private key")
		}

		isLocked, _ := signKey.IsLocked()
		if isLocked {
			if signPassphrase == "" {
				return fmt.Errorf("signing key is locked; passphrase required")
			}
			signKey, err = signKey.Unlock([]byte(signPassphrase))
			if err != nil {
				return fmt.Errorf("signing key unlock failed: %v", err)
			}
		}
	}

	// Validation: Must do at least one thing
	if isSignOnly && signKey == nil {
		return fmt.Errorf("operation must either have a recipient (encrypt) or a signing key (sign)")
	}

	// 3. Perform Operation
	data, err := os.ReadFile(inputFile)
	if err != nil { return err }

	// Determine output path
	targetDir := filepath.Dir(inputFile)
	if outputDir != "" {
		targetDir = outputDir
	}
	baseName := filepath.Base(inputFile)

	if isSignOnly {
		// --- SIGN ONLY MODE (Detached Signature) ---
		signHandle, err := m.pgp.Sign().
			SigningKey(signKey).
			Detached().
			New()
		if err != nil { return err }

		// 1 implies Armored encoding (0=Bytes, 1=Armor, 2=Auto)
		signature, err := signHandle.Sign(data, 1) 
		if err != nil { return err }

		return os.WriteFile(filepath.Join(targetDir, baseName+".sig"), signature, 0644)

	} else {
		// --- ENCRYPT (+ Optional Sign) MODE ---
		builder := m.pgp.Encryption().Recipient(foundKey)
		if signKey != nil {
			builder = builder.SigningKey(signKey)
		}

		encryptionHandle, err := builder.New()
		if err != nil { return err }

		pgpMessage, err := encryptionHandle.Encrypt(data)
		if err != nil { return err }

		armored, err := pgpMessage.Armor()
		if err != nil { return err }
		
		return os.WriteFile(filepath.Join(targetDir, baseName+".pgp"), []byte(armored), 0644)
	}
}

// EncryptFileSymmetric encrypts a file using a passphrase (symmetric encryption).
func (m *PGPManager) EncryptFileSymmetric(inputFile, password, outputDir string) error {
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

	targetDir := filepath.Dir(inputFile)
	if outputDir != "" {
		targetDir = outputDir
	}
	baseName := filepath.Base(inputFile)

	return os.WriteFile(filepath.Join(targetDir, baseName+".pgp"), []byte(armored), 0644)
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

// decryptAndVerify decrypts data and automatically verifies signatures using the loaded keyring.
// Returns the plaintext bytes and a formatted status string describing the signature status.
func (m *PGPManager) decryptAndVerify(ciphertext []byte, passphrase, keyID string) ([]byte, string, error) {
	// Symmetric decryption
	if keyID == "" {
		decHandle, err := m.pgp.Decryption().Password([]byte(passphrase)).New()
		if err != nil { return nil, "", err }
		
		// 0 represents 'Bytes' (binary) encoding in gopenpgp if constants.Bytes is missing
		msg, err := decHandle.Decrypt(ciphertext, 0)
		if err != nil {
			return nil, "", fmt.Errorf("symmetric decryption failed: %v", err)
		}
		return msg.Bytes(), "Symmetric (Password) - No Signature", nil
	}

	// Asymmetric decryption with automatic verification
	// Find key in memory
	var targetKey *crypto.Key
	for _, key := range m.keyring.GetKeys() {
		if key.GetHexKeyID() == keyID {
			targetKey = key
			break
		}
	}
	if targetKey == nil {
		return nil, "", fmt.Errorf("key not found in keyring")
	}

	// Load full private key from disk if memory only has the public part
	if !targetKey.IsPrivate() {
		keyPath, err := findKeyFile(keyID)
		if err != nil {
			return nil, "", fmt.Errorf("private key file missing: %v", err)
		}
		
		fileData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, "", err
		}
		
		fileKey, err := crypto.NewKeyFromArmored(string(fileData))
		if err != nil {
			return nil, "", err
		}
		
		targetKey = fileKey
	}

	// CRITICAL FIX: Check IsPrivate() BEFORE calling IsLocked()
	// gopenpgp/v3 throws "public key cannot be lock" if IsLocked() is called on a public key.
	if !targetKey.IsPrivate() {
		return nil, "", fmt.Errorf("decryption requires a private key; selected key is public only")
	}

	// Unlock key if needed
	isLocked, err := targetKey.IsLocked()
	if err != nil { return nil, "", err }

	if isLocked {
		if passphrase == "" { return nil, "", fmt.Errorf("passphrase required") }
		targetKey, err = targetKey.Unlock([]byte(passphrase))
		if err != nil { return nil, "", fmt.Errorf("incorrect passphrase") }
	}

	// Create Decryption Handle with Verification Keys (Entire Keyring)
	decHandle, err := m.pgp.Decryption().
		DecryptionKey(targetKey).
		VerificationKeys(m.keyring).
		New()
	if err != nil { return nil, "", err }

	// Use 0 for Bytes encoding
	decrypted, err := decHandle.Decrypt(ciphertext, 0)
	if err != nil {
		return nil, "", err
	}

	// Check Verification Result
	verifyStatus := "No Signature Found."
	
	// 'decrypted.VerifyResult' is a field, not a method. Access it directly.
	res := decrypted.VerifyResult
	
	if res.SignatureError() == nil && len(res.Signatures) > 0 {
		// Valid Signature - Try to find who signed it
		signerID := res.SignedByKeyIdHex()
		signerName := "Unknown ID " + signerID
		
		// Lookup friendly name in keyring
		for _, k := range m.keyring.GetKeys() {
			if k.GetHexKeyID() == signerID {
				if ent := k.GetEntity(); ent != nil {
					_, id := ent.PrimaryIdentity(time.Now(), nil)
					if id != nil && id.UserId != nil {
						signerName = fmt.Sprintf("%s <%s>", id.UserId.Name, id.UserId.Email)
					}
				}
			}
		}
		verifyStatus = fmt.Sprintf("✅ Valid Signature from: %s", signerName)
	} else if err := res.SignatureError(); err != nil {
		verifyStatus = fmt.Sprintf("❌ Invalid Signature: %v", err)
	}

	return decrypted.Bytes(), verifyStatus, nil
}

// decryptFile reads a file and decrypts its content to an output file.
// If outputDir is empty, it saves to the same directory as the encrypted file.
// Returns the verification status string.
func (m *PGPManager) decryptFile(encryptedFile, passphrase, keyID, outputDir string) (string, error) {
	data, err := os.ReadFile(encryptedFile)
	if err != nil { return "", err }
	
	plaintext, verifyStatus, err := m.decryptAndVerify(data, passphrase, keyID)
	if err != nil { return "", err }
	
	// Determine output path
	baseName := filepath.Base(encryptedFile)
	// Strip known extensions
	exts := []string{".pgp", ".gpg", ".asc", ".enc"}
	outName := baseName
	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(baseName), ext) {
			outName = baseName[:len(baseName)-len(ext)]
			break
		}
	}
	// Fallback if no extension matched or name collision (simple append)
	if outName == baseName {
		outName += ".decrypted"
	}

	targetDir := filepath.Dir(encryptedFile)
	if outputDir != "" {
		targetDir = outputDir
	}
	
	outputFile := filepath.Join(targetDir, outName)
	err = os.WriteFile(outputFile, plaintext, 0644)
	return verifyStatus, err
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

	// CHECK FOR DUPLICATES
	// Using GetKeyID (uint64) instead of GetHexKeyID (string) as requested
	newID := key.GetKeyID()
	for _, k := range m.keyring.GetKeys() {
		if k.GetKeyID() == newID {
			return fmt.Errorf("key with ID %X already exists in keyring", newID)
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
