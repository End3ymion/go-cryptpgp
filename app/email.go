package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/joho/godotenv"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const (
	keyringService = "PGPManagerApp"
	keyringUser    = "gmail-oauth-token"
)

// AttemptSilentAuth tries to load a saved token from the system keyring to authenticate
// without opening a browser. Returns true if successful.
func (m *PGPManager) AttemptSilentAuth() bool {
	ctx := context.Background()
	config, err := m.getOAuthConfig()
	if err != nil {
		fmt.Println("Silent Auth Failed: Could not load config:", err)
		return false
	}

	tok, err := m.tokenFromKeyring()
	if err != nil {
		fmt.Println("Silent Auth Failed: No valid token found in keyring.")
		return false
	}

	client := config.Client(ctx, tok)
	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		fmt.Println("Silent Auth Failed: Could not create service:", err)
		return false
	}

	m.gmailSvc = srv
	return true
}

// authenticateGmail initiates the OAuth2 flow to authenticate with Gmail API.
func (m *PGPManager) authenticateGmail() error {
	ctx := context.Background()
	config, err := m.getOAuthConfig()
	if err != nil {
		return err
	}

	codeChan := make(chan string)
	errChan := make(chan error)
	server := &http.Server{Addr: ":8080"}

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if errMsg := r.FormValue("error"); errMsg != "" {
				fmt.Fprintf(w, "<h1>Authorization Failed</h1><p>%s</p>", errMsg)
				errChan <- fmt.Errorf("oauth error: %s", errMsg)
				return
			}
			code := r.FormValue("code")
			if code == "" {
				errChan <- fmt.Errorf("no code in response")
				return
			}
			fmt.Fprint(w, "<h1>Success!</h1><p>You can close this tab.</p>")
			codeChan <- code
		})

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Println("Opening browser for auth:", authURL)
	exec.Command("xdg-open", authURL).Start()

	var authCode string
	select {
	case authCode = <-codeChan:
	case err := <-errChan:
		return err
	}

	go server.Shutdown(context.Background())

	tok, err := config.Exchange(ctx, authCode)
	if err != nil {
		return err
	}

	// Save token to system keyring for future silent auth
	if err := m.saveTokenToKeyring(tok); err != nil {
		fmt.Printf("Warning: Failed to save token to keyring: %v\n", err)
	}

	client := config.Client(ctx, tok)
	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return err
	}

	m.gmailSvc = srv
	return nil
}

// sendEmail composes and sends an email via the Gmail API.
// It accepts a Key ID, resolves the email from the keyring, and sends the message.
func (m *PGPManager) sendEmail(recipientKeyID, subject, body string, encrypt bool) error {
	if m.gmailSvc == nil {
		return fmt.Errorf("not authenticated with Gmail")
	}

	var recipientEmail string
	var foundKey *crypto.Key

	// Look up the key in the keyring using the provided ID
	// and extract the email address from the key's identity.
	for _, key := range m.keyring.GetKeys() {
		if key.GetHexKeyID() == recipientKeyID {
			foundKey = key
			if entity := key.GetEntity(); entity != nil {
				_, ident := entity.PrimaryIdentity(time.Now(), nil)
				if ident != nil && ident.UserId != nil {
					recipientEmail = ident.UserId.Email
				}
			}
			break
		}
	}

	if foundKey == nil {
		return fmt.Errorf("recipient key not found for ID: %s", recipientKeyID)
	}
	if recipientEmail == "" {
		return fmt.Errorf("recipient key has no valid identity/email")
	}

	finalBody := body

	// Perform encryption if requested
	if encrypt {
		encHandle, err := m.pgp.Encryption().Recipient(foundKey).New()
		if err != nil {
			return err
		}

		pgpMessage, err := encHandle.Encrypt([]byte(body))
		if err != nil {
			return err
		}

		finalBody, err = pgpMessage.Armor()
		if err != nil {
			return err
		}
	}

	// Construct raw email message (Simple MIME format)
	emailContent := fmt.Sprintf("To: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n%s", recipientEmail, subject, finalBody)
	msg := &gmail.Message{Raw: base64.URLEncoding.EncodeToString([]byte(emailContent))}

	_, err := m.gmailSvc.Users.Messages.Send("me", msg).Do()
	return err
}

func (m *PGPManager) getOAuthConfig() (*oauth2.Config, error) {
	_ = godotenv.Load()
	clientID := os.Getenv("GMAIL_CLIENT_ID")
	clientSecret := os.Getenv("GMAIL_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("missing credentials in .env")
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{gmail.GmailSendScope, gmail.GmailReadonlyScope},
		Endpoint:     google.Endpoint,
		RedirectURL:  "http://localhost:8080",
	}, nil
}

// Helper: Save Token to System Keyring
func (m *PGPManager) saveTokenToKeyring(token *oauth2.Token) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return keyring.Set(keyringService, keyringUser, string(data))
}

// Helper: Load Token from System Keyring
func (m *PGPManager) tokenFromKeyring() (*oauth2.Token, error) {
	dataStr, err := keyring.Get(keyringService, keyringUser)
	if err != nil {
		return nil, err
	}
	
	tok := &oauth2.Token{}
	err = json.Unmarshal([]byte(dataStr), tok)
	return tok, err
}

// fetchInbox placeholder
func (m *PGPManager) fetchInbox() ([]*gmail.Message, error) {
	return nil, nil
}

// fetchMessageBody placeholder
func (m *PGPManager) fetchMessageBody(msgID string) (string, error) {
	return "", nil
}
