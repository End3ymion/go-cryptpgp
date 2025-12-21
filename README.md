# go-cryptpgp

A user-friendly desktop application that makes PGP encryption accessible through an intuitive interface. Built with Go, it simplifies key management, file encryption/decryption, and encrypted Gmail integration—bringing strong OpenPGP cryptography to non-technical users without sacrificing security.

## Features

- 🔐 **Key Management**: Generate, import, export, and delete PGP keys
- 📁 **File Encryption**: Encrypt and decrypt files with public key cryptography
- ✍️ **Digital Signatures**: Sign files to prove authenticity
- 📧 **Gmail Integration**: Send encrypted emails directly through Gmail
- 🔄 **Batch Processing**: Encrypt or decrypt multiple files at once
- 🔑 **Multiple Algorithms**: Support for RSA and modern elliptic curves (Curve25519, Curve448)
- 🎨 **User-Friendly Interface**: GTK4-based graphical interface

## Prerequisites

### System Requirements
- **Go** 1.19 or higher
- **GTK4** development libraries
- **Git** for cloning the repository

### Installing GTK4

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libgtk-4-dev
```

**Fedora:**
```bash
sudo dnf install gtk4-devel
```

**Arch Linux:**
```bash
sudo pacman -S gtk4
```

**macOS (Homebrew):**
```bash
brew install gtk4
```

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/End3ymion/go-cryptpgp.git
   cd go-cryptpgp
   ```

2. **Install Go dependencies:**
   ```bash
   go mod tidy
   ```

3. **Run the application:**
   ```bash
   go run main.go
   ```

   Or build and run:
   ```bash
   go build -o go-cryptpgp main.go
   ./go-cryptpgp
   ```

## Gmail Integration Setup (Optional)

To use the encrypted email feature:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the Gmail API
4. Create OAuth2 credentials (Desktop app type)
5. Create a `.env` file in the project root:
   ```env
   GMAIL_CLIENT_ID=your_client_id.apps.googleusercontent.com
   GMAIL_CLIENT_SECRET=your_client_secret
   ```

## Usage

### Generate a Key Pair
1. Go to the "Key Gen" tab
2. Enter your name and email
3. Choose an algorithm and expiration
4. Optionally set a passphrase
5. Click "Generate Key Pair"

### Encrypt a File
1. Go to "Encrypt/Sign" tab
2. Click "Add Files..." to select files
3. Choose a recipient's public key
4. Optionally sign with your key
5. Click "Execute Batch"

### Decrypt a File
1. Go to "Decrypt/Verify" tab
2. Click "Add Encrypted..." to select files
3. Select your private key
4. Enter passphrase if required
5. Click "Decrypt & Verify All"

### Send Encrypted Email
1. Go to "Send Email" tab
2. Click "Login to Gmail" (first time only)
3. Select recipient's key
4. Write your message
5. Click "Encrypt & Send"

## Project Structure

```
go-cryptpgp/
├── main.go              # Application entry point
├── app/
│   ├── manager.go       # Core application manager
│   ├── ui.go            # GTK4 user interface
│   ├── crypto.go        # Encryption/decryption logic
│   └── email.go         # Gmail API integration
├── pgp_keyring/         # Key storage directory
├── go.mod               # Go module dependencies
└── README.md            # This file
```

## Dependencies

- **[gopenpgp/v3](https://github.com/ProtonMail/gopenpgp)** - OpenPGP encryption library
- **[gotk4](https://github.com/diamondburned/gotk4)** - GTK4 bindings for Go
- **[Gmail API](https://developers.google.com/gmail/api)** - Google Gmail integration
- **[OAuth2](https://golang.org/x/oauth2)** - Authentication framework
- **[godotenv](https://github.com/joho/godotenv)** - Environment variable management
- **[go-keyring](https://github.com/zalando/go-keyring)** - System keyring access

## Security Notes

- Private keys are stored encrypted with passphrases
- Keys are saved in the `pgp_keyring` directory with restricted permissions
- OAuth tokens are stored securely in the system keyring
- Never share your `.env` file or private keys

## Supported Algorithms

- **RSA 3072** - Standard security
- **RSA 4096** - High security
- **Curve25519** - Modern, fast elliptic curve
- **Curve448** - High security elliptic curve

## Troubleshooting

### GTK4 not found
Make sure GTK4 development libraries are installed for your system.

### OAuth2 redirect URI mismatch
Ensure you created a "Desktop app" type credential, not "Web application".

### Key unlock fails
Verify you're entering the correct passphrase used when creating the key.

### Gmail authentication issues
Add yourself as a test user in the OAuth consent screen if the app is in testing mode.

