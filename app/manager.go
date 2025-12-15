package app

import (
	"os"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/diamondburned/gotk4/pkg/gtk/v4"
	"google.golang.org/api/gmail/v1"
)

const (
	keyringPath = "pgp_keyring"
)

// PGPManager serves as the central state container for the application.
// It holds references to UI components, the PGP engine, the keyring, and external services.
type PGPManager struct {
	app       *gtk.Application
	window    *gtk.Window
	notebook  *gtk.Notebook
	keyring   *crypto.KeyRing
	keyCombos []*gtk.ComboBoxText
	keyList   *gtk.ListBox
	gmailSvc  *gmail.Service
	pgp       *crypto.PGPHandle
}

// Run initializes the GTK environment, sets up the main application window,
// constructs the UI tabs, and starts the GTK main event loop.
func Run() {
	// Initialize the GopenPGP v3 engine
	pgpHandle := crypto.PGP()

	// Create a new GTK4 application
	app := gtk.NewApplication("com.example.pgpmanager", 0)

	mgr := &PGPManager{
		pgp: pgpHandle,
		app: app,
	}

	// Connect the "activate" signal to build the UI
	app.ConnectActivate(func() {
		mgr.activate()
	})

	// Run the application
	if code := app.Run(os.Args); code > 0 {
		os.Exit(code)
	}
}

func (m *PGPManager) activate() {
	// Create main window
	m.window = gtk.NewWindow()
	m.window.SetApplication(m.app)
	m.window.SetTitle("PGP Key & File Manager (v3)")
	m.window.SetDefaultSize(950, 700)

	// Create notebook (tabbed interface)
	m.notebook = gtk.NewNotebook()

	// Initialize UI tabs
	m.createKeyGenTab()
	m.createKeyListTab()
	m.createEncryptTab()
	m.createDecryptTab()
	m.createSendTab()

	// Load initial state
	m.loadKeyring()

	// Set the notebook as the child of the window
	m.window.SetChild(m.notebook)
	m.window.Present()
}
