package app

import (
	"log"
	"os"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/gotk3/gotk3/gtk"
	"google.golang.org/api/gmail/v1"
)

const (
	keyringPath = "pgp_keyring"
)

// PGPManager serves as the central state container for the application.
// It holds references to UI components, the PGP engine, the keyring, and external services.
type PGPManager struct {
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
	// Force Wayland backend for compatibility on modern Linux desktops
	os.Setenv("GDK_BACKEND", "wayland")

	gtk.Init(nil)

	// Initialize the GopenPGP v3 engine
	pgpHandle := crypto.PGP()

	mgr := &PGPManager{
		pgp: pgpHandle,
	}
	
	// Create main window
	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		log.Fatal(err)
	}
	mgr.window = win

	win.SetTitle("PGP Key & File Manager (v3)")
	win.SetDefaultSize(950, 700)
	win.Connect("destroy", gtk.MainQuit)

	// Create notebook (tabbed interface)
	notebook, err := gtk.NotebookNew()
	if err != nil {
		log.Fatal(err)
	}
	mgr.notebook = notebook

	// Initialize UI tabs
	mgr.createKeyGenTab()
	mgr.createKeyListTab() 
	mgr.createEncryptTab()
	mgr.createDecryptTab()
	// mgr.createEmailTab() // Placeholder
	// mgr.createInboxTab() // Placeholder

	// Load initial state
	mgr.loadKeyring()

	// Show window and start loop
	win.Add(notebook)
	win.ShowAll()

	gtk.Main()
}
