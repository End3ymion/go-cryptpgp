package app

import (
	"fmt"
	"time"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

// ---------------------------------------------------------
// TAB 1: KEY GENERATION
// ---------------------------------------------------------

// createKeyGenTab builds the UI for generating new PGP key pairs.
func (m *PGPManager) createKeyGenTab() {
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 10)
	box.SetMarginStart(20); box.SetMarginEnd(20); box.SetMarginTop(20); box.SetMarginBottom(20)

	label, _ := gtk.LabelNew("Generate New PGP Key Pair")
	label.SetMarkup("<b>Generate New PGP Key Pair</b>")
	box.PackStart(label, false, false, 0)

	nameEntry := m.createLabeledEntry(box, "Name:")
	emailEntry := m.createLabeledEntry(box, "Email:")
	
	passCheck, _ := gtk.CheckButtonNewWithLabel("Protect with Passphrase")
	passCheck.SetActive(true)
	box.PackStart(passCheck, false, false, 5)

	passEntry := m.createLabeledEntry(box, "Passphrase:")
	passEntry.SetVisibility(false)

	passCheck.Connect("toggled", func() {
		isActive := passCheck.GetActive()
		passEntry.SetSensitive(isActive)
		if !isActive { passEntry.SetText("") }
	})

	algoBox, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 5)
	algoLabel, _ := gtk.LabelNew("Algorithm:")
	algoCombo, _ := gtk.ComboBoxTextNew()
	
	// Populate algorithm choices matching constants in crypto.go
	algoCombo.AppendText("RSA 3072 bits (Standard)") // 0
	algoCombo.AppendText("RSA 4096 bits (High)")     // 1
	algoCombo.AppendText("Curve25519 (Modern)")      // 2
	algoCombo.AppendText("Curve448 (High Security)") // 3
	algoCombo.SetActive(2) // Default to Curve25519
	
	algoBox.PackStart(algoLabel, false, false, 0)
	algoBox.PackStart(algoCombo, true, true, 0)
	box.PackStart(algoBox, false, false, 0)

	validBox, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 5)
	validLabel, _ := gtk.LabelNew("Validity:")
	validCombo, _ := gtk.ComboBoxTextNew()
	validCombo.AppendText("No Expiration")
	validCombo.AppendText("1 Year")
	validCombo.AppendText("2 Years")
	validCombo.AppendText("Expired (Test: Yesterday)") // Testing option
	validCombo.SetActive(0)
	validBox.PackStart(validLabel, false, false, 0)
	validBox.PackStart(validCombo, true, true, 0)
	box.PackStart(validBox, false, false, 0)

	genBtn, _ := gtk.ButtonNewWithLabel("Generate Key Pair")
	statusLabel, _ := gtk.LabelNew("")

	genBtn.Connect("clicked", func() {
		name, _ := nameEntry.GetText()
		email, _ := emailEntry.GetText()
		pass, _ := passEntry.GetText()
		if passCheck.GetActive() && pass == "" {
			statusLabel.SetText("Error: Passphrase required")
			return
		}
		if name == "" || email == "" {
			statusLabel.SetText("Error: Name and Email required")
			return
		}

		algoIndex := algoCombo.GetActive()

		lifetime := 0
		switch validCombo.GetActive() {
		case 1: lifetime = 31536000
		case 2: lifetime = 31536000 * 2
		case 3: lifetime = -1 // Flag to trigger expired key logic
		}

		statusLabel.SetText("Generating...")
		genBtn.SetSensitive(false)

		go func() {
			err := m.generateKey(name, email, pass, algoIndex, lifetime)
			glib.IdleAdd(func() bool {
				genBtn.SetSensitive(true)
				if err != nil {
					statusLabel.SetText("Error: " + err.Error())
				} else {
					statusLabel.SetText("Success!")
					nameEntry.SetText(""); emailEntry.SetText(""); passEntry.SetText("")
					m.loadKeyring()
				}
				return false
			})
		}()
	})

	box.PackStart(genBtn, false, false, 10)
	box.PackStart(statusLabel, false, false, 0)
	
	lbl, _ := gtk.LabelNew("Key Gen")
	m.notebook.AppendPage(box, lbl)
}

// ---------------------------------------------------------
// TAB 2: KEY LIST
// ---------------------------------------------------------

// createKeyListTab builds the UI for displaying and managing the keyring.
func (m *PGPManager) createKeyListTab() {
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 10)
	box.SetMarginStart(20); box.SetMarginEnd(20); box.SetMarginTop(20); box.SetMarginBottom(20)

	label, _ := gtk.LabelNew("Key Management")
	label.SetMarkup("<b>Keyring Contents</b>")
	label.SetHAlign(gtk.ALIGN_START) 
	box.PackStart(label, false, false, 0)

	scrolled, _ := gtk.ScrolledWindowNew(nil, nil)
	scrolled.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	m.keyList, _ = gtk.ListBoxNew()
	m.keyList.SetSelectionMode(gtk.SELECTION_SINGLE)
	scrolled.Add(m.keyList)
	box.PackStart(scrolled, true, true, 10)

	actionFrame, _ := gtk.FrameNew("Actions")
	actionBox, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 10)
	actionBox.SetMarginStart(10); actionBox.SetMarginEnd(10); actionBox.SetMarginTop(10); actionBox.SetMarginBottom(10)
	actionFrame.Add(actionBox)

	exportPubBtn, _ := gtk.ButtonNewWithLabel("Export Public")
	exportPrivBtn, _ := gtk.ButtonNewWithLabel("Export Private")
	deleteBtn, _ := gtk.ButtonNewWithLabel("Delete")
	importBtn, _ := gtk.ButtonNewWithLabel("Import")

	getSelectedKeyID := func() string {
		row := m.keyList.GetSelectedRow()
		if row == nil { return "" }
		id, _ := row.GetName()
		return id
	}

	exportPubBtn.Connect("clicked", func() {
		id := getSelectedKeyID()
		if id == "" { return }
		dialog, _ := gtk.FileChooserNativeDialogNew("Export Public", m.window, gtk.FILE_CHOOSER_ACTION_SAVE, "Export", "Cancel")
		dialog.SetCurrentName(id + "_public.asc")
		if dialog.Run() == int(gtk.RESPONSE_ACCEPT) {
			m.exportKey(id, false, dialog.GetFilename(), "")
		}
		dialog.Destroy()
	})

	exportPrivBtn.Connect("clicked", func() {
		id := getSelectedKeyID()
		if id == "" { return }

		isPrivate, isLocked, err := m.GetKeyStatus(id)
		if err != nil {
			dlg := gtk.MessageDialogNew(m.window, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, "Error reading key: %v", err)
			dlg.Run(); dlg.Destroy()
			return
		}

		if !isPrivate {
			dlg := gtk.MessageDialogNew(m.window, 0, gtk.MESSAGE_WARNING, gtk.BUTTONS_OK, "Cannot Export: This is a Public Key only.")
			dlg.Run(); dlg.Destroy()
			return
		}

		passphrase := ""
		
		if isLocked {
			// Prompt for passphrase if key is locked
			pwdDialog, err := gtk.DialogNewWithButtons("Unlock Key", m.window, gtk.DIALOG_MODAL,
				[]interface{}{"Cancel", gtk.RESPONSE_CANCEL, "Unlock", gtk.RESPONSE_ACCEPT})
			
			if err != nil {
				return
			}
			
			contentArea, _ := pwdDialog.GetContentArea()
			contentArea.SetSpacing(10)
			
			lbl, _ := gtk.LabelNew("Enter passphrase to authorize export:")
			pwdEntry, _ := gtk.EntryNew()
			pwdEntry.SetVisibility(false)
			
			pwdEntry.Connect("activate", func() {
				pwdDialog.Response(gtk.RESPONSE_ACCEPT)
			})
			
			contentArea.Add(lbl)
			contentArea.Add(pwdEntry)
			
			pwdDialog.SetDefaultResponse(gtk.RESPONSE_ACCEPT)
			contentArea.ShowAll()
			pwdEntry.GrabFocus() 

			resp := pwdDialog.Run()
			passphrase, _ = pwdEntry.GetText()
			pwdDialog.Destroy()

			if resp != gtk.RESPONSE_ACCEPT {
				return
			}
		}

		dialog, _ := gtk.FileChooserNativeDialogNew("Export Private", m.window, gtk.FILE_CHOOSER_ACTION_SAVE, "Export", "Cancel")
		dialog.SetCurrentName(id + "_private.asc")
		
		if dialog.Run() == int(gtk.RESPONSE_ACCEPT) {
			err := m.exportKey(id, true, dialog.GetFilename(), passphrase)
			if err != nil {
				errMsg := gtk.MessageDialogNew(m.window, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, "Export Failed: %v", err)
				errMsg.Run(); errMsg.Destroy()
			}
		}
		dialog.Destroy()
	})

	deleteBtn.Connect("clicked", func() {
		id := getSelectedKeyID()
		if id == "" { return }
		dialog := gtk.MessageDialogNew(m.window, 0, gtk.MESSAGE_QUESTION, gtk.BUTTONS_YES_NO, "Delete %s?", id)
		if dialog.Run() == gtk.RESPONSE_YES { m.deleteKey(id) }
		dialog.Destroy()
	})

	importBtn.Connect("clicked", func() {
		dialog, _ := gtk.FileChooserNativeDialogNew("Select Key", m.window, gtk.FILE_CHOOSER_ACTION_OPEN, "Open", "Cancel")
		if dialog.Run() == int(gtk.RESPONSE_ACCEPT) { m.importKey(dialog.GetFilename()) }
		dialog.Destroy()
	})

	actionBox.PackStart(exportPubBtn, false, false, 0)
	actionBox.PackStart(exportPrivBtn, false, false, 0)
	actionBox.PackStart(deleteBtn, false, false, 0)
	actionBox.PackEnd(importBtn, false, false, 0)

	box.PackStart(actionFrame, false, false, 0)
	m.refreshKeyList()
	
	lbl, _ := gtk.LabelNew("Key List")
	m.notebook.AppendPage(box, lbl)
}

// refreshKeyList rebuilds the key list view, calculating expiry dates and
// highlighting expired keys.
func (m *PGPManager) refreshKeyList() {
	glib.IdleAdd(func() bool {
		if m.keyList == nil { return false }
		children := m.keyList.GetChildren()
		children.Foreach(func(item interface{}) { m.keyList.Remove(item.(gtk.IWidget)) })

		if m.keyring == nil { return false }
		
		for _, key := range m.keyring.GetKeys() {
			name := "Unknown"
			email := "Unknown"
			dateInfo := "Created: Unknown -> Expires: Never"
			
			if entity := key.GetEntity(); entity != nil {
				// Attempt to get identity info using current time
				sig, ident := entity.PrimaryIdentity(time.Now(), nil)
				
				// Fallback: If identity lookup fails (e.g., key expired), use creation time
				if sig == nil {
					sig, ident = entity.PrimaryIdentity(entity.PrimaryKey.CreationTime, nil)
				}
				
				if ident != nil {
					if ident.UserId != nil {
						name = ident.UserId.Name
						email = ident.UserId.Email
					}
				}
				
				// Calculate and format dates
				creation := entity.PrimaryKey.CreationTime
				createdStr := creation.Format("2006-01-02")
				expiresStr := "Never"

				if sig != nil && sig.KeyLifetimeSecs != nil {
					life := *sig.KeyLifetimeSecs
					if life != 0 {
						exp := creation.Add(time.Duration(life) * time.Second)
						expiresStr = exp.Format("2006-01-02")
					}
				}
				
				dateInfo = fmt.Sprintf("Created: %s -> Expires: %s", createdStr, expiresStr)
			}
			
			keyID := key.GetHexKeyID()
			
			// Highlight expired keys in red
			isExpired := key.IsExpired(time.Now().Unix())
			color := "black"
			status := "Valid"
			if isExpired {
				color = "red"
				status = "[EXPIRED]"
			}

			row, _ := gtk.ListBoxRowNew()
			row.SetName(keyID)

			hbox, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 2)
			hbox.SetMarginStart(10); hbox.SetMarginTop(5); hbox.SetMarginBottom(5)
			
			displayText := fmt.Sprintf(
				"<span color='%s'><b>%s</b> <small>&lt;%s&gt;</small>\n"+
				"<small>ID: %s  |  %s  |  %s</small></span>",
				color, name, email, keyID, dateInfo, status,
			)
			
			lbl, _ := gtk.LabelNew(displayText)
			lbl.SetUseMarkup(true)
			lbl.SetXAlign(0)

			hbox.PackStart(lbl, false, false, 0)
			row.Add(hbox)
			m.keyList.Add(row)
		}
		m.keyList.ShowAll()
		return false
	})
}

// ---------------------------------------------------------
// TAB 3: ENCRYPTION
// ---------------------------------------------------------

// createEncryptTab builds the UI for file encryption.
func (m *PGPManager) createEncryptTab() {
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 10)
	box.SetMarginStart(20); box.SetMarginEnd(20); box.SetMarginTop(20); box.SetMarginBottom(20)
	
	label, _ := gtk.LabelNew("Encrypt File")
	label.SetMarkup("<b>Encrypt File</b>")
	box.PackStart(label, false, false, 0)

	fileEntry := m.createLabeledEntry(box, "Input File:")
	
	symCheck, _ := gtk.CheckButtonNewWithLabel("Password Only (Symmetric)")
	box.PackStart(symCheck, false, false, 5)

	recipientCombo := m.createLabeledCombo(box, "Recipient:")
	passwordEntry := m.createLabeledEntry(box, "Password:")
	
	pWidget, _ := passwordEntry.GetParent(); pParent, _ := pWidget.(*gtk.Box); pParent.SetVisible(false)

	symCheck.Connect("toggled", func() {
		isSymmetric := symCheck.GetActive()
		rWidget, _ := recipientCombo.GetParent(); rParent, _ := rWidget.(*gtk.Box); rParent.SetVisible(!isSymmetric)
		pParent.SetVisible(isSymmetric)
	})

	browseBtn, _ := gtk.ButtonNewWithLabel("Browse...")
	browseBtn.Connect("clicked", func() {
		dialog, _ := gtk.FileChooserNativeDialogNew("Select File", m.window, gtk.FILE_CHOOSER_ACTION_OPEN, "Open", "Cancel")
		if dialog.Run() == int(gtk.RESPONSE_ACCEPT) { fileEntry.SetText(dialog.GetFilename()) }
		dialog.Destroy()
	})
	box.PackStart(browseBtn, false, false, 0)

	encryptBtn, _ := gtk.ButtonNewWithLabel("Encrypt")
	statusLabel, _ := gtk.LabelNew("")
	encryptBtn.Connect("clicked", func() {
		file, _ := fileEntry.GetText()
		if symCheck.GetActive() {
			pass, _ := passwordEntry.GetText()
			if err := m.EncryptFileSymmetric(file, pass); err != nil { statusLabel.SetText("Error: "+err.Error()) } else { statusLabel.SetText("Success!") }
		} else {
			rcpt := recipientCombo.GetActiveText()
			if err := m.encryptFile(file, rcpt); err != nil { statusLabel.SetText("Error: "+err.Error()) } else { statusLabel.SetText("Success!") }
		}
	})
	box.PackStart(encryptBtn, false, false, 0)
	box.PackStart(statusLabel, false, false, 0)
	
	lbl, _ := gtk.LabelNew("Encrypt")
	m.notebook.AppendPage(box, lbl)
}

// ---------------------------------------------------------
// TAB 4: DECRYPTION
// ---------------------------------------------------------

// createDecryptTab builds the UI for file decryption.
func (m *PGPManager) createDecryptTab() {
	box, _ := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 10)
	box.SetMarginStart(20); box.SetMarginEnd(20); box.SetMarginTop(20); box.SetMarginBottom(20)
	
	label, _ := gtk.LabelNew("Decrypt File")
	label.SetMarkup("<b>Decrypt File</b>")
	box.PackStart(label, false, false, 0)

	fileEntry := m.createLabeledEntry(box, "Encrypted File:")
	symCheck, _ := gtk.CheckButtonNewWithLabel("Symmetric (Password Only)")
	box.PackStart(symCheck, false, false, 5)

	keyCombo := m.createLabeledCombo(box, "My Key:")
	passCheck, _ := gtk.CheckButtonNewWithLabel("Key requires Passphrase")
	passCheck.SetActive(true)
	box.PackStart(passCheck, false, false, 0)
	
	passEntry := m.createLabeledEntry(box, "Passphrase / Password:")
	passEntry.SetVisibility(false)

	symCheck.Connect("toggled", func() {
		isSym := symCheck.GetActive()
		kWidget, _ := keyCombo.GetParent(); kParent, _ := kWidget.(*gtk.Box); kParent.SetVisible(!isSym)
		passCheck.SetVisible(!isSym)
	})
	
	passCheck.Connect("toggled", func() {
		if !symCheck.GetActive() {
			passEntry.SetSensitive(passCheck.GetActive())
		}
	})

	browseBtn, _ := gtk.ButtonNewWithLabel("Browse...")
	browseBtn.Connect("clicked", func() {
		dialog, _ := gtk.FileChooserNativeDialogNew("Select Encrypted", m.window, gtk.FILE_CHOOSER_ACTION_OPEN, "Open", "Cancel")
		if dialog.Run() == int(gtk.RESPONSE_ACCEPT) { fileEntry.SetText(dialog.GetFilename()) }
		dialog.Destroy()
	})
	box.PackStart(browseBtn, false, false, 0)

	decryptBtn, _ := gtk.ButtonNewWithLabel("Decrypt")
	statusLabel, _ := gtk.LabelNew("")
	decryptBtn.Connect("clicked", func() {
		file, _ := fileEntry.GetText()
		pass, _ := passEntry.GetText()
		selector := ""
		if !symCheck.GetActive() { selector = keyCombo.GetActiveText() }
		if err := m.decryptFile(file, pass, selector); err != nil { statusLabel.SetText("Error: "+err.Error()) } else { statusLabel.SetText("Success!") }
	})
	box.PackStart(decryptBtn, false, false, 0)
	box.PackStart(statusLabel, false, false, 0)
	
	lbl, _ := gtk.LabelNew("Decrypt")
	m.notebook.AppendPage(box, lbl)
}

// createEmailTab: Placeholder
func (m *PGPManager) createEmailTab() {}
// createInboxTab: Placeholder
func (m *PGPManager) createInboxTab() {}

// Helpers
func (m *PGPManager) createLabeledEntry(box *gtk.Box, labelText string) *gtk.Entry {
	hbox, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 5)
	label, _ := gtk.LabelNew(labelText)
	label.SetWidthChars(15); label.SetXAlign(0)
	entry, _ := gtk.EntryNew()
	hbox.PackStart(label, false, false, 0); hbox.PackStart(entry, true, true, 0)
	box.PackStart(hbox, false, false, 0)
	return entry
}

func (m *PGPManager) createLabeledCombo(box *gtk.Box, labelText string) *gtk.ComboBoxText {
	hbox, _ := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 5)
	label, _ := gtk.LabelNew(labelText)
	label.SetWidthChars(15); label.SetXAlign(0)
	combo, _ := gtk.ComboBoxTextNew()
	hbox.PackStart(label, false, false, 0); hbox.PackStart(combo, true, true, 0)
	box.PackStart(hbox, false, false, 0)
	m.keyCombos = append(m.keyCombos, combo)
	m.refreshCombo(combo)
	return combo
}

func (m *PGPManager) refreshCombo(c *gtk.ComboBoxText) {
	c.RemoveAll()
	if m.keyring == nil { return }
	for _, key := range m.keyring.GetKeys() {
		email := "unknown"
		if key.GetEntity() != nil {
			// FIXED: Capture 2 values
			_, ident := key.GetEntity().PrimaryIdentity(time.Now(), nil)
			if ident != nil && ident.UserId != nil {
				email = ident.UserId.Email
			}
		}
		c.AppendText(fmt.Sprintf("%s [%s]", email, key.GetHexKeyID()))
	}
	if m.keyring.CountEntities() > 0 { c.SetActive(0) }
}

func (m *PGPManager) refreshCombos() {
	glib.IdleAdd(func() bool {
		for _, c := range m.keyCombos { m.refreshCombo(c) }
		return false
	})
}
