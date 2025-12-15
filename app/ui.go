package app

import (
	"fmt"
	"time"

	"github.com/diamondburned/gotk4/pkg/glib/v2"
	"github.com/diamondburned/gotk4/pkg/gtk/v4"
)

// Helper to show a popup dialog
func (m *PGPManager) showDialog(msgType gtk.MessageType, message string) {
	dialog := gtk.NewMessageDialog(
		m.window,
		gtk.DialogModal,
		msgType,
		gtk.ButtonsOK,
	)
	dialog.SetMarkup(message)
	dialog.ConnectResponse(func(responseId int) {
		dialog.Destroy()
	})
	dialog.Show()
}

// ---------------------------------------------------------
// TAB 1: KEY GENERATION
// ---------------------------------------------------------

func (m *PGPManager) createKeyGenTab() {
	box := gtk.NewBox(gtk.OrientationVertical, 10)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(20)
	box.SetMarginBottom(20)

	label := gtk.NewLabel("Generate New PGP Key Pair")
	label.SetMarkup("<b>Generate New PGP Key Pair</b>")
	box.Append(label)

	nameEntry := m.createLabeledEntry(box, "Name:")
	emailEntry := m.createLabeledEntry(box, "Email:")

	passCheck := gtk.NewCheckButtonWithLabel("Protect with Passphrase")
	passCheck.SetActive(true)
	box.Append(passCheck)

	passEntry := m.createLabeledEntry(box, "Passphrase:")
	passEntry.SetVisibility(false)

	passCheck.ConnectToggled(func() {
		isActive := passCheck.Active()
		passEntry.SetSensitive(isActive)
		if !isActive {
			passEntry.SetText("")
		}
	})

	algoBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	algoLabel := gtk.NewLabel("Algorithm:")
	algoCombo := gtk.NewComboBoxText()

	algoCombo.AppendText("RSA 3072 bits (Standard)")
	algoCombo.AppendText("RSA 4096 bits (High)")
	algoCombo.AppendText("Curve25519 (Modern)")
	algoCombo.AppendText("Curve448 (High Security)")
	algoCombo.SetActive(2)

	algoBox.Append(algoLabel)
	algoBox.Append(algoCombo)
	box.Append(algoBox)

	validBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	validLabel := gtk.NewLabel("Validity:")
	validCombo := gtk.NewComboBoxText()
	validCombo.AppendText("No Expiration")
	validCombo.AppendText("1 Year")
	validCombo.AppendText("2 Years")
	validCombo.AppendText("Expired (Test: Yesterday)")
	validCombo.SetActive(0)
	validBox.Append(validLabel)
	validBox.Append(validCombo)
	box.Append(validBox)

	genBtn := gtk.NewButtonWithLabel("Generate Key Pair")

	genBtn.ConnectClicked(func() {
		name := nameEntry.Text()
		email := emailEntry.Text()
		pass := passEntry.Text()
		if passCheck.Active() && pass == "" {
			m.showDialog(gtk.MessageError, "Error: Passphrase required")
			return
		}
		if name == "" || email == "" {
			m.showDialog(gtk.MessageError, "Error: Name and Email required")
			return
		}

		algoIndex := algoCombo.Active()

		lifetime := 0
		switch validCombo.Active() {
		case 1:
			lifetime = 31536000
		case 2:
			lifetime = 31536000 * 2
		case 3:
			lifetime = -1
		}

		genBtn.SetSensitive(false)

		go func() {
			err := m.generateKey(name, email, pass, algoIndex, lifetime)
			glib.IdleAdd(func() {
				genBtn.SetSensitive(true)
				if err != nil {
					m.showDialog(gtk.MessageError, "Error: "+err.Error())
				} else {
					m.showDialog(gtk.MessageInfo, "Key Pair Generated Successfully!")
					nameEntry.SetText("")
					emailEntry.SetText("")
					passEntry.SetText("")
					go m.loadKeyring()
				}
			})
		}()
	})

	box.Append(genBtn)

	lbl := gtk.NewLabel("Key Gen")
	m.notebook.AppendPage(box, lbl)
}

// ---------------------------------------------------------
// TAB 2: KEY LIST
// ---------------------------------------------------------

func (m *PGPManager) createKeyListTab() {
	box := gtk.NewBox(gtk.OrientationVertical, 10)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(20)
	box.SetMarginBottom(20)

	label := gtk.NewLabel("Key Management")
	label.SetMarkup("<b>Keyring Contents</b>")
	label.SetHAlign(gtk.AlignStart)
	box.Append(label)

	scrolled := gtk.NewScrolledWindow()
	scrolled.SetPolicy(gtk.PolicyAutomatic, gtk.PolicyAutomatic)
	scrolled.SetVExpand(true)

	m.keyList = gtk.NewListBox()
	m.keyList.SetSelectionMode(gtk.SelectionSingle)
	scrolled.SetChild(m.keyList)
	box.Append(scrolled)

	actionFrame := gtk.NewFrame("Actions")
	actionBox := gtk.NewBox(gtk.OrientationHorizontal, 10)
	actionBox.SetMarginStart(10)
	actionBox.SetMarginEnd(10)
	actionBox.SetMarginTop(10)
	actionBox.SetMarginBottom(10)
	actionFrame.SetChild(actionBox)

	exportPubBtn := gtk.NewButtonWithLabel("Export Public")
	exportPrivBtn := gtk.NewButtonWithLabel("Export Private")
	deleteBtn := gtk.NewButtonWithLabel("Delete")
	importBtn := gtk.NewButtonWithLabel("Import")

	getSelectedKeyID := func() string {
		row := m.keyList.SelectedRow()
		if row == nil {
			return ""
		}
		return row.Name()
	}

	exportPubBtn.ConnectClicked(func() {
		id := getSelectedKeyID()
		if id == "" {
			return
		}
		dialog := gtk.NewFileChooserNative("Export Public", m.window, gtk.FileChooserActionSave, "Export", "Cancel")
		dialog.SetCurrentName(id + "_public.asc")

		dialog.ConnectResponse(func(responseId int) {
			if responseId == int(gtk.ResponseAccept) {
				gfile := dialog.File()
				if err := m.exportKey(id, false, gfile.Path(), ""); err != nil {
					m.showDialog(gtk.MessageError, "Export Failed: "+err.Error())
				} else {
					m.showDialog(gtk.MessageInfo, "Public Key Exported Successfully!")
				}
			}
			dialog.Destroy()
		})
		dialog.Show()
	})

	exportPrivBtn.ConnectClicked(func() {
		id := getSelectedKeyID()
		if id == "" {
			return
		}

		isPrivate, isLocked, err := m.GetKeyStatus(id)
		if err != nil {
			m.showDialog(gtk.MessageError, "Error reading key: "+err.Error())
			return
		}

		if !isPrivate {
			m.showDialog(gtk.MessageWarning, "Cannot Export: This is a Public Key only.")
			return
		}

		if isLocked {
			m.showDialog(gtk.MessageWarning, "Exporting locked keys requires unlocked keyring (Not implemented in this port).")
			return
		}

		dialog := gtk.NewFileChooserNative("Export Private", m.window, gtk.FileChooserActionSave, "Export", "Cancel")
		dialog.SetCurrentName(id + "_private.asc")

		dialog.ConnectResponse(func(responseId int) {
			if responseId == int(gtk.ResponseAccept) {
				gfile := dialog.File()
				err := m.exportKey(id, true, gfile.Path(), "")
				if err != nil {
					m.showDialog(gtk.MessageError, "Export Failed: "+err.Error())
				} else {
					m.showDialog(gtk.MessageInfo, "Private Key Exported Successfully!")
				}
			}
			dialog.Destroy()
		})
		dialog.Show()
	})

	deleteBtn.ConnectClicked(func() {
		id := getSelectedKeyID()
		if id == "" {
			return
		}

		dialog := gtk.NewMessageDialog(m.window, gtk.DialogModal, gtk.MessageQuestion, gtk.ButtonsYesNo)
		dialog.SetMarkup(fmt.Sprintf("Delete %s?", id))
		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseYes) {
				m.deleteKey(id)
				m.showDialog(gtk.MessageInfo, "Key Deleted Successfully")
			}
			dialog.Destroy()
		})
		dialog.Show()
	})

	importBtn.ConnectClicked(func() {
		dialog := gtk.NewFileChooserNative("Select Key", m.window, gtk.FileChooserActionOpen, "Open", "Cancel")
		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseAccept) {
				gfile := dialog.File()
				if err := m.importKey(gfile.Path()); err != nil {
					m.showDialog(gtk.MessageError, "Import Failed: "+err.Error())
				} else {
					m.showDialog(gtk.MessageInfo, "Key Imported Successfully!")
				}
			}
			dialog.Destroy()
		})
		dialog.Show()
	})

	actionBox.Append(exportPubBtn)
	actionBox.Append(exportPrivBtn)
	actionBox.Append(deleteBtn)
	actionBox.Append(importBtn)

	box.Append(actionFrame)
	m.refreshKeyList()

	lbl := gtk.NewLabel("Key List")
	m.notebook.AppendPage(box, lbl)
}

func (m *PGPManager) refreshKeyList() {
	glib.IdleAdd(func() {
		if m.keyList == nil {
			return
		}

		// Remove all children safely
		for {
			child := m.keyList.FirstChild()
			if child == nil {
				break
			}
			m.keyList.Remove(child)
		}

		if m.keyring == nil {
			return
		}

		for _, key := range m.keyring.GetKeys() {
			name := "Unknown"
			email := "Unknown"
			dateInfo := "Created: Unknown -> Never"

			if entity := key.GetEntity(); entity != nil {
				_, ident := entity.PrimaryIdentity(time.Now(), nil)
				if ident != nil {
					if ident.UserId != nil {
						name = ident.UserId.Name
						email = ident.UserId.Email
					}
				}

				creation := entity.PrimaryKey.CreationTime
				createdStr := creation.Format("02 Jan 2006")
				dateInfo = fmt.Sprintf("Created: %s", createdStr)
			}

			keyID := key.GetHexKeyID()
			isExpired := key.IsExpired(time.Now().Unix())
			color := "black"
			status := "Valid"
			if isExpired {
				color = "red"
				status = "[EXPIRED]"
			}

			row := gtk.NewListBoxRow()
			row.SetName(keyID)

			hbox := gtk.NewBox(gtk.OrientationVertical, 2)
			hbox.SetMarginStart(10)
			hbox.SetMarginTop(5)
			hbox.SetMarginBottom(5)

			displayText := fmt.Sprintf(
				"<span color='%s'><b>%s</b> <small>&lt;%s&gt;</small>\n"+
					"<small>ID: %s  |  %s  |  %s</small></span>",
				color, name, email, keyID, dateInfo, status,
			)

			lbl := gtk.NewLabel(displayText)
			lbl.SetUseMarkup(true)
			lbl.SetHAlign(gtk.AlignStart)

			hbox.Append(lbl)
			row.SetChild(hbox)
			m.keyList.Append(row)
		}
	})
}

// ---------------------------------------------------------
// TAB 3: ENCRYPTION
// ---------------------------------------------------------

func (m *PGPManager) createEncryptTab() {
	box := gtk.NewBox(gtk.OrientationVertical, 10)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(20)
	box.SetMarginBottom(20)

	label := gtk.NewLabel("Encrypt File")
	label.SetMarkup("<b>Encrypt File</b>")
	box.Append(label)

	fileEntry := m.createLabeledEntry(box, "Input File:")

	symCheck := gtk.NewCheckButtonWithLabel("Password Only (Symmetric)")
	box.Append(symCheck)

	recipientCombo := m.createLabeledCombo(box, "Recipient:")
	passwordEntry := m.createLabeledEntry(box, "Password:")

	// Store parent boxes for visibility toggling
	var pParentBox *gtk.Box
	var rParentBox *gtk.Box
	
	if w := passwordEntry.Parent(); w != nil {
		if box, ok := w.(*gtk.Box); ok {
			pParentBox = box
			pParentBox.SetVisible(false)
		}
	}
	
	if w := recipientCombo.Parent(); w != nil {
		if box, ok := w.(*gtk.Box); ok {
			rParentBox = box
		}
	}

	symCheck.ConnectToggled(func() {
		isSymmetric := symCheck.Active()
		if rParentBox != nil {
			rParentBox.SetVisible(!isSymmetric)
		}
		if pParentBox != nil {
			pParentBox.SetVisible(isSymmetric)
		}
	})

	browseBtn := gtk.NewButtonWithLabel("Browse...")
	browseBtn.ConnectClicked(func() {
		dialog := gtk.NewFileChooserNative("Select File", m.window, gtk.FileChooserActionOpen, "Open", "Cancel")
		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseAccept) {
				fileEntry.SetText(dialog.File().Path())
			}
			dialog.Destroy()
		})
		dialog.Show()
	})
	box.Append(browseBtn)

	encryptBtn := gtk.NewButtonWithLabel("Encrypt")
	encryptBtn.ConnectClicked(func() {
		file := fileEntry.Text()
		var err error

		if symCheck.Active() {
			pass := passwordEntry.Text()
			err = m.EncryptFileSymmetric(file, pass)
		} else {
			rcpt := recipientCombo.ActiveText()
			err = m.encryptFile(file, rcpt)
		}

		if err != nil {
			m.showDialog(gtk.MessageError, "Error: "+err.Error())
		} else {
			m.showDialog(gtk.MessageInfo, "File Encrypted Successfully!")
		}
	})
	box.Append(encryptBtn)

	lbl := gtk.NewLabel("Encrypt")
	m.notebook.AppendPage(box, lbl)
}

// ---------------------------------------------------------
// TAB 4: DECRYPTION
// ---------------------------------------------------------

func (m *PGPManager) createDecryptTab() {
	box := gtk.NewBox(gtk.OrientationVertical, 10)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(20)
	box.SetMarginBottom(20)

	label := gtk.NewLabel("Decrypt File")
	label.SetMarkup("<b>Decrypt File</b>")
	box.Append(label)

	fileEntry := m.createLabeledEntry(box, "Encrypted File:")
	symCheck := gtk.NewCheckButtonWithLabel("Symmetric (Password Only)")
	box.Append(symCheck)

	keyCombo := m.createLabeledCombo(box, "My Key:")
	passCheck := gtk.NewCheckButtonWithLabel("Key requires Passphrase")
	passCheck.SetActive(true)
	box.Append(passCheck)

	passEntry := m.createLabeledEntry(box, "Passphrase / Password:")
	passEntry.SetVisibility(false)

	var kParentBox *gtk.Box
	if w := keyCombo.Parent(); w != nil {
		if box, ok := w.(*gtk.Box); ok {
			kParentBox = box
		}
	}

	symCheck.ConnectToggled(func() {
		isSym := symCheck.Active()
		if kParentBox != nil {
			kParentBox.SetVisible(!isSym)
		}
		passCheck.SetVisible(!isSym)
	})

	passCheck.ConnectToggled(func() {
		if !symCheck.Active() {
			passEntry.SetSensitive(passCheck.Active())
		}
	})

	browseBtn := gtk.NewButtonWithLabel("Browse...")
	browseBtn.ConnectClicked(func() {
		dialog := gtk.NewFileChooserNative("Select Encrypted", m.window, gtk.FileChooserActionOpen, "Open", "Cancel")
		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseAccept) {
				fileEntry.SetText(dialog.File().Path())
			}
			dialog.Destroy()
		})
		dialog.Show()
	})
	box.Append(browseBtn)

	decryptBtn := gtk.NewButtonWithLabel("Decrypt")
	decryptBtn.ConnectClicked(func() {
		file := fileEntry.Text()
		pass := passEntry.Text()
		selector := ""
		if !symCheck.Active() {
			selector = keyCombo.ActiveText()
		}

		err := m.decryptFile(file, pass, selector)
		if err != nil {
			m.showDialog(gtk.MessageError, "Error: "+err.Error())
		} else {
			m.showDialog(gtk.MessageInfo, "File Decrypted Successfully!")
		}
	})
	box.Append(decryptBtn)

	lbl := gtk.NewLabel("Decrypt")
	m.notebook.AppendPage(box, lbl)
}

// ---------------------------------------------------------
// TAB 5: SEND ENCRYPTED EMAIL
// ---------------------------------------------------------

func (m *PGPManager) createSendTab() {
	box := gtk.NewBox(gtk.OrientationVertical, 10)
	box.SetMarginStart(20)
	box.SetMarginEnd(20)
	box.SetMarginTop(20)
	box.SetMarginBottom(20)

	label := gtk.NewLabel("Send Encrypted Email")
	label.SetMarkup("<b>Send Encrypted Email</b>")
	box.Append(label)

	authBtn := gtk.NewButtonWithLabel("Login to Gmail")

	// Message Composition Form
	formBox := gtk.NewBox(gtk.OrientationVertical, 5)

	recipientCombo := m.createLabeledCombo(formBox, "To (Select Key):")
	subjectEntry := m.createLabeledEntry(formBox, "Subject:")

	// Body Text Area
	bodyLabel := gtk.NewLabel("Message Body:")
	bodyLabel.SetHAlign(gtk.AlignStart)
	formBox.Append(bodyLabel)

	scrolled := gtk.NewScrolledWindow()
	scrolled.SetPolicy(gtk.PolicyAutomatic, gtk.PolicyAutomatic)
	scrolled.SetMinContentHeight(200)
	scrolled.SetVExpand(true)

	bodyView := gtk.NewTextView()
	bodyView.SetWrapMode(gtk.WrapWord)
	scrolled.SetChild(bodyView)
	formBox.Append(scrolled)

	box.Append(formBox)

	sendBtn := gtk.NewButtonWithLabel("Encrypt & Send")
	sendBtn.SetSensitive(false)

	// Auth Logic (Silent + Manual)
	checkAuth := func() {
		if m.AttemptSilentAuth() {
			glib.IdleAdd(func() {
				authBtn.SetVisible(false)
				sendBtn.SetSensitive(true)
			})
		}
	}

	authBtn.ConnectClicked(func() {
		go func() {
			err := m.authenticateGmail()
			glib.IdleAdd(func() {
				if err != nil {
					m.showDialog(gtk.MessageError, "Auth Error: "+err.Error())
				} else {
					m.showDialog(gtk.MessageInfo, "Authentication Successful!")
					authBtn.SetVisible(false)
					sendBtn.SetSensitive(true)
				}
			})
		}()
	})
	box.Append(authBtn)

	sendBtn.ConnectClicked(func() {
		// Get Data
		rcptKey := recipientCombo.ActiveText()
		subject := subjectEntry.Text()

		buffer := bodyView.Buffer()
		start := buffer.StartIter()
		end := buffer.EndIter()
		body := buffer.Text(start, end, false)

		if rcptKey == "" {
			m.showDialog(gtk.MessageError, "Please select a recipient key.")
			return
		}

		sendBtn.SetSensitive(false)

		go func() {
			// Encrypt is ALWAYS true for this tab
			err := m.sendEmail(rcptKey, subject, body, true)
			glib.IdleAdd(func() {
				sendBtn.SetSensitive(true)
				if err != nil {
					m.showDialog(gtk.MessageError, "Send Failed: "+err.Error())
				} else {
					m.showDialog(gtk.MessageInfo, "Encrypted Email Sent Successfully!")
					// Clear body
					buffer.SetText("")
					subjectEntry.SetText("")
				}
			})
		}()
	})
	box.Append(sendBtn)

	lbl := gtk.NewLabel("Send Email")
	m.notebook.AppendPage(box, lbl)

	// Try auth on startup
	go checkAuth()
}

// Helpers
func (m *PGPManager) createLabeledEntry(box *gtk.Box, labelText string) *gtk.Entry {
	hbox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	label := gtk.NewLabel(labelText)
	label.SetSizeRequest(100, -1)
	label.SetHAlign(gtk.AlignStart)
	entry := gtk.NewEntry()
	entry.SetHExpand(true)

	hbox.Append(label)
	hbox.Append(entry)
	box.Append(hbox)
	return entry
}

func (m *PGPManager) createLabeledCombo(box *gtk.Box, labelText string) *gtk.ComboBoxText {
	hbox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	label := gtk.NewLabel(labelText)
	label.SetSizeRequest(100, -1)
	label.SetHAlign(gtk.AlignStart)
	combo := gtk.NewComboBoxText()
	combo.SetHExpand(true)

	hbox.Append(label)
	hbox.Append(combo)
	box.Append(hbox)

	m.keyCombos = append(m.keyCombos, combo)
	m.refreshCombo(combo)
	return combo
}

func (m *PGPManager) refreshCombo(c *gtk.ComboBoxText) {
	c.RemoveAll()
	if m.keyring == nil {
		return
	}
	for _, key := range m.keyring.GetKeys() {
		email := "unknown"
		if key.GetEntity() != nil {
			_, ident := key.GetEntity().PrimaryIdentity(time.Now(), nil)
			if ident != nil && ident.UserId != nil {
				email = ident.UserId.Email
			}
		}
		c.AppendText(fmt.Sprintf("%s [%s]", email, key.GetHexKeyID()))
	}
	if m.keyring.CountEntities() > 0 {
		c.SetActive(0)
	}
}

func (m *PGPManager) refreshCombos() {
	glib.IdleAdd(func() {
		for _, c := range m.keyCombos {
			m.refreshCombo(c)
		}
	})
}
