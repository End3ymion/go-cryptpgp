package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/diamondburned/gotk4/pkg/gio/v2"
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

// Helper to prompt for a password.
// This function must be called from a goroutine, NOT the main thread.
func (m *PGPManager) promptPassword(title string) (string, bool) {
	type result struct {
		pass string
		ok   bool
	}
	resChan := make(chan result)

	// Schedule UI operations on the main thread
	glib.IdleAdd(func() {
		dialog := gtk.NewDialog()
		dialog.SetTitle(title)
		dialog.SetTransientFor(m.window)
		dialog.SetModal(true)

		contentArea := dialog.ContentArea()
		contentArea.SetMarginStart(20)
		contentArea.SetMarginEnd(20)
		contentArea.SetMarginTop(20)
		contentArea.SetMarginBottom(20)

		label := gtk.NewLabel("Enter Passphrase:")
		entry := gtk.NewEntry()
		entry.SetVisibility(false)
		entry.SetActivatesDefault(true)

		contentArea.Append(label)
		contentArea.Append(entry)

		dialog.AddButton("Cancel", int(gtk.ResponseCancel))
		dialog.AddButton("OK", int(gtk.ResponseOK))
		dialog.SetDefaultResponse(int(gtk.ResponseOK))

		// Handle response
		dialog.ConnectResponse(func(responseId int) {
			pass := ""
			ok := false
			if responseId == int(gtk.ResponseOK) {
				pass = entry.Text()
				ok = true
			}
			dialog.Destroy()
			resChan <- result{pass, ok}
		})

		dialog.Show()
	})

	// Block here (in the worker goroutine) until the UI thread sends the result
	res := <-resChan
	return res.pass, res.ok
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
	validCombo.AppendText("3 Years")
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
			lifetime = 31536000 * 3
		case 4:
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
			// Locked keys require unlock which we can't easily do in this main thread callback without freezing
			// or re-architecting to spawn a goroutine for every button click. 
			// For simplicity in this demo, we warn.
			m.showDialog(gtk.MessageWarning, "Exporting locked private keys is not fully supported in this demo UI.")
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
				
				// Calculate Expiry
				expiryStr := "Never"
				sig, _ := entity.PrimarySelfSignature(time.Time{}, nil)
				if sig != nil && sig.KeyLifetimeSecs != nil {
					secs := *sig.KeyLifetimeSecs
					if secs != 0 {
						expiryTime := creation.Add(time.Duration(secs) * time.Second)
						expiryStr = expiryTime.Format("02 Jan 2006")
					}
				}
				
				dateInfo = fmt.Sprintf("Created: %s -> %s", createdStr, expiryStr)
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
	label.SetMarkup("<b>Encrypt / Sign File</b>")
	box.Append(label)

	// -- Multiple File Selection --
	fileList := gtk.NewListBox()
	fileList.SetSelectionMode(gtk.SelectionNone)
	fileList.SetSizeRequest(-1, 150)
	
	scrolled := gtk.NewScrolledWindow()
	scrolled.SetChild(fileList)
	scrolled.SetVExpand(true)
	
	// Frame for file list
	listFrame := gtk.NewFrame("Selected Files")
	listFrame.SetChild(scrolled)
	box.Append(listFrame)

	// File Buttons
	fileBtnBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	browseBtn := gtk.NewButtonWithLabel("Add Files...")
	clearBtn := gtk.NewButtonWithLabel("Clear List")
	fileBtnBox.Append(browseBtn)
	fileBtnBox.Append(clearBtn)
	box.Append(fileBtnBox)

	// Store selected paths
	var selectedFiles []string

	// Function to remove a specific file
	removeFile := func(targetPath string, row *gtk.ListBoxRow) {
		// Update selectedFiles slice
		for i, path := range selectedFiles {
			if path == targetPath {
				selectedFiles = append(selectedFiles[:i], selectedFiles[i+1:]...)
				break
			}
		}
		// Remove from UI
		fileList.Remove(row)
	}

	browseBtn.ConnectClicked(func() {
		dialog := gtk.NewFileChooserNative("Select Files", m.window, gtk.FileChooserActionOpen, "Add", "Cancel")
		dialog.SetSelectMultiple(true) // ENABLE MULTI-SELECTION

		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseAccept) {
				// Iterate over selected files from the list model
				filesList := dialog.Files()
				var i uint
				for i = 0; i < filesList.NItems(); i++ {
					obj := filesList.Item(i)
					if fileObj, ok := obj.Cast().(*gio.File); ok {
						path := fileObj.Path()
						// Avoid duplicates in the list
						alreadyExists := false
						for _, existing := range selectedFiles {
							if existing == path {
								alreadyExists = true
								break
							}
						}
						
						if !alreadyExists {
							selectedFiles = append(selectedFiles, path)
							
							// Create Row with Label and Remove Button
							row := gtk.NewListBoxRow()
							rowBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
							
							rowLabel := gtk.NewLabel(path)
							rowLabel.SetHAlign(gtk.AlignStart)
							rowLabel.SetHExpand(true)
							rowLabel.SetMarginStart(5)
							
							removeBtn := gtk.NewButtonWithLabel("✖") // Small remove button
							removeBtn.SetMarginEnd(5)
							// Capture path and row for removal closure
							p := path
							r := row
							removeBtn.ConnectClicked(func() {
								removeFile(p, r)
							})

							rowBox.Append(rowLabel)
							rowBox.Append(removeBtn)
							row.SetChild(rowBox)
							fileList.Append(row)
						}
					}
				}
			}
			dialog.Destroy()
		})
		dialog.Show()
	})

	clearBtn.ConnectClicked(func() {
		selectedFiles = []string{}
		for {
			child := fileList.FirstChild()
			if child == nil { break }
			fileList.Remove(child)
		}
	})

	// -- Output Directory Selection --
	outDirBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	outDirEntry := gtk.NewEntry()
	outDirEntry.SetPlaceholderText("Output Directory (Optional - Default: Input Dir)")
	outDirEntry.SetHExpand(true)
	
	outDirBtn := gtk.NewButtonWithLabel("Select Output Dir...")
	outDirBtn.ConnectClicked(func() {
		dialog := gtk.NewFileChooserNative("Select Output Directory", m.window, gtk.FileChooserActionSelectFolder, "Select", "Cancel")
		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseAccept) {
				outDirEntry.SetText(dialog.File().Path())
			}
			dialog.Destroy()
		})
		dialog.Show()
	})
	
	outDirBox.Append(gtk.NewLabel("Output:"))
	outDirBox.Append(outDirEntry)
	outDirBox.Append(outDirBtn)
	box.Append(outDirBox)

	// -- Options Group --
	optsFrame := gtk.NewFrame("Encryption Options")
	optsBox := gtk.NewBox(gtk.OrientationVertical, 5)
	optsBox.SetMarginStart(10); optsBox.SetMarginEnd(10)
	optsBox.SetMarginTop(5); optsBox.SetMarginBottom(5)
	optsFrame.SetChild(optsBox)
	box.Append(optsFrame)

	// Helper to create checkbox + widget row
	createOptionRow := func(label string, widget gtk.Widgetter) *gtk.CheckButton {
		row := gtk.NewBox(gtk.OrientationHorizontal, 10)
		check := gtk.NewCheckButtonWithLabel(label)
		
		row.Append(check)
		
		// If widget is provided, append it
		if widget != nil {
			// Cast to widget to append
			row.Append(widget)
		}
		
		optsBox.Append(row)
		return check
	}

	// 1. Encrypt for Others
	recipientCombo := m.createLabeledCombo(nil, "") 
	recipientCombo = gtk.NewComboBoxText()
	m.keyCombos = append(m.keyCombos, recipientCombo)
	m.refreshCombo(recipientCombo)
	encryptOthersCheck := createOptionRow("Encrypt for Others:", recipientCombo)

	// 2. Encrypt for Me
	myKeyCombo := gtk.NewComboBoxText()
	m.keyCombos = append(m.keyCombos, myKeyCombo)
	m.refreshCombo(myKeyCombo)
	encryptMeCheck := createOptionRow("Encrypt for Me:", myKeyCombo)

	// 3. Sign
	signKeyCombo := gtk.NewComboBoxText()
	m.keyCombos = append(m.keyCombos, signKeyCombo)
	m.refreshCombo(signKeyCombo)
	signCheck := createOptionRow("Sign with Key:", signKeyCombo)

	// 4. Symmetric
	symmetricCheck := createOptionRow("Symmetric Encryption (Password Prompt)", nil)

	// UI Update Logic
	updateUI := func() {
		// Encrypt Others
		isEncryptOthers := encryptOthersCheck.Active()
		recipientCombo.SetSensitive(isEncryptOthers)

		// Encrypt Me
		isEncryptMe := encryptMeCheck.Active()
		myKeyCombo.SetSensitive(isEncryptMe)

		// Sign
		isSign := signCheck.Active()
		signKeyCombo.SetSensitive(isSign)
	}

	// Connect Signals
	encryptOthersCheck.ConnectToggled(updateUI)
	encryptMeCheck.ConnectToggled(updateUI)
	signCheck.ConnectToggled(updateUI)
	symmetricCheck.ConnectToggled(updateUI)

	// Initial State
	encryptOthersCheck.SetActive(true)
	updateUI()

	actionBtn := gtk.NewButtonWithLabel("Execute Batch")
	actionBtn.ConnectClicked(func() {
		if len(selectedFiles) == 0 {
			m.showDialog(gtk.MessageError, "Please select at least one input file.")
			return
		}

		outputDir := outDirEntry.Text()
		isEncryptOthers := encryptOthersCheck.Active()
		isEncryptMe := encryptMeCheck.Active()
		isSign := signCheck.Active()
		isSymmetric := symmetricCheck.Active()

		if !isEncryptOthers && !isEncryptMe && !isSign && !isSymmetric {
			m.showDialog(gtk.MessageError, "Please select at least one operation.")
			return
		}

		if isEncryptOthers && recipientCombo.ActiveID() == "" {
			m.showDialog(gtk.MessageError, "Please select a recipient.")
			return
		}
		if isEncryptMe && myKeyCombo.ActiveID() == "" {
			m.showDialog(gtk.MessageError, "Please select your public key.")
			return
		}
		if isSign && signKeyCombo.ActiveID() == "" {
			m.showDialog(gtk.MessageError, "Please select a signing key.")
			return
		}

		// Capture needed data from UI before goroutine
		rcptID := ""
		if isEncryptOthers {
			rcptID = recipientCombo.ActiveID()
		} else if isEncryptMe {
			rcptID = myKeyCombo.ActiveID()
		}
		
		var signID string
		if isSign {
			signID = signKeyCombo.ActiveID()
		}

		actionBtn.SetSensitive(false)

		// Copy file list to avoid race conditions
		filesToProcess := make([]string, len(selectedFiles))
		copy(filesToProcess, selectedFiles)

		go func() {
			defer glib.IdleAdd(func() { actionBtn.SetSensitive(true) })

			var pass string
			var ok bool

			// Get password for Symmetric if needed
			if isSymmetric {
				pass, ok = m.promptPassword("Enter Symmetric Password")
				if !ok {
					return // User cancelled
				}
			}

			// Get password for Signing Key if needed
			var signPass string
			if isSign {
				isPrivate, isLocked, _ := m.GetKeyStatus(signID)
				if isPrivate && isLocked {
					signPass, ok = m.promptPassword("Enter Passphrase for Signing Key")
					if !ok {
						return // User cancelled
					}
				}
			}

			var errs []string
			successCount := 0

			for _, file := range filesToProcess {
				var err error
				if isSymmetric && !isEncryptOthers && !isEncryptMe && !isSign {
					err = m.EncryptFileSymmetric(file, pass, outputDir)
				} else {
					err = m.encryptFile(file, rcptID, signID, signPass, outputDir)
				}

				if err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", file, err))
				} else {
					successCount++
				}
			}
			
			glib.IdleAdd(func() {
				if len(errs) > 0 {
					msg := fmt.Sprintf("Processed %d/%d files.\n\nErrors:\n%s", 
						successCount, len(filesToProcess), strings.Join(errs, "\n"))
					m.showDialog(gtk.MessageError, msg)
				} else {
					m.showDialog(gtk.MessageInfo, fmt.Sprintf("Successfully processed %d files!", successCount))
					// Clear list on success
					selectedFiles = []string{}
					for {
						child := fileList.FirstChild()
						if child == nil { break }
						fileList.Remove(child)
					}
				}
			})
		}()
	})
	box.Append(actionBtn)

	lbl := gtk.NewLabel("Encrypt/Sign")
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

	label := gtk.NewLabel("Decrypt & Verify")
	label.SetMarkup("<b>Decrypt & Verify</b>")
	box.Append(label)

	// -- Multiple File Selection --
	fileList := gtk.NewListBox()
	fileList.SetSelectionMode(gtk.SelectionNone)
	fileList.SetSizeRequest(-1, 150)
	
	scrolled := gtk.NewScrolledWindow()
	scrolled.SetChild(fileList)
	scrolled.SetVExpand(true)
	
	listFrame := gtk.NewFrame("Encrypted Files")
	listFrame.SetChild(scrolled)
	box.Append(listFrame)

	// File Buttons
	fileBtnBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	browseBtn := gtk.NewButtonWithLabel("Add Encrypted...")
	clearBtn := gtk.NewButtonWithLabel("Clear List")
	fileBtnBox.Append(browseBtn)
	fileBtnBox.Append(clearBtn)
	box.Append(fileBtnBox)

	var selectedFiles []string

	// Function to remove a specific file
	removeFile := func(targetPath string, row *gtk.ListBoxRow) {
		for i, path := range selectedFiles {
			if path == targetPath {
				selectedFiles = append(selectedFiles[:i], selectedFiles[i+1:]...)
				break
			}
		}
		fileList.Remove(row)
	}

	browseBtn.ConnectClicked(func() {
		dialog := gtk.NewFileChooserNative("Select Encrypted", m.window, gtk.FileChooserActionOpen, "Add", "Cancel")
		dialog.SetSelectMultiple(true) // ENABLE MULTI-SELECTION

		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseAccept) {
				// Iterate over selected files from the list model
				filesList := dialog.Files()
				var i uint
				for i = 0; i < filesList.NItems(); i++ {
					obj := filesList.Item(i)
					if fileObj, ok := obj.Cast().(*gio.File); ok {
						path := fileObj.Path()
						// Avoid duplicates in the list
						alreadyExists := false
						for _, existing := range selectedFiles {
							if existing == path {
								alreadyExists = true
								break
							}
						}
						
						if !alreadyExists {
							selectedFiles = append(selectedFiles, path)
							
							row := gtk.NewListBoxRow()
							rowBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
							
							lbl := gtk.NewLabel(path)
							lbl.SetHAlign(gtk.AlignStart)
							lbl.SetHExpand(true)
							lbl.SetMarginStart(5)
							
							removeBtn := gtk.NewButtonWithLabel("✖") 
							removeBtn.SetMarginEnd(5)
							
							p := path
							r := row
							removeBtn.ConnectClicked(func() {
								removeFile(p, r)
							})

							rowBox.Append(lbl)
							rowBox.Append(removeBtn)
							row.SetChild(rowBox)
							fileList.Append(row)
						}
					}
				}
			}
			dialog.Destroy()
		})
		dialog.Show()
	})

	clearBtn.ConnectClicked(func() {
		selectedFiles = []string{}
		for {
			child := fileList.FirstChild()
			if child == nil { break }
			fileList.Remove(child)
		}
	})

	// -- Output Directory Selection --
	outDirBox := gtk.NewBox(gtk.OrientationHorizontal, 5)
	outDirEntry := gtk.NewEntry()
	outDirEntry.SetPlaceholderText("Output Directory (Optional - Default: Input Dir)")
	outDirEntry.SetHExpand(true)
	
	outDirBtn := gtk.NewButtonWithLabel("Select Output Dir...")
	outDirBtn.ConnectClicked(func() {
		dialog := gtk.NewFileChooserNative("Select Output Directory", m.window, gtk.FileChooserActionSelectFolder, "Select", "Cancel")
		dialog.ConnectResponse(func(resp int) {
			if resp == int(gtk.ResponseAccept) {
				outDirEntry.SetText(dialog.File().Path())
			}
			dialog.Destroy()
		})
		dialog.Show()
	})
	
	outDirBox.Append(gtk.NewLabel("Output:"))
	outDirBox.Append(outDirEntry)
	outDirBox.Append(outDirBtn)
	box.Append(outDirBox)

	symCheck := gtk.NewCheckButtonWithLabel("Symmetric (Password Only)")
	box.Append(symCheck)

	keyCombo := m.createLabeledCombo(box, "My Key (for decryption):")
	
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
	})

	decryptBtn := gtk.NewButtonWithLabel("Decrypt & Verify All")
	decryptBtn.ConnectClicked(func() {
		if len(selectedFiles) == 0 {
			m.showDialog(gtk.MessageError, "Please select at least one file to decrypt.")
			return
		}

		outputDir := outDirEntry.Text()
		keyID := ""
		isSym := symCheck.Active()
		
		if !isSym {
			keyID = keyCombo.ActiveID()
		}

		decryptBtn.SetSensitive(false)

		// Copy list
		filesToProcess := make([]string, len(selectedFiles))
		copy(filesToProcess, selectedFiles)

		go func() {
			defer glib.IdleAdd(func() { decryptBtn.SetSensitive(true) })

			var pass string
			var ok bool

			needPass := false
			if isSym {
				needPass = true
			} else {
				// Check if private key is locked
				isPrivate, isLocked, _ := m.GetKeyStatus(keyID)
				if isPrivate && isLocked {
					needPass = true
				}
			}

			if needPass {
				title := "Enter Decryption Password"
				if !isSym {
					title = "Enter Key Passphrase"
				}
				pass, ok = m.promptPassword(title)
				if !ok {
					return
				}
			}

			var logs []string
			
			for _, file := range filesToProcess {
				verifyMsg, err := m.decryptFile(file, pass, keyID, outputDir)
				if err != nil {
					logs = append(logs, fmt.Sprintf("❌ %s: Failed - %v", file, err))
				} else {
					logs = append(logs, fmt.Sprintf("✅ %s: Decrypted\n   (%s)", file, verifyMsg))
				}
			}
			
			glib.IdleAdd(func() {
				resultText := strings.Join(logs, "\n\n")
				
				// Show results in a scrolled dialog if too long
				dialog := gtk.NewDialog()
				dialog.SetTitle("Decryption Results")
				dialog.SetTransientFor(m.window)
				dialog.SetDefaultSize(600, 400)
				
				content := dialog.ContentArea()
				scrolled := gtk.NewScrolledWindow()
				scrolled.SetVExpand(true)
				
				tv := gtk.NewTextView()
				tv.SetEditable(false)
				tv.Buffer().SetText(resultText)
				
				scrolled.SetChild(tv)
				content.Append(scrolled)
				
				dialog.AddButton("Close", int(gtk.ResponseOK))
				dialog.ConnectResponse(func(id int) {
					dialog.Destroy()
				})
				dialog.Show()

				// Clear input list on success
				selectedFiles = []string{}
				for {
					child := fileList.FirstChild()
					if child == nil { break }
					fileList.Remove(child)
				}
			})
		}()
	})
	box.Append(decryptBtn)

	lbl := gtk.NewLabel("Decrypt/Verify")
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

	// -- Attachment UI Removed --

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
		rcptKeyID := recipientCombo.ActiveID()
		subject := subjectEntry.Text()

		buffer := bodyView.Buffer()
		start := buffer.StartIter()
		end := buffer.EndIter()
		body := buffer.Text(start, end, false)

		if rcptKeyID == "" {
			m.showDialog(gtk.MessageError, "Please select a recipient key.")
			return
		}

		sendBtn.SetSensitive(false)

		go func() {
			// Encrypt is ALWAYS true for this tab
			err := m.sendEmail(rcptKeyID, subject, body, true)
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
	label.SetSizeRequest(150, -1)
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
	label.SetSizeRequest(150, -1)
	label.SetHAlign(gtk.AlignStart)
	combo := gtk.NewComboBoxText()
	combo.SetHExpand(true)

	hbox.Append(label)
	hbox.Append(combo)
	if box != nil {
		box.Append(hbox)
	}

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
		name := ""
		email := "unknown"
		
		if entity := key.GetEntity(); entity != nil {
			_, ident := entity.PrimaryIdentity(time.Now(), nil)
			if ident != nil && ident.UserId != nil {
				name = ident.UserId.Name
				email = ident.UserId.Email
			}
		}
		
		displayText := email
		if name != "" {
			displayText = fmt.Sprintf("%s <%s>", name, email)
		}
		
		// Use ID as value, Display Text as label (without ID)
		c.Append(key.GetHexKeyID(), displayText)
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
