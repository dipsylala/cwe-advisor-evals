package main

import (
	"crypto/cipher"
	"crypto/des"
	"io"
	"net/http"
)

func encryptUploadHandler(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	key := []byte(r.FormValue("key"))
	// SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
	block, err := des.NewCipher(key)
	if err != nil {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}

	iv := make([]byte, des.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	w.Write(ciphertext)
}
