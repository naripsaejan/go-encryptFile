package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

type CryptoAESGCMService struct{}

const (
	tagLength = 16 // 128 bits for GCM
	ivLength  = 12 // GCM standard IV length
)

func (s *CryptoAESGCMService) DecryptFile(encryptedData string, accessKey string, outputFilePath string) error {
	cipherKey := []byte(accessKey)

	// Decode base64 string
	decode, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return err
	}

	if len(decode) < ivLength {
		return fmt.Errorf("invalid encrypted data")
	}

	// Extract IV
	iv := decode[:ivLength]
	cipherText := decode[ivLength:]

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Decrypt
	plainText, err := aead.Open(nil, iv, cipherText, nil)
	if err != nil {
		return err
	}

	// Write the decrypted data to a file
	if err := ioutil.WriteFile(outputFilePath, plainText, 0644); err != nil {
		return err
	}

	return nil
}


func (s *CryptoAESGCMService) TESTEncryptFile(data []byte, accessKey string) (string, error) {
	cipherKey := []byte(accessKey)

	// Create IV
	iv := make([]byte, ivLength)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt
	cipherText := aead.Seal(nil, iv, data, nil)

	// Combine IV and cipherText
	cipherData := append(iv, cipherText...)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(cipherData), nil
}

func main() {
	service := &CryptoAESGCMService{}
	accessKey := "0123456789abcdef0123456789zzz346"

	// Path to the encrypted file
	pathIn := "pathIn/KTB_USER_DETAIL_1_20241018.TXT"
outputFilePath := "pathOut/decrypted_output.txt" // Specify your output path
	// Read the encrypted data from the file
	encryptedData, err := ioutil.ReadFile(pathIn)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Convert the encrypted data from byte slice to string
	encryptedDataStr := string(encryptedData)

	// Decrypt the data and save to a file
	if err := service.DecryptFile(encryptedDataStr, accessKey, outputFilePath); err != nil {
		log.Fatalf("Error decrypting: %v", err)
	}

	fmt.Printf("Decrypted data saved to %s\n", outputFilePath)

	// // Example: Encrypting and saving back to file (optional)
	// plainText := []byte("Hello, World!")
	// encrypted, err := service.TESTEncryptFile(plainText, accessKey)
	// if err != nil {
	// 	log.Fatalf("Error encrypting: %v", err)
	// }

	// // Save the encrypted data back to a file
	// err = ioutil.WriteFile("pathIn/encrypted_out.TXT", []byte(encrypted), 0644)
	// if err != nil {
	// 	log.Fatalf("Error writing file: %v", err)
	// }
	// fmt.Println("Encrypted data saved to encrypted_out.TXT")
}
