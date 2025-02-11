package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

var filename string

// Structure to hold license details
type licensefile struct {
	expiry_date string
	user_id     string
}

var Encryptedfile string = "Encryptedfile.txt"

// Function to read license details
func (eg *licensefile) read_info(date *string, user_id *string) {
	fmt.Println("Enter the expiry date of the license file in YYYY-MM-DD format:")
	fmt.Scanln(&eg.expiry_date)
	*date = eg.expiry_date
	fmt.Println("Enter the User Id:")
	fmt.Scanln(&eg.user_id)
	*user_id = eg.user_id
}

// Function to read and write file data
func (eg *licensefile) open_file() {
	fmt.Println("Enter the filename with type:")
	fmt.Scanln(&filename)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error in opening the file")
		return
	}
	defer file.Close()

	file.WriteString("expiry_date:" + eg.expiry_date + "\n")
	file.WriteString("User_id:" + eg.user_id + "\n")
}

// Function to encrypt the raw file
func encryptfile(inputfile string, outputfile string, publicKey *rsa.PublicKey) error {
	file, err := os.Open(inputfile)
	if err != nil {
		return fmt.Errorf("error opening the file: %w", err)
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error reading the file: %w", err)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		return fmt.Errorf("error encrypting file: %w", err)
	}

	encryptedfile, err := os.Create(outputfile)
	if err != nil {
		return fmt.Errorf("error creating encrypted file: %w", err)
	}
	defer encryptedfile.Close()

	_, err = encryptedfile.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("error writing ciphertext to output file: %w", err)
	}

	return nil
}

// Function to decrypt the encrypted file
func decryptfile(encryptedfile, outputfile, privateKeyPath string) error {
	// Load private key from PEM file
	privateKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("error loading private key: %w", err)
	}

	file, err := os.Open(encryptedfile)
	if err != nil {
		return fmt.Errorf("error opening encrypted file: %w", err)
	}
	defer file.Close()

	ciphertext, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error reading encrypted file: %w", err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("error decrypting file: %w", err)
	}

	decryptedfile, err := os.Create(outputfile)
	if err != nil {
		return fmt.Errorf("error creating decrypted file: %w", err)
	}
	defer decryptedfile.Close()

	_, err = decryptedfile.Write(plaintext)
	if err != nil {
		return fmt.Errorf("error writing decrypted text to output file: %w", err)
	}

	return nil
}

// Function to generate and save RSA private key
func GeneratePrivatekeyFile(filename string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %w", err)
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("error creating private key file: %w", err)
	}
	defer file.Close()

	err = pem.Encode(file, privPemBlock)
	if err != nil {
		return nil, fmt.Errorf("error encoding PEM block: %w", err)
	}

	return privateKey, nil
}

// Function to load a private key from a PEM file
func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	return privateKey, nil
}

func validateLicense(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("error opening the file: %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return false, fmt.Errorf("error reading the file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "expiry_date:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "expiry_date:"))
			expiryDate, err := time.Parse("2006-01-02", dateStr)
			if err != nil {
				return false, fmt.Errorf("invalid date format in the file: %w", err)
			}

			if time.Now().Before(expiryDate) {
				return true, nil
			}
			return false, nil
		}
	}
	return false, fmt.Errorf("expiry_date not found in the file")
}

func displaycontentinfile(filename string) error {

	file, err := os.Open(filename)
	if err != nil {

		return fmt.Errorf("error in opening the file : %w", err)

	}

	content, err := io.ReadAll(file)
	if err != nil {

		return fmt.Errorf("error in reading the file : %w", err)

	}

	fmt.Println("Input given by user :")

	fmt.Println(string(content))
	return nil
}

//checing if the License file exists or no

func checkFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func main() {
	lcfile := licensefile{}
	var temp1, temp2 string
	lcfile.read_info(&temp1, &temp2)
	fmt.Printf("The expiry date of the license file is %s \n", temp1)
	lcfile.open_file()

	privateKeyFile := "privatekey.pem"
	prkey, err := GeneratePrivatekeyFile(privateKeyFile)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	err = encryptfile(filename, "Encryptedfile.txt", &prkey.PublicKey)
	if err != nil {
		fmt.Println("Error encrypting the file:", err)
		return
	}

	fmt.Println("File encrypted successfully")

	YNresponse()

}

func YNresponse() string {

	var ans string
	for {

		fmt.Println("Do you want to decrypt the file(Y/N):")
		fmt.Scanln(&ans)

		if ans == "Y" || ans == "N" {
			break
		}
		fmt.Println("Invalid input. Please enter Y or N.")
	}

	if ans == "Y" {
		Y()
	} else {
		fmt.Println("Decryption has stopped")
		return ans
	}
	return ans
}

func Y() {
	var privateKeyPath string
	fmt.Println("Enter the private key file path to decrypt:")
	fmt.Scanln(&privateKeyPath)
	err := decryptfile(Encryptedfile, "decryptedfile.txt", privateKeyPath)
	if err != nil {
		fmt.Println("Error decrypting the file:", err)
		return
	}

	fmt.Println("File decrypted successfully")
	valid, err := validateLicense(filename)
	if err != nil {
		fmt.Println("Error validating the license:", err)
		return
	}

	if valid {
		fmt.Println("------------------------------------------")
		fmt.Println(" License is valid. Access granted.\n", "displaying the contents inside the file:")
		fmt.Println("-----------------------------------------")
		err := displaycontentinfile(filename)
		if err != nil {
			fmt.Println("error while displaying the file : %w", err)
		}
	} else {
		fmt.Println("License has expired. Access denied !!! .")
	}

	// file checking for every 24 hours
	if checkFileExists(filename) {
		fmt.Println("File exists.")
	} else {

		fmt.Println("File does not exist.")
	}

	time.Sleep(10 * time.Second)

}
