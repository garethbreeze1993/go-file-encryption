package main

import (
    "bytes"
    "fmt"
    "os"

    "github.com/garethbreeze1993/go-file-encryption/filecrypt"
    "golang.org/x/term"

)

func main(){
    if len(os.Args) < 2 {
        printHelp()
        os.Exit(0)
    }

    function := os.Args[1]
    switch function{
    case "help":
        printHelp()
    case "encrypt":
        encryptHandle()
    case "decrypt":
        decryptHandle()
    default:
        fmt.Println("Run encrypt to encrypt a file and decrypt to decrypt a file")
        os.Exit(1)
    }
}

func printHelp() {

    fmt.Println("CryptoGo")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tCryptoGo encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")

}

func encryptHandle() {

	if len(os.Args) < 3 {
		println("Missing the path to the file. For more information run CryptoGo help")
		os.Exit(0)
	}

	file := os.Args[2]
	if !validateFile(file){
	    panic("File not found")
	}

	password := getPassword()

	fmt.Println("\nEncrypting...")
	filecrypt.Encrypt(file, password)
	fmt.Println("\nFile successfully protected")
}

func decryptHandle() {

    if len(os.Args) < 3 {
		println("Missing the path to the file. For more information run CryptoGo help")
		os.Exit(0)
	}

	file := os.Args[2]

	if !validateFile(file) {
		panic("File not found")
	}

	fmt.Print("Enter password: ")
	password, _ := term.ReadPassword(0)

	fmt.Println("\nDecrypting...")
	filecrypt.Decrypt(file, password)
	fmt.Println("\nFile successfully decrypted.")
}

func getPassword() []byte{
    fmt.Print("Please Enter Password")
    password, _ := term.ReadPassword(0)
    fmt.Print("\nPlease Confirm Password")
    password2, _ := term.ReadPassword(0)

    if !validatePassword(password, password2){
        fmt.Print("\n Passwords do not match please try again")
        return getPassword()
    }
    return password
}

func validatePassword(password1 []byte, password2 []byte) bool{

    if !bytes.Equal(password1, password2){
        return false
    }

    return true

}

func validateFile(file string) bool {
    if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}

	return true

}