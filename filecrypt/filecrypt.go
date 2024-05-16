package filecrypt

import (
    "encoding/hex"
    "io"
    "os"
    "golang.org/x/crypto/pbkdf2"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha1"
)

func Encrypt(source string, password []byte){

    if _, err := os.Stat(source); os.IsNotExist(err){
        panic(err.Error())
    }

    srcFile, err := os.Open(source)

    if err != nil {
        panic(err.Error())
    }

    defer srcFile.Close()

    plainText, err := io.ReadAll(srcFile)

    if err != nil {
        panic(err.Error())
    }

    key := password

    nonce := make([]byte, 12)

    // Randomizing the nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

    dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

    block, err := aes.NewCipher(dk)

    if err != nil {
        panic(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)

    if err != nil {
        panic(err.Error())
    }

    ciphertext := aesgcm.Seal(nil, nonce, plainText, nil)

    ciphertext = append(ciphertext, nonce...)

    dstFile, err := os.Create(source)

    if err != nil {
        panic(err.Error())
    }

    defer dstFile.Close()

    _, err = dstFile.Write(ciphertext)

    if err != nil {
        panic(err.Error())
    }

}

func Decrypt(source string, password []byte){

    if _, err := os.Stat(source); os.IsNotExist(err){
        panic(err.Error())
    }


    srcFile, err := os.Open(source)

    if err != nil {
        panic(err.Error())
    }

    cipherText, err := io.ReadAll(srcFile)

    if err != nil {
        panic(err.Error())
    }

    key := password

    salt := cipherText[len(cipherText) - 12:]

    str__ := hex.EncodeToString(salt)

    nonce, err := hex.DecodeString(str__)

    dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

    block, err := aes.NewCipher(dk)

    if err != nil {
        panic(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)

    if err != nil {
        panic(err.Error())
    }

    plainText, err := aesgcm.Open(nil, nonce, cipherText[:len(cipherText) - 12], nil)

    if err != nil {
        panic(err.Error())
    }


    dstFile, err := os.Create(source)

    if err != nil {
        panic(err.Error())
    }

    defer dstFile.Close()

    _, err = dstFile.Write(plainText)

    if err != nil {
        panic(err.Error())
    }




}