package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
	"syscall"
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fatal("wrong number of arguments.")
	}

	filePath := os.Args[1]

	err = checkExist(filePath)
	check(err)

	f, err := os.Open(filePath)
	check(err)

	var password []byte

	if len(os.Args) >= 3 {
		password = []byte(os.Args[2])
	} else {
		password, err = readPassword()
		check(err)
	}

	defer f.Close()

	buf := bufio.NewReader(f)

	magic, err := readInt16(buf)
	check(err)

	if magic != 1285 {
		fatal("not SafeInCloud.db file")
	}

	version, err := readByte(buf)
	check(err)

	if version != 1 {
		fatal("unknown database version")
	}

	salt, err := readByteArray(buf)
	check(err)

	iv, err := readByteArray(buf)
	check(err)

	secretSalt, err := readByteArray(buf)
	check(err)

	secrets, err := readByteArray(buf)
	check(err)

	key := pbkdf2.Key(password, salt, 10000, 32, sha1.New)

	block, err := aes.NewCipher(key)
	check(err)

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(secrets, secrets)

	secretsBuf := bufio.NewReader(bytes.NewReader(secrets))

	secretIv, err := readByteArray(secretsBuf)
	check(err)

	secretKey, err := readByteArray(secretsBuf)
	check(err)

	checkSum, err := readByteArray(secretsBuf)
	check(err)

	calculatedCheckSum := pbkdf2.Key(secretKey, secretSalt, 1000, 32, sha1.New)

	if !bytes.Equal(checkSum, calculatedCheckSum) {
		fatal("wrong password")
	}

	xml, err := ioutil.ReadAll(buf)
	check(err)

	block, err = aes.NewCipher(secretKey)
	check(err)

	mode = cipher.NewCBCDecrypter(block, secretIv)
	mode.CryptBlocks(xml, xml)

	r, err := zlib.NewReader(bytes.NewReader(xml))
	check(err)

	xml, err = ioutil.ReadAll(r)
	check(err)

	xml, err = formatXml(xml)
	check(err)

	io.Copy(os.Stdout, bytes.NewReader(xml))
	fmt.Println()
}

func fatal(err string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}

func check(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func checkExist(filePath string) error {
	_, err := os.Stat(filePath)

	if os.IsNotExist(err) {
		return fmt.Errorf("no such file or directory")
	}

	return err
}

func readPassword() ([]byte, error) {
	fmt.Fprint(os.Stderr, "Password:")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	return password, err
}

func formatXml(data []byte) ([]byte, error) {
	buff := &bytes.Buffer{}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	encoder := xml.NewEncoder(buff)
	encoder.Indent("", "  ")
	var err error
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		encoder.EncodeToken(token)
	}

	encoder.Flush()
	if err == nil || err == io.EOF {
		return buff.Bytes(), nil
	} else {
		return buff.Bytes(), err
	}
}

func readByte(reader *bufio.Reader) (byte, error) {
	var value byte
	err := binary.Read(reader, binary.LittleEndian, &value)
	return value, err
}

func readInt16(reader *bufio.Reader) (int16, error) {
	var value int16
	err := binary.Read(reader, binary.LittleEndian, &value)
	return value, err
}

func readByteArray(reader *bufio.Reader) ([]byte, error) {
	num, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, num)
	_, err = io.ReadFull(reader, buf)
	return buf, err
}
