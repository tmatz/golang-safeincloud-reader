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
    "io"
    "io/ioutil"
    "os"
)

func main() {
    if len(os.Args) != 3 {
        fmt.Println("wrong number of arguments.")
        os.Exit(1)
    }

    filePath := os.Args[1]
    password := []byte(os.Args[2])

    f, err := os.Open(filePath)
    if err != nil {
        fmt.Println(err)
        return
    }

    defer f.Close()

    buf := bufio.NewReader(f)

    /*magic, _ :=*/ readInt16(buf)
    /*version, _ :=*/ readByte(buf)
    salt, _ := readByteArray(buf)
    iv, _ := readByteArray(buf)
    secretSalt, _ := readByteArray(buf)
    secrets, _ := readByteArray(buf)

    key := pbkdf2.Key(password, salt, 10000, 32, sha1.New)

    block, err := aes.NewCipher(key)

    mode := cipher.NewCBCDecrypter(block, iv)

    mode.CryptBlocks(secrets, secrets)

    secretsBuf := bufio.NewReader(bytes.NewReader(secrets))

    secretIv, _ := readByteArray(secretsBuf)
    secretKey, _ := readByteArray(secretsBuf)
    checkSum, _ := readByteArray(secretsBuf)

    calculatedCheckSum := pbkdf2.Key(
	    secretKey, secretSalt, 1000, 32, sha1.New)

    if !bytes.Equal(checkSum, calculatedCheckSum) {
        fmt.Println("wrong password")
        return
    }

    xml, err := ioutil.ReadAll(buf)

    block, err = aes.NewCipher(secretKey)

    mode = cipher.NewCBCDecrypter(block, secretIv)
    mode.CryptBlocks(xml, xml)

    r, err := zlib.NewReader(bytes.NewReader(xml))
    xml, _ = ioutil.ReadAll(r)
    xml, _ = formatXml(xml)

    io.Copy(os.Stdout, bytes.NewReader(xml))
    fmt.Println()
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
            break;
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
    binary.Read(reader, binary.LittleEndian, &value)
    return value, nil
}

func readInt16(reader *bufio.Reader) (int16, error) {
    var value int16
    binary.Read(reader, binary.LittleEndian, &value)
    return value, nil
}

func readByteArray(reader *bufio.Reader) ([]byte, error) {
    num, err := reader.ReadByte()
    buf := make([]byte, num)
    _, err = io.ReadFull(reader, buf)
    return buf, err
}
