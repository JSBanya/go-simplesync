package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type Connection struct {
	net.Conn
}

type EncryptedConnection struct {
	*Connection

	encKey [KEY_SIZE]byte
	macKey [KEY_SIZE]byte
}

func (c *Connection) WriteLength(l uint64) error {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, l)
	_, err := c.Write(buf)
	return err
}

func (c *Connection) ReadLength() (uint64, error) {
	lenData := make([]byte, binary.MaxVarintLen64)
	_, err := io.ReadFull(c, lenData)
	if err != nil {
		return 0, err
	}

	l, n := binary.Uvarint(lenData)
	if n <= 0 {
		return 0, errors.New("Error in reading length data")
	}

	return l, nil
}

func (c *Connection) WriteFull(data []byte) error {
	l := uint64(len(data))
	err := c.WriteLength(l)

	_, err = c.Write(data)
	return err
}

func (c *Connection) ReadFull() ([]byte, error) {
	// Read length
	l, err := c.ReadLength()
	if err != nil {
		return nil, err
	}

	// Read data
	data := make([]byte, l)
	_, err = io.ReadFull(c, data)
	return data, err
}

func (c *Connection) ReadBytes(size uint64) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(c, data)
	return data, err
}

func (c *EncryptedConnection) ReadIV() ([aes.BlockSize]byte, error) {
	b, err := c.ReadBytes(aes.BlockSize)
	if err != nil {
		return [aes.BlockSize]byte{}, err
	}

	var iv [aes.BlockSize]byte
	copy(iv[:], b)
	return iv, nil
}

func (c *EncryptedConnection) ReadMAC() ([]byte, error) {
	return c.ReadBytes(HASH_SIZE)
}

func (c *EncryptedConnection) WriteEncryptedFull(data []byte) error {
	r := bytes.NewReader(data)
	return c.WriteEncryptedStream(r, uint64(len(data)))
}

func (c *EncryptedConnection) ReadEncryptedFull() ([]byte, error) {
	var b bytes.Buffer
	buf := bufio.NewWriter(&b)
	err := c.ReadEncryptedStream(buf)
	return b.Bytes(), err
}

func (c *EncryptedConnection) WriteEncryptedStream(source io.Reader, l uint64) error {
	encStream, err := NewEncryptStream(c.encKey, c)
	if err != nil {
		return err
	}

	mac := NewHMAC(c.macKey[:])

	if err = c.WriteLength(l); err != nil {
		return err
	}

	if _, err = c.Write(encStream.IV[:]); err != nil {
		return err
	}

	tee := io.TeeReader(source, mac)

	if _, err = io.Copy(encStream, tee); err != nil {
		return err
	}

	macSum := mac.Sum(nil)
	_, err = c.Write(macSum)
	return err
}

func (c *EncryptedConnection) ReadEncryptedStream(target io.Writer) error {
	size, err := c.ReadLength()
	if err != nil {
		return err
	}

	iv, err := c.ReadIV()
	if err != nil {
		return err
	}

	decStream, err := NewDecryptStream(c.encKey, iv, c)
	if err != nil {
		return err
	}

	mac := NewHMAC(c.macKey[:])
	tee := io.TeeReader(decStream, mac)

	if _, err = io.CopyN(target, tee, int64(size)); err != nil {
		return err
	}

	sentMac, err := c.ReadMAC()
	if err != nil {
		return err
	}

	macSum := mac.Sum(nil)
	if !ConstantTimeCompare(sentMac, macSum) {
		return errors.New("hashes do not match")
	}

	return nil
}
