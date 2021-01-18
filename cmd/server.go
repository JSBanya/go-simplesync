package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/JSBanya/go-lfile"
)

// States
const (
	SERVER_EXIT = iota
	SERVER_HANDLE_HELLO
	SERVER_HANDLE_PASSWORD
	SERVER_HANDLE_GENERIC
)

type Server struct {
	Port     int64
	Password string
	Root     string

	encKey [KEY_SIZE]byte
	macKey [KEY_SIZE]byte
}

var __deleteTimes map[string]int64 = make(map[string]int64) // We store delete times to properly handle deletes over several connections and long periods of time

func (s *Server) Start() error {
	// Derive keys
	s.encKey, s.macKey = DeriveKeys(s.Password)

	// Ensure root contains trailing seperator
	s.Root = strings.TrimSuffix(s.Root, string(os.PathSeparator)) + string(os.PathSeparator)

	// Listen
	ln, err := net.Listen("tcp", fmt.Sprintf(":%v", s.Port))
	if err != nil {
		return err
	}

	log.Printf("Listening on port %v", s.Port)

	// Handle incoming connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		c := &Connection{
			Conn: conn,
		}

		go s.handleConnection(c)
	}
}

func (s *Server) handleConnection(conn *Connection) {
	defer conn.Close()

	if err := s.doHandshake(conn); err != nil {
		log.Printf("[%s] Unable to perform successful handshake: %s", conn.RemoteAddr(), err)
		return
	}

	// Successfully connected
	// Setup encrypted connection
	encConn := &EncryptedConnection{
		Connection: conn,
		encKey:     s.encKey,
		macKey:     s.macKey,
	}

	// Listen for incoming data indefinitely
	if err := s.handleRequests(encConn); err != nil {
		log.Printf("[%s] Error handling requests: %s", conn.RemoteAddr(), err)
		return
	}
}

func (s *Server) doHandshake(conn *Connection) error {
	// Read hello
	data, err := conn.ReadFull()
	if err != nil {
		return err
	}

	if string(data) != "hello" {
		return errors.New("Bad protocol")
	}

	err = conn.WriteFull([]byte("ok"))
	if err != nil {
		return err
	}

	// Read password
	data, err = conn.ReadFull()
	if err != nil {
		return err
	}

	if len(data) != SALT_SIZE+2+HASH_SIZE {
		return errors.New("Unexpected protocol (bad size)")
	}

	salt := data[:SALT_SIZE] // Split salt and hash

	expected := SHA256WithPredefinedSalt([]byte(s.Password), salt)
	if !ConstantTimeCompare(expected, data) { // Compare send and expected hashes
		return errors.New("Bad password")
	}

	err = conn.WriteFull([]byte("ok"))
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) handleRequests(conn *EncryptedConnection) error {
	for {
		data, err := conn.ReadEncryptedFull() // Block until data is read
		if err != nil {
			return err
		}

		// Convert data to request
		var req FileInfoReq
		err = json.Unmarshal(data, &req)
		if err != nil {
			return err
		}

		// Check request type
		switch req.ReqType {
		case REQ_TYPE_UPDATE:
			{
				// Do update
				if err = s.handleUpdate(conn, &req); err != nil {
					return err
				}
			}
		case REQ_TYPE_CREATE_DIR:
			{
				// Do create
				if err = s.handleCreateDir(conn, &req); err != nil {
					return err
				}
			}
		case REQ_TYPE_DELETE:
			{
				// Do delete
				if err = s.handleDelete(conn, &req); err != nil {
					return err
				}
			}
		default:
			return errors.New("Unknown request type")
		}
	}
}

func (s *Server) handleCreateDir(conn *EncryptedConnection, req *FileInfoReq) error {
	relPath := req.RelPath
	fqpath := s.Root + relPath
	modTime := time.Unix(0, req.ModTime)

	_, err := os.Stat(fqpath)
	if err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil {
		// Directory already exists
		return nil
	}

	if err = os.MkdirAll(fqpath, 0777); err != nil {
		return err
	}

	log.Printf("[Local %s] Created new directory %s", conn.RemoteAddr(), req.RelPath)
	return os.Chtimes(fqpath, modTime, modTime)
}

func (s *Server) handleUpdate(conn *EncryptedConnection, req *FileInfoReq) error {
	relPath := req.RelPath
	fqpath := s.Root + relPath
	modTime := time.Unix(0, req.ModTime)

	resp := &FileInfoResp{}
	resp.SendFile = false

	// Check if file exists
	fexists := true
	stat, err := os.Stat(fqpath)
	if err != nil && os.IsNotExist(err) {
		// File does not exist locally, always request send
		fexists = false
		resp.SendFile = true
	} else if err != nil {
		return err
	}

	// Stat file
	if fexists {
		// File exists locally, compare mod-times
		if stat.ModTime().Before(modTime) {
			// Local file is older
			resp.SendFile = true
		}
	}

	// Send response
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	if err = conn.WriteEncryptedFull(data); err != nil {
		return err
	}

	if !resp.SendFile {
		// We requested file not to be sent, so exit
		return nil
	}

	log.Printf("[Local %s] Getting file transfer for %s", conn.RemoteAddr(), relPath)

	// Create a temporary file to write to so that we don't overwrite old file if transfer fails
	// Writing to a temporary file also avoids deadlocks caused by immediately write-locking the file
	// The temporary file will be "revoled" to the real file later whenever a lock can be aquired
	tempFile, err := ioutil.TempFile("", "")
	if err != nil {
		return err
	}
	defer func() {
		tempFile.Close()
		os.Remove(tempFile.Name())
	}()

	// Begin reading file
	if err = conn.ReadEncryptedStream(tempFile); err != nil {
		return err
	}

	if _, err := tempFile.Seek(0, 0); err != nil {
		return err
	}

	// File transfer successful, swap old file with temp file
	// This is done as soon as we can get a lock

	// Open file and create if not exists
	var f *os.File
	stat, err = os.Stat(fqpath)
	if err != nil && os.IsNotExist(err) {
		// File still does not exist, so we can safely create and lock it
		f, err = os.Create(fqpath)
		if err != nil {
			return err
		}
	} else if err != nil {
		// Unhandled stat error
		return err
	} else {
		// File exists
		if !stat.ModTime().Before(modTime) {
			// Local file is now newer, exit
			log.Printf("[Local %s] Refuse to resolve %s, file updated locally.", conn.RemoteAddr(), relPath)
			return nil // Silent exit
		} else {
			// Open the existing file
			f, err = os.OpenFile(fqpath, os.O_RDWR, 0666)
			if err != nil {
				return err
			}
		}
	}

	// Lock file
	lf := lfile.New(f)
	defer func() {
		log.Printf("[Local %s] Unlocking %s...", conn.RemoteAddr(), relPath)
		lf.UnlockAndClose()
		log.Printf("[Local %s] Unlocked %s", conn.RemoteAddr(), relPath)
	}()

	log.Printf("[Local %s] Locking %s to resolve transfer...", conn.RemoteAddr(), relPath)
	err = lf.RWLock()
	if err != nil {
		return err
	}
	log.Printf("[Local %s] Locked %s", conn.RemoteAddr(), relPath)

	// Resolve file
	if err = lf.Truncate(0); err != nil {
		return err
	}

	if _, err = io.Copy(lf, tempFile); err != nil {
		return err
	}

	if err = os.Chtimes(fqpath, modTime, modTime); err != nil {
		return err
	}

	log.Printf("[Local %s] Updated file %s", conn.RemoteAddr(), relPath)
	return nil
}

func (s *Server) handleDelete(conn *EncryptedConnection, req *FileInfoReq) error {
	relPath := req.RelPath
	fqpath := s.Root + relPath
	delTime := time.Unix(0, req.DelTime)

	fi, err := os.Stat(fqpath)
	if err != nil && os.IsNotExist(err) {
		// File already deleted
		return nil
	} else if err != nil {
		return err
	}

	// Check mod time
	if !fi.ModTime().Before(delTime) {
		// Delete is not the most recent op, ignore
		return nil
	}

	// Delete is most recent; do delete
	log.Printf("[Local %s] Deleting file %s", conn.RemoteAddr(), relPath)
	__deleteTimes[relPath] = req.DelTime
	return os.RemoveAll(fqpath)
}
