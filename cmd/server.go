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
		case REQ_TYPE_UPDATE_PING:
			{
				// Do update
				if err = s.handleUpdate(conn, &req); err != nil {
					return err
				}
			}
		case REQ_TYPE_CREATE_FILE, REQ_TYPE_CREATE_DIR:
			{
				// Do create
				if err = s.handleCreate(conn, &req); err != nil {
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

func (s *Server) handleCreate(conn *EncryptedConnection, req *FileInfoReq) error {
	relPath := req.RelPath
	fqpath := s.Root + relPath
	modTime := time.Unix(0, req.ModTime)

	_, err := os.Stat(fqpath)
	if err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil {
		// File/Directory already exists
		return nil
	}

	if req.ReqType == REQ_TYPE_CREATE_DIR {
		if err = os.MkdirAll(fqpath, 0777); err != nil {
			return err
		}

		log.Printf("[Local %s] Created new directory %s", conn.RemoteAddr(), req.RelPath)
		return os.Chtimes(fqpath, modTime, modTime)
	}

	// File/Directory doesn't exist, create
	f, _ := os.Create(fqpath)
	f.Close()
	log.Printf("[Local %s] Created new file %s", conn.RemoteAddr(), req.RelPath)
	return os.Chtimes(fqpath, modTime, modTime)
}

func (s *Server) handleUpdate(conn *EncryptedConnection, req *FileInfoReq) error {
	relPath := req.RelPath
	fqpath := s.Root + relPath

	// Check if file exists
	fexists := true
	_, err := os.Stat(fqpath)
	if err != nil && os.IsNotExist(err) {
		fexists = false
	} else if err != nil {
		return err
	}

	// Open file and create if not exists
	f, err := os.OpenFile(fqpath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}

	// Lock file
	lf := lfile.New(f)
	err = lf.RWLock()
	if err != nil {
		return err
	}
	defer lf.UnlockAndClose()

	// Send ping response
	resp := &FileInfoResp{}
	resp.PingOK = true
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	if err = conn.WriteEncryptedFull(data); err != nil {
		return err
	}

	// Get follow-up file info
	data, err = conn.ReadEncryptedFull()
	if err != nil {
		return err
	}

	var req2 FileInfoReq
	err = json.Unmarshal(data, &req2)
	if err != nil {
		return err
	}

	if req2.RelPath != relPath {
		return errors.New("Mismatching ping and data requests.")
	}

	modTime := time.Unix(0, req2.ModTime)

	// Stat file
	stat, err := lf.Stat()
	if err != nil {
		return err
	}

	// Check mod time
	resp = &FileInfoResp{}
	if stat.ModTime().Before(modTime) || !fexists {
		// Request update if local version is older or file was created as a result of this action
		resp.SendFile = true
	} else {
		// Local version is same or newer, do not update
		resp.SendFile = false
	}

	data, err = json.Marshal(resp)
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

	log.Printf("[Local %s] Getting file transfer for %s", conn.RemoteAddr(), req.RelPath)

	// Create a temporary file to write to so that we don't overwrite old file if transfer fails
	tempFile, err := ioutil.TempFile("", "")
	if err != nil {
		return err
	}
	defer func() {
		tempFile.Close()
		os.Remove(tempFile.Name())
	}()

	// File was requested, begin reading file
	if err = conn.ReadEncryptedStream(tempFile); err != nil {
		return err
	}

	// File transfer successful, swap old file with temp file
	if _, err := tempFile.Seek(0, 0); err != nil {
		return err
	}

	if err = lf.Truncate(0); err != nil {
		return err
	}

	if _, err = io.Copy(lf, tempFile); err != nil {
		return err
	}

	if err = os.Chtimes(fqpath, modTime, modTime); err != nil {
		return err
	}

	log.Printf("[Local %s] Updated file %s", conn.RemoteAddr(), req.RelPath)
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
	__deleteTimes[relPath] = req.DelTime
	return os.RemoveAll(fqpath)
}
