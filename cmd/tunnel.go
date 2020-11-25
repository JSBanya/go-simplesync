package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JSBanya/go-lfile"
	"github.com/fsnotify/fsnotify"
)

type Tunnel struct {
	IP       string
	Port     int64
	Password string
	Root     string

	conn    *Connection
	encConn *EncryptedConnection

	passwordHash []byte
	encKey       [KEY_SIZE]byte
	macKey       [KEY_SIZE]byte
}

// FileInfoReq.ReqType
const (
	REQ_TYPE_CREATE_FILE = iota
	REQ_TYPE_CREATE_DIR
	REQ_TYPE_UPDATE_PING
	REQ_TYPE_UPDATE
	REQ_TYPE_DELETE
)

type FileInfoReq struct {
	ReqType int
	RelPath string `json:"relPath"`
	ModTime int64  `json:"modTime"`
	DelTime int64  `json:"delTime"`
}

type FileInfoResp struct {
	PingOK   bool `json:"pingOK"`
	SendFile bool `json:"sendFile"`
}

// Start the connection to peer
func (t *Tunnel) Setup() error {
	// Create password hash
	var err error
	t.passwordHash, err = SHA256WithNewSalt([]byte(t.Password))
	if err != nil {
		return err
	}

	// Derive keys
	t.encKey, t.macKey = DeriveKeys(t.Password)

	// Ensure root contains trailing seperator
	t.Root = strings.TrimSuffix(t.Root, string(os.PathSeparator)) + string(os.PathSeparator)

	return nil
}

func (t *Tunnel) Start() {
	for {
		if t.conn != nil {
			t.conn.Close() // Close current connection
		}

		t.createConnections()
		log.Printf("[%v:%v] Connected", t.IP, t.Port)

		log.Printf("[%v:%v] Performing handshake", t.IP, t.Port)
		if err := t.doHandshake(); err != nil {
			log.Printf("[%v:%v] Unable to perform successful handshake: %s", t.IP, t.Port, err)
			continue
		}
		log.Printf("[%v:%v] Ready", t.IP, t.Port)

		if err := t.Watch(); err != nil {
			log.Printf("[%v:%v] Error watching files: %s", t.IP, t.Port, err)
			continue
		}
	}

	t.conn.Close()
}

// Attempt to start a connection, retrying indefinitely
func (t *Tunnel) createConnections() {
	firstLoop := false

	currentSleepTime := 3
	sleepTimeInc := 1
	maxSleepTime := 30

	for {
		if !firstLoop {
			time.Sleep(time.Duration(currentSleepTime) * time.Second)
			currentSleepTime += sleepTimeInc
			if currentSleepTime > maxSleepTime {
				currentSleepTime = maxSleepTime
			}
		}
		firstLoop = false

		log.Printf("Attempting to connect to peer at %v:%v\n", t.IP, t.Port)
		conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", t.IP, t.Port))
		if err != nil {
			log.Printf("Error connecting to peer at %v:%v : %s", t.IP, t.Port, err)
			continue
		}

		t.conn = &Connection{
			Conn: conn,
		}

		t.encConn = &EncryptedConnection{
			Connection: t.conn,
			encKey:     t.encKey,
			macKey:     t.macKey,
		}

		return // Tunnel established
	}
}

func (t *Tunnel) doHandshake() error {
	// Send hello
	if err := t.conn.WriteFull([]byte("hello")); err != nil {
		return err
	}

	data, err := t.conn.ReadFull()
	if err != nil {
		return err
	}

	if string(data) != "ok" {
		return errors.New("Bad protocol.")
	}

	// Check password
	if err = t.conn.WriteFull(t.passwordHash); err != nil {
		return err
	}

	data, err = t.conn.ReadFull()
	if err != nil {
		return err
	}

	if string(data) != "ok" {
		return errors.New("Bad protocol.")
	}

	return nil
}

func (t *Tunnel) Watch() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	if err = watcher.Add(t.Root); err != nil {
		return err
	}

	// Do initial sync
	// Get current files and directories
	files, dirs, err := ListItems(t.Root, "")
	if err != nil {
		return err
	}

	// Add all dirs to watcher
	// Create artificial watcher events to sync each directory
	for _, d := range dirs {
		e := fsnotify.Event{
			Name: t.Root + d,
			Op:   fsnotify.Create,
		}

		log.Printf("[Remote %v:%v] Synchronizing directory %s", t.IP, t.Port, e.Name)

		if err = t.handleEvent(e, watcher); err != nil { // Directory will be added to watcher automatically on create events
			return err
		}
	}

	// Create artificial watcher events to delete old files
	for relPath, _ := range __deleteTimes {
		e := fsnotify.Event{
			Name: t.Root + relPath,
			Op:   fsnotify.Remove,
		}

		log.Printf("[Remote %v:%v] Removing historic file %s", t.IP, t.Port, e.Name)

		if err = t.handleEvent(e, watcher); err != nil {
			return err
		}
	}

	// Create artificial watcher events to sync each file
	for _, f := range files {
		e := fsnotify.Event{
			Name: t.Root + f,
			Op:   fsnotify.Write,
		}

		log.Printf("[Remote %v:%v] Synchronizing file %s", t.IP, t.Port, e.Name)

		if err = t.handleEvent(e, watcher); err != nil {
			return err
		}
	}

	// Handle future events
	done := make(chan error)
	go t.WatchHandler(watcher, done)

	return <-done
}

func (t *Tunnel) WatchHandler(watcher *fsnotify.Watcher, done chan error) {
	for {
		select {
		case event, ok := <-watcher.Events:
			{
				if !ok {
					done <- errors.New("Watcher failed for unknown reason.")
					return
				}

				err := t.handleEvent(event, watcher)
				if err != nil {
					done <- err
					return
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				done <- errors.New(fmt.Sprintf("Watcher failed: %s", err))
				return
			}
		}
	}
}

func (t *Tunnel) handleEvent(e fsnotify.Event, watcher *fsnotify.Watcher) error {
	fullPath := e.Name
	relPath := strings.TrimPrefix(e.Name, t.Root)
	if relPath == fullPath {
		// File or directory not contained within root
		return nil
	}

	cleanedPath := filepath.Clean(relPath)
	if cleanedPath != relPath {
		return errors.New("Path not clean")
	}

	if cleanedPath == "" || cleanedPath == "." {
		// Cannot handle events on root itself
		return nil
	}

	// Handle event
	if e.Op&fsnotify.Remove == fsnotify.Remove || e.Op&fsnotify.Rename == fsnotify.Rename {
		// Deleted file (rename behaves as a delete+create)
		return t.handleEventDelete(fullPath, relPath, watcher)
	}

	if e.Op&fsnotify.Create == fsnotify.Create {
		// Created file or directory
		return t.handleEventCreate(fullPath, relPath, watcher)
	}

	if e.Op&fsnotify.Write == fsnotify.Write {
		// Modified file
		return t.handleEventUpdate(fullPath, relPath, watcher)
	}

	return nil
}

func (t *Tunnel) handleEventCreate(fullPath string, relPath string, watcher *fsnotify.Watcher) error {
	log.Printf("[Remote %v:%v] Initiated create for %s", t.IP, t.Port, relPath)
	delete(__deleteTimes, relPath)

	// Check if directory
	fi, err := os.Stat(fullPath)
	if err != nil && os.IsNotExist(err) {
		log.Println(err)
		return nil
	}

	reqType := REQ_TYPE_CREATE_FILE
	if fi.IsDir() {
		watcher.Add(fullPath)
		reqType = REQ_TYPE_CREATE_DIR
	}

	// Is a file
	// Create request
	req := &FileInfoReq{
		ReqType: reqType,
		RelPath: relPath,
		ModTime: fi.ModTime().UnixNano(),
	}

	// Send request metadata
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if err = t.encConn.WriteEncryptedFull(data); err != nil {
		return err
	}

	// No need to follow-up on create requests
	if reqType == REQ_TYPE_CREATE_DIR {
		log.Printf("[Remote %v:%v] Now synchronizing created directory %s", t.IP, t.Port, fullPath)
	} else {
		log.Printf("[Remote %v:%v] Now synchronizing created file %s", t.IP, t.Port, fullPath)
	}

	return nil
}

func (t *Tunnel) handleEventUpdate(fullPath string, relPath string, watcher *fsnotify.Watcher) error {
	log.Printf("[Remote %v:%v] Initiated update for %s", t.IP, t.Port, relPath)
	delete(__deleteTimes, relPath)

	// Send ping request
	// This is done to avoid race conditions and ensure file is write-locked on peer and read-locked locally before processing
	req := &FileInfoReq{
		ReqType: REQ_TYPE_UPDATE_PING,
		RelPath: relPath,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if err = t.encConn.WriteEncryptedFull(data); err != nil {
		return err
	}

	respData, err := t.encConn.ReadEncryptedFull()
	if err != nil {
		return err
	}

	var resp FileInfoResp
	err = json.Unmarshal(respData, &resp)
	if err != nil {
		return err
	}

	if !resp.PingOK {
		return errors.New("Update ping failed.")
	}

	// Open file
	f, err := os.OpenFile(fullPath, os.O_RDONLY, 0666)
	if err != nil {
		return nil
	}
	lf := lfile.New(f)
	defer lf.UnlockAndClose()

	// Lock file
	err = lf.RLock()
	if err != nil {
		return err
	}

	// Get the mod time
	stat, err := lf.Stat()
	if err != nil {
		return err
	}
	modTime := stat.ModTime()

	// Create request metadata
	req = &FileInfoReq{
		ReqType: REQ_TYPE_UPDATE,
		RelPath: relPath,
		ModTime: modTime.UnixNano(),
	}

	// Send request metadata
	data, err = json.Marshal(req)
	if err != nil {
		return err
	}

	if err = t.encConn.WriteEncryptedFull(data); err != nil {
		return err
	}

	// Get response
	respData, err = t.encConn.ReadEncryptedFull()
	if err != nil {
		return err
	}

	var resp2 FileInfoResp
	err = json.Unmarshal(respData, &resp2)
	if err != nil {
		return err
	}

	// Check response
	if resp2.SendFile {
		// Server requesting file
		log.Printf("[%v:%v] Transferring file %s", t.IP, t.Port, relPath)
		if err = t.encConn.WriteEncryptedStream(lf, uint64(stat.Size())); err != nil {
			return err
		}
		log.Printf("[%v:%v] Transfer complete for %s", t.IP, t.Port, relPath)
	} else {
		log.Printf("[%v:%v] No update needed for %s", t.IP, t.Port, relPath)
	}

	return nil
}

func (t *Tunnel) handleEventDelete(fullPath string, relPath string, watcher *fsnotify.Watcher) error {
	log.Printf("[Remote %v:%v] Initiated delete for %s", t.IP, t.Port, relPath)

	var delTime int64
	if _, ok := __deleteTimes[relPath]; ok {
		delTime = __deleteTimes[relPath]
	} else {
		delTime = time.Now().UnixNano()
		__deleteTimes[relPath] = delTime
	}
	watcher.Remove(fullPath)

	req := &FileInfoReq{
		ReqType: REQ_TYPE_DELETE,
		RelPath: relPath,
		DelTime: delTime,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if err = t.encConn.WriteEncryptedFull(data); err != nil {
		return err
	}

	return nil
}
