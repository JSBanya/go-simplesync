package main

import (
	"io/ioutil"
	"os"
)

func ListItems(root string, relPath string) ([]string, []string, error) {
	var dirs []os.FileInfo
	files, err := ioutil.ReadDir(root)
	if err != nil {
		return nil, nil, err
	}

	fileList := []string{}
	dirList := []string{}

	for _, f := range files {
		if f.IsDir() {
			dirList = append(dirList, relPath+f.Name())
			dirs = append(dirs, f)
			continue
		}

		// Is file
		fileList = append(fileList, relPath+f.Name())
	}

	// Walk directories
	for _, d := range dirs {
		recursiveFileList, recursiveDirList, err := ListItems(root+d.Name()+string(os.PathSeparator), relPath+d.Name()+string(os.PathSeparator))
		if err != nil {
			return nil, nil, err
		}

		fileList = append(fileList, recursiveFileList...)
		dirList = append(dirList, recursiveDirList...)
	}

	return fileList, dirList, nil
}
