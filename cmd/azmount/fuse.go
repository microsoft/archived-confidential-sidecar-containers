// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"context"
	"os"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/Microsoft/confidential-sidecar-containers/cmd/azmount/filemanager"
	"github.com/pkg/errors"
)

// For more information about the library used to set up the FUSE filesystem:
//
//     https://github.com/bazil/fuse

func FuseSetup(mountpoint string, readOnly bool) error {

	var c *fuse.Conn
	var err error
	if readOnly {
		c, err = fuse.Mount(
			mountpoint,
			fuse.FSName("azure_filesystem"),
			fuse.Subtype("azurefs"),
			fuse.ReadOnly(),
		)
	} else {
		c, err = fuse.Mount(
			mountpoint,
			fuse.FSName("azure_filesystem"),
			fuse.Subtype("azurefs"),
		)
	}

	if err != nil {
		return errors.Wrapf(err, "can't start fuse")
	}
	defer c.Close()

	// The execution flow stops here. This function is never left until there is
	// a crash or the filesystem is unmounted by the user.
	err = fs.Serve(c, FS{readOnly: readOnly})
	if err != nil {
		return errors.Wrapf(err, "can't serve fuse")
	}
	return nil
}

// FS implements the file system.
type FS struct {
	readOnly bool
}

func (fs FS) Root() (fs.Node, error) {
	return Dir{readOnly: fs.readOnly}, nil
}

// Dir implements both Node and Handle for the root directory.
type Dir struct {
	readOnly bool
}

func (Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = os.ModeDir | 0o777
	return nil
}

func (d Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	if name == "data" {
		return File{readOnly: d.readOnly}, nil
	}
	return nil, syscall.ENOENT
}

var dirDirs = []fuse.Dirent{
	{Inode: 2, Name: "data", Type: fuse.DT_File},
}

func (Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	return dirDirs, nil
}

// File implements both Node and Handle for the file.
type File struct {
	readOnly bool
}

func (f File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 2
	if f.readOnly {
		a.Mode = 0o444
	} else {
		a.Mode = 0o777
	}
	a.Size = uint64(filemanager.GetFileSize())
	return nil
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (f File) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	if req.Offset < 0 {
		// Before beginning of file.
		return fuse.Errno(syscall.EINVAL)
	}
	if req.Size == 0 {
		// No bytes requested.
		return nil
	}
	offset := uint64(req.Offset)
	fileSize := uint64(filemanager.GetFileSize())

	if offset >= fileSize {
		// Beyond end of file.
		return nil
	}

	to := min(fileSize, offset+uint64(req.Size))
	if offset == to {
		return nil
	}

	err, data := filemanager.GetBytes(int64(offset), int64(to))
	resp.Data = data
	return err
}

func (f *File) ReadAll(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (f File) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	if req.Offset < 0 {
		// Before beginning of file.
		return fuse.Errno(syscall.EINVAL)
	}

	offset := uint64(req.Offset)
	fileSize := uint64(filemanager.GetFileSize())

	if offset >= fileSize {
		// Beyond end of file.
		return nil
	}

	to := min(fileSize, offset+uint64(len(req.Data)))
	if to == offset {
		return nil
	}

	err := filemanager.SetBytes(int64(offset), req.Data)
	if err == nil {
		resp.Size = len(req.Data)
	}
	return err
}

func (f File) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
	filemanager.ClearCache()
	return nil
}
