// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/pkg/errors"
)

const (
	BYTES_PER_KB        = 1024
	BYTES_PER_32KB      = int64(32 * BYTES_PER_KB)
	BYTES_PER_64KB      = int64(64 * BYTES_PER_KB)
	BYTES_PER_128KB     = int64(128 * BYTES_PER_KB)
	BYTES_PER_512KB     = int64(512 * BYTES_PER_KB)
	BLOCK_SIZE          = BYTES_PER_KB * BYTES_PER_KB // 1024^2
	BASE_OFFSET         = 0
	BLOCK2_OFFSET       = 2 * BLOCK_SIZE
	BLOCK3_OFFSET       = 3 * BLOCK_SIZE
	BLOCK5_OFFSET       = 5 * BLOCK_SIZE
	BLOCK12_OFFSET      = 12 * BLOCK_SIZE
	REFERENCE_FILE_SIZE = 256*BLOCK_SIZE - 1024 // 256*1024^2 - 1024
)

// The reference file format is a file full of zeroes with 32-bit offset stamps
// every kilobyte. For example:
//
// Address    || Offset stamp      || Padding
// -----------++-------------------++--------------
// 0x00000000 || 00 | 00 | 00 | 00 || 00 | 00 | ...
// 0x00012400 || 00 | 01 | 24 | 00 || 00 | 00 | ...
// 0x34567800 || 34 | 56 | 78 | 00 || 00 | 00 | ...

func GenerateReferenceSlice(offset int64, size int64) []byte {
	if size == 0 {
		return []byte{}
	}

	// If going over the end of the file, return less bytes than requested
	if offset+size > fm.contentLength {
		size = fm.contentLength - offset
	}

	data := make([]byte, size)
	for i := int64(0); i < size; i++ {
		realOffset := offset + i
		if (realOffset % BYTES_PER_KB) == 0 {
			data[i] = byte(realOffset >> 24)
		} else if (realOffset % BYTES_PER_KB) == 1 {
			data[i] = byte((realOffset - 1) >> 16)
		} else if (realOffset % BYTES_PER_KB) == 2 {
			data[i] = byte((realOffset - 2) >> 8)
		} else if (realOffset % BYTES_PER_KB) == 3 {
			data[i] = byte(realOffset - 3)
		} else {
			data[i] = 0
		}
	}
	return data
}

func GenerateReferenceFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "failed to create file")
	}
	defer file.Close()

	var offset int64 = 0
	for {
		// generate 4 bytes (32 bits) of data
		data := []byte{byte(offset >> 24), byte(offset >> 16), byte(offset >> 8), byte(offset)}

		// move file location to offset
		_, err = file.Seek(offset, io.SeekStart)
		if err != nil {
			return errors.Wrapf(err, "failed to seek in file")
		}

		// every 1KB write 4 bytes of data (will have zeros to fill in the rest of the KB)
		_, err = file.Write(data)
		if err != nil {
			return errors.Wrapf(err, "failed to write in file")
		}
		// increment offset by 1KB
		offset = offset + BYTES_PER_KB

		if offset == REFERENCE_FILE_SIZE {
			break
		}
	}

	file.Truncate(REFERENCE_FILE_SIZE)

	return nil
}

// Test reading different ranges of bytes from the file. None of them should
// cross a block boundary.
func Test_GetBytes_Supported(t *testing.T) {
	ClearCache()

	VerifyReadRange := func(t *testing.T, offset int64, size int64) {
		err, data := GetBytes(offset, offset+size)
		if err != nil {
			t.Errorf("GetBytes(%d, %d) failed: %s", offset, offset+size, err.Error())
			return
		}
		referenceData := GenerateReferenceSlice(offset, size)

		res := bytes.Compare(data, referenceData)
		if res != 0 {
			t.Errorf("GetBytes(%d, %d): comparison failed", offset, offset+size)
		}
	}

	// Block 0
	VerifyReadRange(t, BASE_OFFSET+BYTES_PER_32KB, 4)
	VerifyReadRange(t, BASE_OFFSET+BYTES_PER_128KB, 2500)

	// Block 1
	VerifyReadRange(t, BLOCK_SIZE+BYTES_PER_64KB, 1000)
	VerifyReadRange(t, BLOCK_SIZE+BYTES_PER_512KB, 1024)

	// Block 5
	VerifyReadRange(t, BLOCK5_OFFSET+BYTES_PER_64KB, 1000)
	VerifyReadRange(t, BLOCK5_OFFSET+BYTES_PER_512KB, 10000)

	// Block 12
	VerifyReadRange(t, BLOCK12_OFFSET+BYTES_PER_64KB, 1000)
	VerifyReadRange(t, BLOCK12_OFFSET+BYTES_PER_512KB, 10000)

	// Get bytes from start of the file
	VerifyReadRange(t, BASE_OFFSET, 100)
	VerifyReadRange(t, BASE_OFFSET, 10000)

	// Get bytes from end of the file
	endOffset := int64(REFERENCE_FILE_SIZE - 100)
	VerifyReadRange(t, endOffset, 90)
	VerifyReadRange(t, endOffset, 99)
	VerifyReadRange(t, endOffset, 100)

	// Try to get more bytes than available (the resulting slice should be
	// smaller than the requested size)
	VerifyReadRange(t, endOffset, 101)
	VerifyReadRange(t, endOffset, 200)
}

// Test that this function fails when trying to get data in ranges that cross a
// block boundary
func Test_GetBytes_Unsupported(t *testing.T) {
	ClearCache()

	GetBytesShouldFail := func(t *testing.T, from int64, to int64) {
		err, _ := GetBytes(from, to)
		if err == nil {
			t.Errorf("GetBytes(%d, %d) should have failed", from, to)
		}
	}

	GetBytesShouldSucceed := func(t *testing.T, from int64, to int64) {
		err, _ := GetBytes(from, to)
		if err != nil {
			t.Errorf("GetBytes(%d, %d) should have succeeded", from, to)
		}
	}

	// Test negative values
	GetBytesShouldFail(t, -1, 100)
	GetBytesShouldFail(t, 100, -1)

	// Test end of slice before start
	GetBytesShouldFail(t, 100, 50)

	// Test offset values around a block boundary to test for off-by-one
	// errors in the checks.
	GetBytesShouldSucceed(t, BLOCK_SIZE, BLOCK2_OFFSET-1)
	GetBytesShouldSucceed(t, BLOCK_SIZE, BLOCK2_OFFSET)
	GetBytesShouldFail(t, BLOCK_SIZE, BLOCK2_OFFSET+1)
	GetBytesShouldFail(t, BLOCK_SIZE-1, BLOCK2_OFFSET)
	GetBytesShouldSucceed(t, BLOCK_SIZE, BLOCK2_OFFSET)
	GetBytesShouldSucceed(t, BLOCK_SIZE+1, BLOCK2_OFFSET)

	// Test bigger sizes than allowed
	GetBytesShouldFail(t, BLOCK_SIZE, BLOCK3_OFFSET)
	GetBytesShouldFail(t, BLOCK_SIZE, BLOCK2_OFFSET+1)
}

// Test getting blocks outside of bounds, and the ones right at the limits.
func Test_GetBlock_TestBounds(t *testing.T) {
	ClearCache()

	err, _ := GetBlock(-1)
	if err.Error() != "invalid block index (-1)" {
		t.Errorf("GetBlock(-1) should have failed")
	}
	err, _ = GetBlock(0)
	if err != nil {
		t.Errorf("GetBlock(0) should have succeeded: %s", err.Error())
	}
	err, _ = GetBlock(255)
	if err != nil {
		t.Errorf("GetBlock(255) should have succeeded: %s", err.Error())
	}
	err, _ = GetBlock(256)
	if err.Error() != "block index over limit (256 > 255)" {
		t.Errorf("GetBlock(-1) should have failed")
	}
}

// The tests only test the filemanager cache code. In order for them to run
// faster, the local file reader is setup, not the Azure downloader. The
// TestMain funcion needs to generate a reference file so that the tests can
// run.
func DoAllTests(m *testing.M, readOnly bool) {
	if err := InitializeCache(BLOCK_SIZE, 32, readOnly); err != nil {
		fmt.Printf("Failed to initialize cache: %s\n", err.Error())
		//return 1
	}

	// Create temporary folder
	tempDir, err := ioutil.TempDir("", "aztemp")
	if err != nil {
		fmt.Printf("Failed to create temp dir: %s\n", err.Error())
		//return 1
	}
	defer os.RemoveAll(tempDir) // Remove folder at exit
	fmt.Printf("Temporary directory: %s\n", tempDir)

	// Generate the reference file inside the temporary folder so that it is
	// deleted along the temporary folder at exit

	referenceFile := path.Join(tempDir, "reference_file")

	if err := GenerateReferenceFile(referenceFile); err != nil {
		fmt.Printf("Failed to create reference file: %s\n", err.Error())
		//return 1
	}

	if err = LocalSetup(referenceFile); err != nil {
		fmt.Printf("Local filesystem setup error: %s\n", err.Error())
		//return 1
	}

	m.Run()

	//return m.Run()
}

func TestMain(m *testing.M) {
	// All the tests are in DoAllTests() so that all deferred functions are
	// called when returning from there. They aren't called when the program
	// ends because of a call to os.Exit().
	DoAllTests(m, true)
	DoAllTests(m, false)
	//os.Exit(DoAllTests(m, true))
}
