//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

/*
	base64 encodeing is a 64 bit alphabet for asci encoding.
	base64utl has a slightly  differnt map:

	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	So "+" and "/" imply base64 while "-" and "_" imply base64url

	There are also options around the padding at the end "=" vs none.
*/

var decodeCmd = cli.Command{
	Name:  "decode",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "input,i",
			Usage: "input encoded file",
			Value: "input.base64",
		},
		cli.StringFlag{
			Name:  "output,o",
			Usage: "output binary file",
			Value: "output.bin",
		},
		cli.BoolFlag{
			Name:  "url,u",
			Usage: "use base64url encoding",
		},
		cli.BoolFlag{
			Name:  "clean,c",
			Usage: "remove whitespace of all sorts",
		},
	},
	Action: func(ctx *cli.Context) error {
		inFilename := ctx.String("input")
		outFilename := ctx.String("output")
		urlMode := ctx.Bool("url")
		clean := ctx.Bool("clean")
		inData, err := ioutil.ReadFile(inFilename)
		if clean {
			beforeLen := len(inData)
			var empty []byte
			inData = bytes.Replace(inData, []byte(" "), empty, -1)
			inData = bytes.Replace(inData, []byte("\n"), empty, -1)
			inData = bytes.Replace(inData, []byte("\t"), empty, -1)
			inData = bytes.Replace(inData, []byte("\r"), empty, -1)
			inData = bytes.Replace(inData, []byte{0}, empty, -1)
			afterLen := len(inData)
			if beforeLen != afterLen {
				fmt.Printf("cleaned %d bytes\n", beforeLen-afterLen)
			}
		}
		if err != nil {
			return errors.Wrapf(err, "failed to read input file.")
		}

		var outData []byte

		if urlMode == false {
			outData, err = base64.StdEncoding.DecodeString(string(inData))
		} else {
			outData, err = base64.URLEncoding.DecodeString(string(inData))
		}

		if err != nil {
			return errors.Wrapf(err, "failed to decode.")
		}

		err = ioutil.WriteFile(outFilename, outData, 0644)
		if err != nil {
			return errors.Wrapf(err, "failed to write output file.")
		}
		return nil
	},
}

var encodeCmd = cli.Command{
	Name:  "encode",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "input,i",
			Usage: "input binary file",
			Value: "input.bin",
		},
		cli.StringFlag{
			Name:  "output,o",
			Usage: "output base64 file",
			Value: "output.base64",
		},
		cli.BoolFlag{
			Name:  "url,u",
			Usage: "use base64url encoding",
		},
	},
	Action: func(ctx *cli.Context) error {
		inFilename := ctx.String("input")
		outFilename := ctx.String("output")
		urlMode := ctx.Bool("url")
		inData, err := ioutil.ReadFile(inFilename)
		if err != nil {
			return errors.Wrapf(err, "failed to read input file.")
		}

		var outData string

		if urlMode == false {
			outData = base64.StdEncoding.EncodeToString(inData)
		} else {
			outData = base64.URLEncoding.EncodeToString(inData)
		}

		err = ioutil.WriteFile(outFilename, []byte(outData), 0644)
		if err != nil {
			return errors.Wrapf(err, "failed to write output file.")
		}
		return nil
	},
}

var detectCmd = cli.Command{
	Name:  "detect",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "input,i",
			Usage: "input binary file",
			Value: "input.base64",
		},
	},
	Action: func(ctx *cli.Context) error {
		inFilename := ctx.String("input")
		inData, err := ioutil.ReadFile(inFilename)
		if err != nil {
			return errors.Wrapf(err, "failed to read input file.")
		}

		var isStandard = false
		var isUrl = false

		_, errStd := base64.StdEncoding.DecodeString(string(inData))
		if errStd == nil {
			isStandard = true
		}
		_, errUrl := base64.URLEncoding.DecodeString(string(inData))
		if errUrl == nil {
			isUrl = true
		}

		if isStandard && isUrl {
			fmt.Println("either")
		}

		if !isStandard && isUrl {
			fmt.Println("base64url")
		}

		if isStandard && !isUrl {
			fmt.Println("base64")
		}

		if !isStandard && !isUrl {
			fmt.Printf("neither: Std error '%s' Url error '%s'\n", errStd.Error(), errUrl.Error())
		}

		return nil
	},
}

var stdBytes []byte = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
var urlBytes []byte = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

func isStdByte(b byte) bool {
	for _, stdByte := range stdBytes {
		if b == stdByte {
			return true
		}
	}
	return false
}

func isUrlByte(b byte) bool {
	for _, urlByte := range urlBytes {
		if b == urlByte {
			return true
		}
	}
	return false
}

var scanCmd = cli.Command{
	Name:  "scan",
	Usage: "",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "input,i",
			Usage: "input binary file",
			Value: "input.base64",
		},
		cli.BoolFlag{
			Name:  "all,a",
			Usage: "show all errors",
		},
		cli.BoolFlag{
			Name:  "clean,c",
			Usage: "remove whitespace of all sorts",
		},
	},
	Action: func(ctx *cli.Context) error {

		inFilename := ctx.String("input")
		showAll := ctx.Bool("all")
		clean := ctx.Bool("clean")
		inData, err := ioutil.ReadFile(inFilename)
		if err != nil {
			return errors.Wrapf(err, "failed to read input file.")
		}

		if clean {
			beforeLen := len(inData)
			str := string(inData)
			str = strings.ReplaceAll(str, " ", "")
			str = strings.ReplaceAll(str, "\r", "")
			str = strings.ReplaceAll(str, "\n", "")
			str = strings.ReplaceAll(str, "\t", "")
			str = strings.ReplaceAll(str, "\000", "")
			inData = []byte(str)
			afterLen := len(inData)
			if beforeLen != afterLen {
				fmt.Printf("cleaned %d byte(s)\n", beforeLen-afterLen)
			}
		}

		var counts [256]int
		var lastPosn [256]int
		// I guess I don't really need this.
		for i, _ := range counts {
			counts[i] = 0
			lastPosn[i] = 0
		}

		for i, v := range inData {
			counts[v]++
			lastPosn[v] = i

			if showAll {
				c := string([]byte{v})
				if c == "\n" {
					c = "\\n"
				}
				if !isStdByte(byte(v)) {
					fmt.Printf("found non std char 0x%02x (%s) at %d\n", v, c, i)
				} else {
					if !isUrlByte(byte(v)) {
						fmt.Printf("found non url char 0x%02x (%s) at %d\n", v, c, i)
					}
				}
			}
		}

		for i, v := range counts {
			if v > 0 {
				c := string([]byte{byte(i)})
				if c == "\n" {
					c = "\\n"
				}
				if !isStdByte(byte(i)) {
					fmt.Printf("found non std char 0x%02x (%s) count %d last posn %d\n", i, c, v, lastPosn[i])
				} else {
					if !isUrlByte(byte(i)) {
						fmt.Printf("found non url char 0x%02x (%s) count %d last posn %d\n", i, c, v, lastPosn[i])
					}
				}
			}
		}

		return nil
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "decoder"
	app.Commands = []cli.Command{
		encodeCmd,
		decodeCmd,
		detectCmd,
		scanCmd,
	}

	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
