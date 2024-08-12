package excute

import (
	"bytes"
	"io"
	ex "os/exec"
	"strings"
	"syscall"
	"vuln/structs"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func toUTF8(s string) string {
	d := chardet.NewTextDetector()
	res, err := d.DetectBest([]byte(s))
	if err != nil {
		return s
	}

	var bs []byte
	switch res.Charset {
	case "UTF-8":
		bs, err = []byte(s), nil
	case "UTF-16LE":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()))
	case "UTF-16BE":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), unicode.UTF16(unicode.BigEndian, unicode.UseBOM).NewDecoder()))
	case "Shift_JIS":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), japanese.ShiftJIS.NewDecoder()))
	case "EUC-JP":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), japanese.EUCJP.NewDecoder()))
	case "ISO-2022-JP":
		bs, err = io.ReadAll(transform.NewReader(strings.NewReader(s), japanese.ISO2022JP.NewDecoder()))
	default:
		bs, err = []byte(s), nil
	}
	if err != nil {
		return s
	}
	return string(bs)
}

func LocalExec(cmdstr string) structs.ResultCmd {
	var results structs.ResultCmd
	cmd := ex.Command("powershell.exe", "-NoProfile", "-NonInteractive", cmdstr)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*ex.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			results.ExitStatus = waitStatus.ExitStatus()
		} else {
			results.ExitStatus = 999
		}
	} else {
		results.ExitStatus = 0
	}
	results.Stdout = toUTF8(stdoutBuf.String())
	results.Stderr = toUTF8(stderrBuf.String())

	return results
}
