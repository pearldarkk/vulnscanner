package winscanner

import (
	"bufio"
	"fmt"
	"strings"
	"vuln/excute"
	"vuln/structs"

	"golang.org/x/xerrors"
)

func DetectWindows() (structs.OsInfo, error) {

	var osInfo structs.OsInfo
	if r, r2 := excute.LocalExec(`$CurrentVersion = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion"); Format-List -InputObject $CurrentVersion -Property ProductName, CurrentVersion, CurrentMajorVersionNumber, CurrentMinorVersionNumber, CurrentBuildNumber, UBR, CSDVersion, EditionID, InstallationType`), excute.LocalExec(`(Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment").PROCESSOR_ARCHITECTURE`); (r.ExitStatus == 0 && r.Stdout != "") && (r2.ExitStatus == 0 && r2.Stdout != "") {

		osInfo, err := parseRegistry(r.Stdout, strings.TrimSpace(r2.Stdout))
		if err != nil {
			fmt.Println([]error{xerrors.Errorf("Failed to parse Registry. err: %s", err.Error())})
			return osInfo, err
		}
		return osInfo, nil
	}

	return osInfo, nil
}

func parseRegistry(stdout, arch string) (structs.OsInfo, error) {
	var (
		o     structs.OsInfo
		major string
		minor string
	)

	winscanner := bufio.NewScanner(strings.NewReader(stdout))
	for winscanner.Scan() {
		line := winscanner.Text()

		switch {
		case strings.HasPrefix(line, "ProductName"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect ProductName. expected: "ProductName : <ProductName>", line: "%s"`, line)
			}
			o.ProductName = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect CurrentVersion. expected: "CurrentVersion : <Version>", line: "%s"`, line)
			}
			o.Version = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentMajorVersionNumber"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect CurrentMajorVersionNumber. expected: "CurrentMajorVersionNumber : <Version>", line: "%s"`, line)
			}
			major = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentMinorVersionNumber"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect CurrentMinorVersionNumber. expected: "CurrentMinorVersionNumber : <Version>", line: "%s"`, line)
			}
			minor = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CurrentBuildNumber"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect CurrentBuildNumber. expected: "CurrentBuildNumber : <Build>", line: "%s"`, line)
			}
			o.Build = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "UBR"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect UBR. expected: "UBR : <Revision>", line: "%s"`, line)
			}
			o.Revision = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "EditionID"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect EditionID. expected: "EditionID : <EditionID>", line: "%s"`, line)
			}
			o.Edition = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CSDVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect CSDVersion. expected: "CSDVersion : <CSDVersion>", line: "%s"`, line)
			}
			o.ServicePack = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "InstallationType"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return structs.OsInfo{}, xerrors.Errorf(`Failed to detect InstallationType. expected: "InstallationType : <InstallationType>", line: "%s"`, line)
			}
			o.InstallationType = strings.TrimSpace(rhs)
		default:
		}
	}
	if major != "" && minor != "" {
		o.Version = fmt.Sprintf("%s.%s", major, minor)
	}

	formatted, err := formatArch(arch)
	if err != nil {
		return structs.OsInfo{}, xerrors.Errorf("Failed to format arch. arch: %s, err: %w", arch, err)
	}
	o.Arch = formatted

	return o, nil
}

func formatArch(arch string) (string, error) {
	switch arch {
	case "AMD64", "x64-based":
		return "x64-based", nil
	case "ARM64", "ARM64-based":
		return "ARM64-based", nil
	case "IA64", "Itanium-based":
		return "Itanium-based", nil
	case "x86", "X86-based":
		return "32-bit", nil
	default:
		return "", xerrors.New("CPU Architecture not found")
	}
}
