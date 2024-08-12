package winscanner

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"vuln/constant"
	"vuln/excute"
	"vuln/structs"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
)

// func ScanPackages(osInfo structs.OsInfo) (map[string]structs.Package, structs.WindowsKB, error) {
func ScanPackages(osInfo structs.OsInfo) (structs.WindowsKB, error) {
	// installed := make(map[string]structs.Package)
	var windowsKB structs.WindowsKB

	// r := excute.LocalExec("$Packages = (Get-Package); Format-List -InputObject $Packages -Property Name, Version, ProviderName")
	// if r.ExitStatus == 0 && r.Stdout != "" {
	// 	var err error
	// 	installed, err = parseInstalledPackages(r.Stdout)
	// 	if err != nil {
	// 		return installed, windowsKB, err
	// 	}
	// }

	windowsKB, err := scanKBs(osInfo)
	if err != nil {
		// return installed, windowsKB, nil
		return windowsKB, nil
	}

	return windowsKB, nil
}

func parseInstalledPackages(stdout string) (map[string]structs.Package, error) {
	var name, version string
	installed := make(map[string]structs.Package)

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			name, version = "", ""
		case strings.HasPrefix(line, "Name"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return installed, xerrors.Errorf(`Failed to detect PackageName. expected: "Name : <PackageName>", line: "%s"`, line)
			}
			name = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "Version"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return installed, xerrors.Errorf(`Failed to detect Version. expected: "Version : <Version>", line: "%s"`, line)
			}
			version = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "ProviderName"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return installed, xerrors.Errorf(`Failed to detect ProviderName. expected: "ProviderName : <ProviderName>", line: "%s"`, line)
			}

			switch strings.TrimSpace(rhs) {
			case "msu":
			default:
				if name != "" {
					installed[name] = structs.Package{Name: name, Version: version}
				}
			}
		default:
		}
	}
	return installed, nil
}

func scanKBs(osInfo structs.OsInfo) (structs.WindowsKB, error) {

	applied, unapplied := map[string]struct{}{}, map[string]struct{}{}
	if r := excute.LocalExec("$Hotfix = (Get-Hotfix); Format-List -InputObject $Hotfix -Property HotFixID"); r.ExitStatus == 0 && r.Stdout != "" {
		kbs, err := parseGetHotfix(r.Stdout)
		if err != nil {
			return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to parse Get-Hotifx. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	if r := excute.LocalExec("$Packages = (Get-Package -ProviderName msu); Format-List -InputObject $Packages -Property Name"); r.ExitStatus == 0 && r.Stdout != "" {
		kbs, err := parseGetPackageMSU(r.Stdout)
		if err != nil {
			return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to parse Get-Package. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	var searcher string
	c, _ := getServerSelection()
	searcher = fmt.Sprintf("$UpdateSession = (New-Object -ComObject Microsoft.Update.Session); $UpdateSearcher = $UpdateSession.CreateUpdateSearcher(); $UpdateSearcher.ServerSelection = %d;", c)
	if r := excute.LocalExec(fmt.Sprintf(`%s $UpdateSearcher.search("IsInstalled = 1 and RebootRequired = 0 and Type='Software'").Updates | ForEach-Object -MemberName KBArticleIDs`, searcher)); r.ExitStatus == 0 && r.Stdout != "" {
		kbs, err := parseWindowsUpdaterSearch(r.Stdout)
		if err != nil {
			return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	if r := excute.LocalExec(fmt.Sprintf(`%s $UpdateSearcher.search("IsInstalled = 0 and Type='Software'").Updates | ForEach-Object -MemberName KBArticleIDs`, searcher)); r.ExitStatus == 0 && r.Stdout != "" {
		kbs, err := parseWindowsUpdaterSearch(r.Stdout)
		if err != nil {
			return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
		}
		for _, kb := range kbs {
			unapplied[kb] = struct{}{}
		}
	}

	if r := excute.LocalExec(fmt.Sprintf(`%s $UpdateSearcher.search("IsInstalled = 1 and RebootRequired = 1 and Type='Software'").Updates | ForEach-Object -MemberName KBArticleIDs`, searcher)); r.ExitStatus == 0 && r.Stdout != "" {
		kbs, err := parseWindowsUpdaterSearch(r.Stdout)
		if err != nil {
			return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
		}
		for _, kb := range kbs {
			unapplied[kb] = struct{}{}
		}
	}

	if r := excute.LocalExec("$UpdateSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $HistoryCount = $UpdateSearcher.GetTotalHistoryCount(); $UpdateSearcher.QueryHistory(0, $HistoryCount) | Sort-Object -Property Date | Format-List -Property Title, Operation, ResultCode"); r.ExitStatus == 0 && r.Stdout != "" {
		kbs, err := parseWindowsUpdateHistory(r.Stdout)
		if err != nil {
			return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to parse Windows Update History. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	release, err := DetectOSName(osInfo)
	if err != nil {
		return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to detect release from os information. err: %w", err)
	}
	kbs, err := DetectKBsFromKernelVersion(release, FormatKernelVersion(osInfo))
	if err != nil {
		return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, xerrors.Errorf("Failed to detect KBs from kernel version. err: %w", err)
	}
	for _, kb := range kbs.Applied {
		applied[kb] = struct{}{}
	}
	for _, kb := range kbs.Unapplied {
		unapplied[kb] = struct{}{}
	}

	for kb := range applied {
		delete(unapplied, kb)
	}

	return structs.WindowsKB{Applied: maps.Keys(applied), Unapplied: maps.Keys(unapplied)}, nil
}

func FormatKernelVersion(osInfo structs.OsInfo) string {
	v := fmt.Sprintf("%s.%s", osInfo.Version, osInfo.Build)
	if osInfo.Revision != "" {
		v = fmt.Sprintf("%s.%s", v, osInfo.Revision)
	}
	return v
}

func parseGetHotfix(stdout string) ([]string, error) {
	var kbs []string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "HotFixID"):
			_, rhs, found := strings.Cut(line, ":")

			if !found {
				return nil, xerrors.Errorf(`Failed to detect HotFixID. expected: "HotFixID : <KBID>", line: "%s"`, line)
			}
			kbs = append(kbs, strings.TrimPrefix(strings.TrimSpace(rhs), "KB"))
		default:
		}
	}
	return kbs, nil
}

func getServerSelection() (int, error) {
	err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED)
	if err != nil {
		return 0, err
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Microsoft.Update.Session")
	if err != nil {
		return 0, err
	}
	defer unknown.Release()

	updateSession, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return 0, err
	}
	defer updateSession.Release()

	// Get the ServerSelection property
	serverSelectionVariant, err := oleutil.GetProperty(updateSession, "ServerSelection")
	if err != nil {
		return 0, err
	}

	// Convert the variant to an integer
	serverSelection, ok := serverSelectionVariant.Value().(int)
	if !ok {
		return 0, fmt.Errorf("could not convert ServerSelection to int")
	}

	return serverSelection, nil
}

func parseWindowsUpdaterSearch(stdout string) ([]string, error) {
	var kbs []string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			kbs = append(kbs, line)
		}
	}

	return kbs, nil
}

func DetectOSName(osInfo structs.OsInfo) (string, error) {
	osName, err := detectOSNameFromOSInfo(osInfo)
	if err != nil {
		return "", xerrors.Errorf("Failed to detect OS Name from OSInfo: %+v, err: %w", osInfo, err)
	}
	return osName, nil
}

func detectOSNameFromOSInfo(osInfo structs.OsInfo) (string, error) {
	switch osInfo.Version {
	case "5.0":
		switch osInfo.InstallationType {
		case "Client":
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("Microsoft Windows 2000 %s", osInfo.ServicePack), nil
			}
			return "Microsoft Windows 2000", nil
		case "Server", "Domain Controller":
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("Microsoft Windows 2000 Server %s", osInfo.ServicePack), nil
			}
			return "Microsoft Windows 2000 Server", nil
		}
	case "5.1":
		switch osInfo.InstallationType {
		case "Client":
			var n string
			switch osInfo.Edition {
			case "Professional":
				n = "Microsoft Windows XP Professional"
			case "Media Center":
				n = "Microsoft Windows XP Media Center Edition 2005"
			case "Tablet PC":
				n = "Microsoft Windows XP Tablet PC Edition 2005"
			default:
				n = "Microsoft Windows XP"
			}
			switch osInfo.Arch {
			case "x64-based":
				n = fmt.Sprintf("%s x64 Edition", n)
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.ServicePack), nil
			}
			return n, nil
		}
	case "5.2":
		switch osInfo.InstallationType {
		case "Client":
			var n string
			switch osInfo.Edition {
			case "Professional":
				n = "Microsoft Windows XP Professional"
			case "Media Center":
				n = "Microsoft Windows XP Media Center Edition 2005"
			case "Tablet PC":
				n = "Microsoft Windows XP Tablet PC Edition 2005"
			default:
				n = "Microsoft Windows XP"
			}
			switch osInfo.Arch {
			case "x64-based":
				n = fmt.Sprintf("%s x64 Edition", n)
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.ServicePack), nil
			}
			return n, nil
		case "Server", "Domain Controller":
			n := "Microsoft Windows Server 2003"
			if strings.Contains(osInfo.ProductName, "R2") {
				n = "Microsoft Windows Server 2003 R2"
			}
			switch osInfo.Arch {
			case "x64-based":
				n = fmt.Sprintf("%s x64 Edition", n)
			case "Itanium-based":
				if osInfo.Edition == "Enterprise" {
					n = fmt.Sprintf("%s, Enterprise Edition for Itanium-based Systems", n)
				} else {
					n = fmt.Sprintf("%s for Itanium-based Systems", n)
				}
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.ServicePack), nil
			}
			return n, nil
		}
	case "6.0":
		switch osInfo.InstallationType {
		case "Client":
			var n string
			switch osInfo.Arch {
			case "x64-based":
				n = "Windows Vista x64 Editions"
			default:
				n = "Windows Vista"
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.ServicePack), nil
			}
			return n, nil
		case "Server", "Domain Controller":
			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("Windows Server 2008 for %s Systems %s", arch, osInfo.ServicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("Windows Server 2008 for %s Systems %s (Server Core installation)", arch, osInfo.ServicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 for %s Systems (Server Core installation)", arch), nil
		}
	case "6.1":
		switch osInfo.InstallationType {
		case "Client":
			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("Windows 7 for %s Systems %s", arch, osInfo.ServicePack), nil
			}
			return fmt.Sprintf("Windows 7 for %s Systems", arch), nil
		case "Server", "Domain Controller":
			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("Windows Server 2008 R2 for %s Systems %s", arch, osInfo.ServicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 R2 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			if osInfo.ServicePack != "" {
				return fmt.Sprintf("Windows Server 2008 R2 for %s Systems %s (Server Core installation)", arch, osInfo.ServicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 R2 for %s Systems (Server Core installation)", arch), nil
		}
	case "6.2":
		switch osInfo.InstallationType {
		case "Client":
			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Windows 8 for %s Systems", arch), nil
		case "Server", "Domain Controller":
			return "Windows Server 2012", nil
		case "Server Core":
			return "Windows Server 2012 (Server Core installation)", nil
		}
	case "6.3":
		switch osInfo.InstallationType {
		case "Client":
			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Windows 8.1 for %s Systems", arch), nil
		case "Server", "Domain Controller":
			return "Windows Server 2012 R2", nil
		case "Server Core":
			return "Windows Server 2012 R2 (Server Core installation)", nil
		}
	case "10.0":
		switch osInfo.InstallationType {
		case "Client":
			if strings.Contains(osInfo.ProductName, "Windows 11") {
				arch, err := formatArch(osInfo.Arch)
				if err != nil {
					return "", err
				}
				name, err := formatNamebyBuild("11", osInfo.Build)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s for %s Systems", name, arch), nil
			}

			arch, err := formatArch(osInfo.Arch)
			if err != nil {
				return "", err
			}
			name, err := formatNamebyBuild("10", osInfo.Build)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s for %s Systems", name, arch), nil
		case "Server", "Nano Server", "Domain Controller":
			return formatNamebyBuild("Server", osInfo.Build)
		case "Server Core":
			name, err := formatNamebyBuild("Server", osInfo.Build)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s (Server Core installation)", name), nil
		}
	}
	return "", xerrors.New("OS Name not found")
}

func parseGetPackageMSU(stdout string) ([]string, error) {
	var kbs []string

	kbIDPattern := regexp.MustCompile(`KB(\d{6,7})`)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect PackageName. expected: "Name : <PackageName>", line: "%s"`, line)
			}

			for _, m := range kbIDPattern.FindAllStringSubmatch(strings.TrimSpace(rhs), -1) {
				kbs = append(kbs, m[1])
			}
		default:
		}
	}

	return kbs, nil
}

func parseWindowsUpdateHistory(stdout string) ([]string, error) {
	kbs := map[string]struct{}{}

	kbIDPattern := regexp.MustCompile(`KB(\d{6,7})`)
	var title, operation string
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			title, operation = "", ""
		case strings.HasPrefix(line, "Title"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect Title. expected: "Title : <Title>", line: "%s"`, line)
			}
			title = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "Operation"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect Operation. expected: "Operation : <Operation>", line: "%s"`, line)
			}
			operation = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "ResultCode"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect ResultCode. expected: "ResultCode : <ResultCode>", line: "%s"`, line)
			}

			// https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-operationresultcode
			if strings.TrimSpace(rhs) == "2" {
				for _, m := range kbIDPattern.FindAllStringSubmatch(title, -1) {
					// https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-updateoperation
					switch operation {
					case "1":
						kbs[m[1]] = struct{}{}
					case "2":
						delete(kbs, m[1])
					default:
					}
				}
			}
		default:
		}
	}

	return maps.Keys(kbs), nil
}

func DetectKBsFromKernelVersion(release, kernelVersion string) (structs.WindowsKB, error) {

	switch ss := strings.Split(kernelVersion, "."); len(ss) {
	case 3:
		return structs.WindowsKB{}, nil
	case 4:
		switch {
		case strings.HasPrefix(release, "Windows 10 "), strings.HasPrefix(release, "Windows 11 "):
			osver := strings.Split(release, " ")[1]
			verReleases, ok := constant.WindowsReleases["Client"][osver]
			if !ok {
				return structs.WindowsKB{}, nil
			}

			rels, ok := verReleases[ss[2]]
			if !ok {
				return structs.WindowsKB{}, nil
			}

			nMyRevision, err := strconv.Atoi(ss[3])

			if err != nil {
				return structs.WindowsKB{}, xerrors.Errorf("Failed to parse revision number. err: %w", err)
			}

			var index int
			for i, r := range rels.Rollup {
				nRevision, err := strconv.Atoi(r.Revision)
				if err != nil {
					return structs.WindowsKB{}, xerrors.Errorf("Failed to parse revision number. err: %w", err)
				}
				if nMyRevision < nRevision {
					break
				}
				index = i
			}

			var kbs structs.WindowsKB
			for _, r := range rels.Rollup[:index+1] {
				if r.Kb != "" {

					kbs.Applied = append(kbs.Applied, r.Kb)
				}
			}
			for _, r := range rels.Rollup[index+1:] {
				if r.Kb != "" {
					kbs.Unapplied = append(kbs.Unapplied, r.Kb)
				}
			}
			return kbs, nil
		case strings.HasPrefix(release, "Windows Server 2016"), strings.HasPrefix(release, "Windows Server, Version 1709"), strings.HasPrefix(release, "Windows Server, Version 1809"), strings.HasPrefix(release, "Windows Server 2019"), strings.HasPrefix(release, "Windows Server, Version 1903"), strings.HasPrefix(release, "Windows Server, Version 1909"), strings.HasPrefix(release, "Windows Server, Version 2004"), strings.HasPrefix(release, "Windows Server, Version 20H2"), strings.HasPrefix(release, "Windows Server 2022"):
			osver := strings.TrimSpace(strings.NewReplacer("Windows Server", "", ",", "", "(Server Core installation)", "").Replace(release))

			verReleases, ok := constant.WindowsReleases["Server"][osver]
			if !ok {
				return structs.WindowsKB{}, nil
			}

			rels, ok := verReleases[ss[2]]
			if !ok {
				return structs.WindowsKB{}, nil
			}

			nMyRevision, err := strconv.Atoi(ss[3])
			if err != nil {
				return structs.WindowsKB{}, xerrors.Errorf("Failed to parse revision number. err: %w", err)
			}

			var index int
			for i, r := range rels.Rollup {
				nRevision, err := strconv.Atoi(r.Revision)
				if err != nil {
					return structs.WindowsKB{}, xerrors.Errorf("Failed to parse revision number. err: %w", err)
				}
				if nMyRevision < nRevision {
					break
				}
				index = i
			}

			var kbs structs.WindowsKB
			for _, r := range rels.Rollup[:index+1] {
				if r.Kb != "" {
					kbs.Applied = append(kbs.Applied, r.Kb)
				}
			}
			for _, r := range rels.Rollup[index+1:] {
				if r.Kb != "" {
					kbs.Unapplied = append(kbs.Unapplied, r.Kb)
				}
			}
			return kbs, nil
		default:
			return structs.WindowsKB{}, nil
		}
	default:
		return structs.WindowsKB{}, xerrors.Errorf("unexpected kernel version. expected: <major version>.<minor version>.<build>(.<revision>), actual: %s", kernelVersion)
	}

}

func formatNamebyBuild(osType string, mybuild string) (string, error) {
	builds, ok := constant.WinBuilds[osType]
	if !ok {
		return "", xerrors.New("OS Type not found")
	}

	nMybuild, err := strconv.Atoi(mybuild)
	if err != nil {
		return "", xerrors.Errorf("Failed to parse build number. err: %w", err)
	}

	v := builds[0].Name
	for _, b := range builds {
		nBuild, err := strconv.Atoi(b.Build)
		if err != nil {
			return "", xerrors.Errorf("Failed to parse build number. err: %w", err)
		}
		if nMybuild < nBuild {
			break
		}
		v = b.Name
	}
	return v, nil
}
