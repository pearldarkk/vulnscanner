package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"vuln/structs"
	"vuln/winscanner"
)

func writeJSONToFile(jsonString, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(jsonString)
	if err != nil {
		return err
	}

	return nil
}

func convertStructToJSON(data structs.JsonOutPut, indent int) (string, error) {
	indentation := strings.Repeat(" ", indent)
	jsonBytes, err := json.MarshalIndent(data, "", indentation)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func logErrorToFile(filepath string, err error) {
	file, openErr := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if openErr != nil {
		log.Fatal(openErr)
	}
	defer file.Close()

	log.SetOutput(file)

	log.Println(err.Error())
	fmt.Println("[ERROR] ", err.Error())
}

func main() {

	outputDir := flag.String("o", "", "Specify the directory path to save result")
	flag.Parse()

	if *outputDir == "" || (func() bool {
		_, err := os.Stat(*outputDir)
		return os.IsNotExist(err)
	})() {
		*outputDir, _ = os.Getwd()
	}

	debugPath := filepath.Join(*outputDir, "debug.log")

	currentTime := time.Now()
	scanAt := currentTime.Format("2006-01-02T15:04:05.999999-07:00")
	fmt.Println("[INFO] Start to get information:", scanAt)

	fmt.Println("[INFO] Detecting OS of machine...")
	osInfo, err := winscanner.DetectWindows()
	if err != nil {
		logErrorToFile(debugPath, err)
		os.Exit(1)
	}
	fmt.Println("[INFO] Detecting Packages & Patches...")
	// installed, windowsKB, err := winscanner.ScanPackages(osInfo)
	windowsKB, err := winscanner.ScanPackages(osInfo)
	if err != nil {
		logErrorToFile(debugPath, err)
		os.Exit(1)
	}

	var jsonOutPut structs.JsonOutPut
	var container structs.Container
	var platform structs.Platform
	var kernelVersion structs.KernelVersion

	// jsonOutPut.Packages = installed
	jsonOutPut.WindowsKB = windowsKB

	jsonOutPut.JsonVersion = 4
	jsonOutPut.Lang = ""
	jsonOutPut.ServerUUID = ""

	hostname, _ := os.Hostname()
	jsonOutPut.ServerName = hostname
	jsonOutPut.Family = runtime.GOOS

	release, err := winscanner.DetectOSName(osInfo)
	if err != nil {
		logErrorToFile(debugPath, err)
		os.Exit(1)
	}
	jsonOutPut.Release = release

	container.ContainerID = ""
	container.Name = ""
	container.Image = ""
	container.Type = ""
	container.Uuid = ""
	jsonOutPut.Container = container

	platform.Name = "other"
	platform.InstanceID = ""
	jsonOutPut.Platform = platform
	jsonOutPut.ScannedAt = scanAt
	jsonOutPut.ScanMode = "deep mode"
	jsonOutPut.ScannedVersion = ""
	jsonOutPut.ScannedRevision = ""
	jsonOutPut.ScannedBy = hostname
	jsonOutPut.ScannedVia = "local"
	jsonOutPut.ReportedAt = "0001-01-01T00:00:00Z"
	jsonOutPut.ReportedVersion = ""
	jsonOutPut.ReportedRevision = ""
	jsonOutPut.ReportedBy = ""
	jsonOutPut.ScannedVersion = "n0n$la$ v1.0"
	jsonOutPut.ScannedRevision = "n0n$la$ v1.0"
	jsonOutPut.Errors = make([]string, 0)
	jsonOutPut.Warnings = make([]string, 0)
	jsonOutPut.ScannedCves = make(map[string]string)

	kernelVersion.Release = release
	kernelVersion.Version = winscanner.FormatKernelVersion(osInfo)
	kernelVersion.RebootRequired = false
	jsonOutPut.KernelVersion = kernelVersion

	interfaces, err := winscanner.ListNetworkInterfaces()
	if err != nil {
		logErrorToFile(debugPath, err)
		os.Exit(1)
	}
	for _, itface := range interfaces {
		if len(itface.DefaultGateway) > 0 {
			jsonOutPut.Ipv4Addrs = append(jsonOutPut.Ipv4Addrs, itface.Ipv4Address...)
			jsonOutPut.ScannedIpv4Addrs = jsonOutPut.Ipv4Addrs
			jsonOutPut.Ipv6Addrs = itface.Ipv6Address
		}
	}

	jsonString, err := convertStructToJSON(jsonOutPut, 4)
	if err != nil {
		logErrorToFile(debugPath, err)
		os.Exit(1)
	}
	err = os.MkdirAll(filepath.Join("C:\\ProgramData\\viettel_rsmd", "vuln_output"), 0755)
	if err != nil {
		logErrorToFile(debugPath, err)
		os.Exit(1)
	}

	jsonName := filepath.Join("C:\\ProgramData\\viettel_rsmd", "vuln_output", hostname+"_vuln.json")
	err = writeJSONToFile(jsonString, jsonName)
	if err != nil {
		logErrorToFile(debugPath, err)
		os.Exit(1)
	}
	fmt.Println("[INFO] Complete the information gathering process. Results are saved at", jsonName)

	return
}
