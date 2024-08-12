package structs

type WindowsRelease struct {
	Revision string
	Kb       string
}

type UpdateProgram struct {
	Rollup       []WindowsRelease
	SecurityOnly []string
}

type BuildNumber struct {
	Build string
	Name  string
}

type ResultCmd struct {
	Stdout     string
	Stderr     string
	ExitStatus int
}

type Interfaces struct {
	Name           string
	Ipv4Address    []string
	Ipv6Address    []string
	DefaultGateway string
}

type OsInfo struct {
	ProductName      string
	Version          string
	Build            string
	Revision         string
	Edition          string
	ServicePack      string
	Arch             string
	InstallationType string
}

type Platform struct {
	Name       string `json:"name"`
	InstanceID string `json:"instanceID"`
}
type WindowsKB struct {
	Applied   []string `json:"applied,omitempty"`
	Unapplied []string `json:"unapplied,omitempty"`
}

type KernelVersion struct {
	Release        string `json:"release"`
	Version        string `json:"version"`
	RebootRequired bool   `json:"rebootRequired"`
}

type Container struct {
	ContainerID string `json:"containerID"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	Type        string `json:"type"`
	Uuid        string `json:"uuid"`
}

type Package struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Release    string `json:"release"`
	NewVersion string `json:"newVersion"`
	NewRelease string `json:"newRelease"`
	Arch       string `json:"arch"`
	Repository string `json:"repository"`
}

type JsonOutPut struct {
	JsonVersion      int                `json:"jsonVersion"`
	Lang             string             `json:"lang"`
	ServerUUID       string             `json:"serverUUID"`
	ServerName       string             `json:"serverName"`
	Family           string             `json:"family"`
	Release          string             `json:"release"`
	Container        Container          `json:"container"`
	Platform         Platform           `json:"platform"`
	Ipv4Addrs        []string           `json:"ipv4Addrs"`
	Ipv6Addrs        []string           `json:"ipv6Addrs"`
	ScannedAt        string             `json:"scannedAt"`
	ScanMode         string             `json:"scanMode"`
	ScannedVersion   string             `json:"scannedVersion"`
	ScannedRevision  string             `json:"scannedRevision"`
	ScannedBy        string             `json:"scannedBy"`
	ScannedVia       string             `json:"scannedVia"`
	ScannedIpv4Addrs []string           `json:"scannedIpv4Addrs"`
	ReportedAt       string             `json:"reportedAt"`
	ReportedVersion  string             `json:"reportedVersion"`
	ReportedRevision string             `json:"reportedRevision"`
	ReportedBy       string             `json:"reportedBy"`
	Errors           []string           `json:"errors"`
	Warnings         []string           `json:"warnings"`
	ScannedCves      map[string]string  `json:"scannedCves"`
	KernelVersion    KernelVersion      `json:"runningKernel"`
	Packages         map[string]Package `json:"packages"`
	WindowsKB        WindowsKB          `json:"windowsKB"`
}
