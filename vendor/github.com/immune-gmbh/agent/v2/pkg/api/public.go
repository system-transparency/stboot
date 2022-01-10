// Keep in sync with agent/pkg/api/types.go
package api

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type FirmwareError string

const (
	NoError        FirmwareError = ""
	UnknownError   FirmwareError = "unkn"
	NoPermission   FirmwareError = "no-perm"
	NoResponse     FirmwareError = "no-resp"
	NotImplemented FirmwareError = "not-impl"
)

// /v2/info (apisrv)
type Info struct {
	APIVersion string `jsonapi:"attr,api_version" json:"api_version"`
}

// /v2/configuration (apisrv)
type KeyTemplate struct {
	Public PublicKey `json:"public"`
	Label  string    `json:"label"`
}

// /v2/configuration (apisrv)
type Configuration struct {
	Root            KeyTemplate            `jsonapi:"attr,root" json:"root"`
	Keys            map[string]KeyTemplate `jsonapi:"attr,keys" json:"keys"`
	PCRBank         uint16                 `jsonapi:"attr,pcr_bank" json:"pcr_bank"`
	PCRs            []int                  `jsonapi:"attr,pcrs" json:"pcrs"`
	UEFIVariables   []UEFIVariable         `jsonapi:"attr,uefi" json:"uefi"`
	MSRs            []MSR                  `jsonapi:"attr,msrs" json:"msrs"`
	CPUIDLeafs      []CPUIDLeaf            `jsonapi:"attr,cpuid" json:"cpuid"`
	TPM2NVRAM       []uint32               `jsonapi:"attr,tpm2_nvram" json:"tpm2_nvram,string"`
	SEV             []SEVCommand           `jsonapi:"attr,sev" json:"sev"`
	ME              []MEClientCommands     `jsonapi:"attr,me" json:"me"`
	TPM2Properties  []TPM2Property         `jsonapi:"attr,tpm2_properties" json:"tpm2_properties"`
	PCIConfigSpaces []PCIConfigSpace       `jsonapi:"attr,pci" json:"pci"`
}

// /v2/attest (apisrv)
type FirmwareProperties struct {
	UEFIVariables   []UEFIVariable     `json:"uefi,omitempty"`
	MSRs            []MSR              `json:"msrs,omitempty"`
	CPUIDLeafs      []CPUIDLeaf        `json:"cpuid,omitempty"`
	SEV             []SEVCommand       `json:"sev,omitempty"`
	ME              []MEClientCommands `json:"me,omitempty"`
	TPM2Properties  []TPM2Property     `json:"tpm2_properties,omitempty"`
	TPM2NVRAM       []TPM2NVIndex      `json:"tpm2_nvram,omitempty"`
	PCIConfigSpaces []PCIConfigSpace   `json:"pci,omitempty"`
	ACPI            ACPITables         `json:"acpi"`
	SMBIOS          ErrorBuffer        `json:"smbios"`
	TXTPublicSpace  ErrorBuffer        `json:"txt"`
	VTdRegisterSet  ErrorBuffer        `json:"vtd"`
	Flash           ErrorBuffer        `json:"flash"`
	TPM2EventLog    ErrorBuffer        `json:"event_log"`
	MACAddresses    MACAddresses       `json:"mac"`
	OS              OS                 `json:"os"`
	Memory          Memory             `json:"memory"`
}

type OS struct {
	Hostname string        `json:"hostname"`
	Release  string        `json:"name"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type SEVCommand struct {
	Command    uint32        `json:"command"` // firmware.SEV*
	ReadLength uint32        `json:"read_length"`
	Response   *Buffer       `json:"response,omitempty"`
	Error      FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MEClientCommands struct {
	GUID     *uuid.UUID    `json:"guid,omitempty"`
	Address  *uint8        `json:"address,omitempty"`
	Commands []MECommand   `json:"commands"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MECommand struct {
	Command  Buffer        `json:"command"`
	Response Buffer        `json:"response,omitempty"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type UEFIVariable struct {
	Vendor string        `json:"vendor"`
	Name   string        `json:"name"`
	Value  *Buffer       `json:"value,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MSR struct {
	MSR    uint32        `json:"msr,string"`
	Values []uint64      `json:"value,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type CPUIDLeaf struct {
	LeafEAX uint32        `json:"leaf_eax,string"`
	LeafECX uint32        `json:"leaf_ecx,string"`
	EAX     *uint32       `json:"eax,string,omitempty"`
	EBX     *uint32       `json:"ebx,string,omitempty"`
	ECX     *uint32       `json:"ecx,string,omitempty"`
	EDX     *uint32       `json:"edx,string,omitempty"`
	Error   FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type TPM2Property struct {
	Property uint32        `json:"property,string"`
	Value    *uint32       `json:"value,omitempty,string"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type TPM2NVIndex struct {
	Index  uint32        `json:"index,string"`
	Public *NVPublic     `json:"public,omitempty"`
	Value  *Buffer       `json:"value,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type Memory struct {
	Values []MemoryRange `json:"values,omitempty"`
	Error  FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MemoryRange struct {
	Start    uint64 `json:"start,string"`
	Bytes    uint64 `json:"bytes,string"`
	Reserved bool   `json:"reserved"`
}

type ACPITables struct {
	Tables map[string]Buffer `json:"tables,omitempty"`
	Error  FirmwareError     `json:"error,omitempty"` // FirmwareErr*
}

type ErrorBuffer struct {
	Data  Buffer        `json:"data,omitempty"`
	Error FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type MACAddresses struct {
	Addresses []string      `json:"addrs"`
	Error     FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

type PCIConfigSpace struct {
	Bus      uint16        `json:"bus,string"`
	Device   uint16        `json:"device,string"`
	Function uint8         `json:"function,string"`
	Value    Buffer        `json:"value,omitempty"`
	Error    FirmwareError `json:"error,omitempty"` // FirmwareErr*
}

// /v2/enroll (apisrv)
type Enrollment struct {
	NameHint               string         `jsonapi:"attr,name_hint" json:"name_hint"`
	EndoresmentKey         PublicKey      `jsonapi:"attr,endoresment_key" json:"endoresment_key"`
	EndoresmentCertificate *Certificate   `jsonapi:"attr,endoresment_certificate" json:"endoresment_certificate"`
	Root                   PublicKey      `jsonapi:"attr,root" json:"root"`
	Keys                   map[string]Key `jsonapi:"attr,keys" json:"keys"`
	Cookie                 string         `jsonapi:"attr,cookie" json:"cookie"`
}

// /v2/enroll (apisrv)
type Key struct {
	Public                 PublicKey `json:"public"`
	CreationProof          Attest    `json:"certify_info"`
	CreationProofSignature Signature `json:"certify_signature"`
}

const EvidenceType = "evidence/1"

// /v2/attest (apisrv)
type Evidence struct {
	Type      string             `jsonapi:"attr,type" json:"type"`
	Quote     Attest             `jsonapi:"attr,quote" json:"quote"`
	Signature Signature          `jsonapi:"attr,signature" json:"signature"`
	Algorithm string             `jsonapi:"attr,algorithm" json:"algorithm"`
	PCRs      map[string]Buffer  `jsonapi:"attr,pcrs" json:"pcrs"`
	Firmware  FirmwareProperties `jsonapi:"attr,firmware" json:"firmware"`
	Cookie    string             `jsonapi:"attr,cookie" json:"cookie"`
}

// /v2/enroll (apisrv)
type EncryptedCredential struct {
	Name       string `jsonapi:"attr,name" json:"name"`
	KeyID      Buffer `jsonapi:"attr,key_id" json:"key_id"`
	Credential Buffer `jsonapi:"attr,credential" json:"credential"` // encrypted JWT
	Secret     Buffer `jsonapi:"attr,secret" json:"secret"`
	Nonce      Buffer `jsonapi:"attr,nonce" json:"nonce"`
}

// /v2/devices (apisrv)
type Appraisal struct {
	Id        string    `jsonapi:"primary,appraisals" json:"id"`
	Received  time.Time `jsonapi:"attr,received,rfc3339" json:"received"`
	Appraised time.Time `jsonapi:"attr,appraised,rfc3339" json:"appraised"`
	Expires   time.Time `jsonapi:"attr,expires,rfc3339" json:"expires"`
	Verdict   Verdict   `jsonapi:"attr,verdict" json:"verdict"`
	Report    Report    `jsonapi:"attr,report" json:"report"`
	Policy    *Policy   `jsonapi:"relation,policy" json:"policy"`
}

const VerdictType = "verdict/1"

// /v2/devices (apisrv)
type Verdict struct {
	Type          string `json:"type"`
	Result        bool   `json:"result"`
	Bootchain     bool   `json:"bootchain"`
	Firmware      bool   `json:"firmware"`
	Configuration bool   `json:"configuration"`
}

const ReportType = "report/2"
const ReportTypeV1 = "report/1"

// /v2/devices (apisrv)
type ReportV1 struct {
	Type        string       `json:"type"`
	Host        Host         `json:"host"`
	SMBIOS      *SMBIOS      `json:"smbios,omitempty"`
	UEFI        *UEFI        `json:"uefi,omitempty"`
	TPM         *TPM         `json:"tpm,omitempty"`
	ME          *ME          `json:"me,omitempty"`
	SGX         *SGX         `json:"sgx,omitempty"`
	TXT         *TXT         `json:"txt,omitempty"`
	SEV         *SEV         `json:"sev,omitempty"`
	Annotations []Annotation `json:"annotations"`
}

// /v2/devices (apisrv)
type Report struct {
	Type        string       `json:"type"`
	Values      ReportValues `json:"values"`
	Annotations []Annotation `json:"annotations"`
}

type ReportValues struct {
	Host   Host    `json:"host"`
	SMBIOS *SMBIOS `json:"smbios,omitempty"`
	UEFI   *UEFI   `json:"uefi,omitempty"`
	TPM    *TPM    `json:"tpm,omitempty"`
	ME     *ME     `json:"me,omitempty"`
	SGX    *SGX    `json:"sgx,omitempty"`
	TXT    *TXT    `json:"txt,omitempty"`
	SEV    *SEV    `json:"sev,omitempty"`
}

const (
	OSWindows = "windows"
	OSLinux   = "linux"
	OSUnknown = "unknown"
)

type CPUVendor string

const (
	IntelCPU CPUVendor = "GenuineIntel"
	AMDCPU   CPUVendor = "AuthenticAMD"
)

type Host struct {
	// Windows: <ProductName> <CurrentMajorVersionNumber>.<CurrentMinorVersionNumber> Build <CurrentBuild>
	// Linux: /etc/os-release PRETTY_NAME or lsb_release -d
	OSName    string    `json:"name"`
	Hostname  string    `json:"hostname"`
	OSType    string    `json:"type"` // OS*
	CPUVendor CPUVendor `json:"cpu_vendor"`
}

type SMBIOS struct {
	Manufacturer    string `json:"manufacturer"`
	Product         string `json:"product"`
	BIOSReleaseDate string `json:"bios_release_date"`
	BIOSVendor      string `json:"bios_vendor"`
	BIOSVersion     string `json:"bios_version"`
}

const (
	EFICertificate = "certificate"
	EFIFingerprint = "fingerprint"
)

type EFISignature struct {
	Type        string     `json:"type"`              // EFIFingerprint or EFICertificate
	Subject     *string    `json:"subject,omitempty"` // certificate only
	Issuer      *string    `json:"issuer,omitempty"`  // certificate only
	Fingerprint string     `json:"fingerprint"`
	NotBefore   *time.Time `json:"not_before,omitempty,rfc3339"` // certificate only
	NotAfter    *time.Time `json:"not_after,omitempty,rfc3339"`  // certificate only
	Algorithm   *string    `json:"algorithm,omitempty"`          // certificate only
}

const (
	ModeSetup    = "setup"
	ModeAudit    = "audit"
	ModeUser     = "user"
	ModeDeployed = "deployed"
)

type UEFI struct {
	Mode          string          `json:"mode"` // Mode*
	SecureBoot    bool            `json:"secureboot"`
	PlatformKeys  *[]EFISignature `json:"platform_keys"`
	ExchangeKeys  *[]EFISignature `json:"exchange_keys"`
	PermittedKeys *[]EFISignature `json:"permitted_keys"`
	ForbiddenKeys *[]EFISignature `json:"forbidden_keys"`
}

type TPM struct {
	Manufacturer string            `json:"manufacturer"`
	VendorID     string            `json:"vendor_id"`
	SpecVersion  string            `json:"spec_version"`
	EventLog     []TPMEvent        `json:"eventlog"`
	PCR          map[string]string `json:"pcr"`
}

const (
	ICU        = "ICU"
	TXE        = "TXE"
	ConsumerME = "Consumer CSME"
	BusinessME = "Business CSME"
	LightME    = "Light ME"
	SPS        = "SPS"
	UnknownME  = "Unrecognized"
)

type ME struct {
	Features        []string `json:"features"`
	Variant         string   `json:"variant"` // constants above
	Version         []uint16 `json:"version"`
	RecoveryVersion []uint16 `json:"recovery_version"`
	FITCVersion     []uint16 `json:"fitc_version"`
	API             []uint   `json:"api_version,string"`
	MEUpdate        string   `json:"updatable"`
	ChipsetVersion  uint     `json:"chipset_version,string"`
	ChipID          uint     `json:"chip_id,string"`
	Manufacturer    string   `json:"manufacturer,omitempty"`
	Size            uint     `json:"size,string"`
	Signature       string   `json:"signature"`
}

type SGX struct {
	Version          uint               `json:"version"`
	Enabled          bool               `json:"enabled"`
	FLC              bool               `json:"flc"`
	KSS              bool               `json:"kss"`
	MaxEnclaveSize32 uint               `json:"enclave_size_32"`
	MaxEnclaveSize64 uint               `json:"enclave_size_64"`
	EPC              []EnclavePageCache `json:"epc"`
}

type TXT struct {
	Ready bool `json:"ready"`
}

type SEV struct {
	Enabled bool   `json:"enabled"`
	Version []uint `json:"version"`
	SME     bool   `json:"sme"`
	ES      bool   `json:"es"`
	VTE     bool   `json:"vte"`
	SNP     bool   `json:"snp"`
	VMPL    bool   `json:"vmpl"`
	Guests  uint   `json:"guests"`
	MinASID uint   `json:"min_asid"`
}

// /v2/devices (apisrv)
type TPMEvent struct {
	PCR       uint   `json:"pcr"`
	Value     string `json:"value"`
	Algorithm uint   `json:"algorithm"`
	Note      string `json:"note"`
}

// /v2/devices (apisrv)
type EnclavePageCache struct {
	Base          uint64 `json:"base"`
	Size          uint64 `json:"size"`
	CIRProtection bool   `json:"cir_protection"`
}

// /v2/devices (apisrv)
type Annotation struct {
	Id       AnnotationID `json:"id"`
	Expected string       `json:"expected,omitempty"`
	Path     string       `json:"path"`
	Fatal    bool         `json:"fatal"`
}

const (
	BootchainCategory     = "bootchain"
	FirmwareCategory      = "firmware"
	ConfigurationCategory = "configuration"
)

func (a Annotation) Category() string {
	if strings.HasPrefix(a.Path, "/tpm/pcr/") {
		return BootchainCategory
	} else if strings.HasSuffix(string(a.Id), "-disabled") {
		return ConfigurationCategory
	} else {
		return FirmwareCategory
	}
}

type AnnotationID string

const (
	// host
	AnnHostname  = "host-hostname"
	AnnOSType    = "host-type"
	AnnCPUVendor = "host-cpu-ven"

	// smbios
	AnnNoSMBIOS           = "smbios-miss"
	AnnInvalidSMBIOS      = "smbios-inv"
	AnnSMBIOSType0Missing = "smbios-type0-miss"
	AnnSMBIOSType0Dup     = "smbios-type0-dup"
	AnnSMBIOSType1Missing = "smbios-type1-miss"
	AnnSMBIOSType1Dup     = "smbios-type1-dup"

	// uefi
	AnnNoEFI                = "uefi-vars-miss"
	AnnNoSecureBoot         = "uefi-secure-boot"
	AnnNoDeployedSecureBoot = "uefi-deployed-secure-boot"
	AnnMissingEventLog      = "uefi-eventlog-miss"
	AnnModeInvalid          = "uefi-mode-inv"
	AnnPKMissing            = "uefi-pk-miss"
	AnnPKInvalid            = "uefi-pk-inv"
	AnnKEKMissing           = "uefi-kek-miss"
	AnnKEKInvalid           = "uefi-kek-inv"
	AnnDBMissing            = "uefi-db-miss"
	AnnDBInvalid            = "uefi-db-inv"
	AnnDBxMissing           = "uefi-dbx-miss"
	AnnDBxInvalid           = "uefi-dbx-inv"

	// txt
	AnnNoTXTPubspace = "txt-public-miss"
	// css-*

	// sgx
	AnnNoSGX            = "sgx-missing"
	AnnSGXDisabled      = "sgx-disabled"
	AnnSGXCaps0Missing  = "sgx-cpuid0-miss"
	AnnSGXCaps1Missing  = "sgx-cpuid1-miss"
	AnnSGXCaps29Missing = "sgx-cpuid2-9-miss"

	// tpm
	AnnNoTPM                  = "tpm-miss"
	AnnNoTPMManufacturer      = "tpm-manuf-miss"
	AnnInvalidTPMManufacturer = "tpm-manuf-inv"
	AnnNoTPMVendorID          = "tpm-vid-miss"
	AnnInvalidTPMVendorID     = "tpm-vid-inv"
	AnnNoTPMSpecVersion       = "tpm-spec-miss"
	AnnInvalidTPMSpecVersion  = "tpm-spec-inv"
	AnnEventLogMissing        = "tpm-eventlog-miss"
	AnnEventLogInvalid        = "tpm-eventlog-inv"
	AnnEventLogBad            = "tpm-eventlog-bad"
	AnnPCRInvalid             = "tpm-pcr-miss"
	AnnPCRMissing             = "tpm-pcr-inv"

	// sev
	AnnNoSEV                 = "sev-miss"
	AnnSEVDisabled           = "sev-disabled"
	AnnPlatformStatusMissing = "sev-ps-miss"
	AnnPlatformStatusInvalid = "sev-ps-inv"

	// me
	AnnNoMEDevice           = "me-miss"
	AnnMEConfigSpaceInvalid = "me-inv"
	AnnMEVariantInvalid     = "me-variant-inv"
	AnnMEVersionMissing     = "me-version-miss"
	AnnMEVersionInvalid     = "me-version-inv"
	AnnMEFeaturesMissing    = "me-feat-miss"
	AnnMEFeaturesInvalid    = "me-feat-inv"
	AnnMEFWUPMissing        = "me-fwup-miss"
	AnnMEFWUPInvalid        = "me-fwup-inv"
)

var AnnFatal = map[AnnotationID]bool{
	// host
	AnnHostname:  false,
	AnnOSType:    false,
	AnnCPUVendor: false,

	// smbios
	AnnNoSMBIOS:           false,
	AnnInvalidSMBIOS:      true,
	AnnSMBIOSType0Missing: true,
	AnnSMBIOSType0Dup:     true,
	AnnSMBIOSType1Missing: true,
	AnnSMBIOSType1Dup:     true,

	// uefi
	AnnNoEFI:                false,
	AnnNoSecureBoot:         true,
	AnnNoDeployedSecureBoot: true,
	AnnMissingEventLog:      false,
	AnnModeInvalid:          false,
	AnnPKMissing:            true,
	AnnPKInvalid:            true,
	AnnKEKMissing:           true,
	AnnKEKInvalid:           true,
	AnnDBMissing:            true,
	AnnDBInvalid:            true,
	AnnDBxMissing:           true,
	AnnDBxInvalid:           true,

	// txt
	AnnNoTXTPubspace: false,
	// css-*

	// sgx
	AnnNoSGX:            false,
	AnnSGXDisabled:      false,
	AnnSGXCaps0Missing:  true,
	AnnSGXCaps1Missing:  true,
	AnnSGXCaps29Missing: true,

	// tpm
	AnnNoTPM:                  false,
	AnnNoTPMManufacturer:      true,
	AnnInvalidTPMManufacturer: true,
	AnnNoTPMVendorID:          true,
	AnnInvalidTPMVendorID:     true,
	AnnNoTPMSpecVersion:       true,
	AnnInvalidTPMSpecVersion:  true,
	AnnEventLogMissing:        false,
	AnnEventLogInvalid:        true,
	AnnEventLogBad:            true,
	AnnPCRInvalid:             true,
	AnnPCRMissing:             true,

	// sev
	AnnNoSEV:                 false,
	AnnSEVDisabled:           false,
	AnnPlatformStatusMissing: true,
	AnnPlatformStatusInvalid: true,

	// me
	AnnNoMEDevice:           false,
	AnnMEConfigSpaceInvalid: true,
	AnnMEVariantInvalid:     true,
	AnnMEVersionMissing:     true,
	AnnMEVersionInvalid:     true,
	AnnMEFeaturesMissing:    true,
	AnnMEFeaturesInvalid:    true,
	AnnMEFWUPMissing:        true,
	AnnMEFWUPInvalid:        true,
}

func (a AnnotationID) IsFatal() bool {
	if fatal, ok := AnnFatal[a]; ok {
		return fatal
	} else {
		return !strings.HasPrefix(string(a), "css-")
	}
}

var (
	ChangeEnroll     = "enroll"      // device
	ChangeRename     = "rename"      // device
	ChangeTag        = "tag"         // device
	ChangeAssociate  = "associate"   // device,policy
	ChangeTemplate   = "template"    // policy
	ChangeNew        = "new"         // policy
	ChangeInstaciate = "instanciate" // policy
	ChangeRevoke     = "revoke"      // policy
	ChangeRetire     = "retire"      // device
)

// /v2/changes
type Change struct {
	Id        string    `jsonapi:"primary,changes" json:"id"`
	Actor     *string   `jsonapi:"attr,actor,omitempty" json:"actor,omitempty"`
	Timestamp time.Time `jsonapi:"attr,timestamp,rfc3339" json:"timestamp"`
	Comment   *string   `jsonapi:"attr,comment,omitempty" json:"comment,omitempty"`
	Type      string    `jsonapi:"attr,type" json:"type"` // Change*
	Device    *Device   `jsonapi:"relation,devices,omitempty" json:"device,omitempty"`
	Policy    *Policy   `jsonapi:"relation,policies,omitempty" json:"policy,omitempty"`
}

const (
	StateNew           = "new"
	StateUnseen        = "unseen"
	StateVuln          = "vulnerable"
	StateTrusted       = "trusted"
	StateOutdated      = "outdated"
	StateRetired       = "retired"
	StateResurrectable = "resurrectable"
)

// /v2/devices
type Device struct {
	Id         string                 `jsonapi:"primary,devices" json:"id"`
	Cookie     string                 `jsonapi:"attr,cookie,omitempty" json:"cookie,omitempty"`
	Name       string                 `jsonapi:"attr,name" json:"name"`
	Attributes map[string]interface{} `jsonapi:"attr,groups" json:"attributes"`
	State      string                 `jsonapi:"attr,state" json:"state"`
	Hwid       string                 `jsonapi:"attr,hwid" json:"hwid"`
	Policies   []*Policy              `jsonapi:"relation,policies,omitempty" json:"policies,omitempty"`
	Replaces   []*Device              `jsonapi:"relation,replaces,omitempty" json:"replaces,omitempty"`
	ReplacedBy []*Device              `jsonapi:"relation,replaced_by,omitempty" json:"replaced_by,omitempty"`
	Appraisals []*Appraisal           `jsonapi:"relation,appraisals,omitempty" json:"appraisals,omitempty"`
	Changes    []*Change              `jsonapi:"relation,changes,omitempty" json:"changes,omitempty"`
}

// /v2/devices
type DevicePatch struct {
	Id         string                  `jsonapi:"primary,devices" json:"id"`
	Name       *string                 `jsonapi:"attr,name,omitempty" json:"name"`
	Attributes *map[string]interface{} `jsonapi:"attr,groups,omitempty" json:"attributes"`
	State      *string                 `jsonapi:"attr,state,omitempty" json:"state"`
	Comment    *string                 `jsonapi:"attr,comment,omitempty" json:"comment,omitempty"`
}

// /v2/policies
type Policy struct {
	Id          string                 `jsonapi:"primary,policies" json:"id"`
	Cookie      string                 `jsonapi:"attr,cookie,omitempty" json:"cookie,omitempty"`
	Name        string                 `jsonapi:"attr,name" json:"name"`
	ValidSince  *time.Time             `jsonapi:"attr,valid_from,omitempty,rfc3339" json:"valid_since,string,omitempty"`
	ValidUntil  *time.Time             `jsonapi:"attr,valid_until,omitempty,rfc3339" json:"valid_until,string,omitempty"`
	Revoked     bool                   `jsonapi:"attr,revoked" json:"revoked"`
	PCRTemplate []string               `jsonapi:"attr,pcr_template,omitempty" json:"pcr_template,string,omitempty"`
	FWTemplate  []string               `jsonapi:"attr,fw_template,omitempty" json:"fw_template,omitempty"`
	PCRs        map[string]interface{} `jsonapi:"attr,pcrs,omitempty" json:"pcrs,omitempty"`
	FWOverrides []string               `jsonapi:"attr,fw_overrides,omitempty" json:"fw_overrides,omitempty"`
	Devices     []*Device              `jsonapi:"relation,devices,omitempty" json:"devices,string"`
	Replaces    []*Policy              `jsonapi:"relation,replaces,omitempty" json:"replaces,omitempty,string"`
	ReplacedBy  []*Policy              `jsonapi:"relation,replaced_by,omitempty" json:"replaced_by,omitempty,string"`
	Changes     []*Change              `jsonapi:"relation,changes,omitempty" json:"changes"`
}

// /v2/policies
type PolicyCreation struct {
	Id         string     `jsonapi:"primary,policies" json:"id"`
	Name       string     `jsonapi:"attr,name,omitempty" json:"name"`
	Devices    []*Device  `jsonapi:"relation,devices,omitempty" json:"devices,string"`
	Cookie     *string    `jsonapi:"attr,cookie,omitempty" json:"cookie,omitempty"`
	ValidSince *time.Time `jsonapi:"attr,valid_from,omitempty,rfc3339" json:"valid_since,string,omitempty"`
	ValidUntil *time.Time `jsonapi:"attr,valid_until,omitempty,rfc3339" json:"valid_until,string,omitempty"`

	// policy.Template
	PCRTemplate  []string   `jsonapi:"attr,pcr_template,omitempty" json:"pcr_template,string,omitempty"`
	FWTemplate   []string   `jsonapi:"attr,fw_template,omitempty" json:"fw_template,omitempty"`
	RevokeActive *time.Time `jsonapi:"attr,revoke_active,omitempty,rfc3339" json:"revoke_active,string,omitempty"`

	// policy.New
	PCRs        map[string]interface{} `jsonapi:"attr,pcrs,omitempty" json:"pcrs,omitempty"`
	FWOverrides []string               `jsonapi:"attr,fw_overrides,omitempty" json:"fw_overrides,omitempty"`
}
