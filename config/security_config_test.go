package config

import (
	"testing"
)

type StubSecurityCfgParser struct {
	sc *SecurityCfg
}

func (s StubSecurityCfgParser) Parse() (*SecurityCfg, error) {
	return s.sc, nil
}

func TestLoadSecurityCfg(t *testing.T) {
	validSecurityCfgTests := []struct {
		name string
		cfg  *SecurityCfg
	}{
		{
			name: "Minimum valid config with implicit defaults",
			cfg: &SecurityCfg{
				Version:  SecurityCfgVersion,
				BootMode: LocalBoot,
			},
		},
		{
			name: "Minimum valid config with explicit values",
			cfg: &SecurityCfg{
				Version:                 SecurityCfgVersion,
				ValidSignatureThreshold: 1,
				BootMode:                NetworkBoot,
				UsePkgCache:             true,
			},
		},
	}

	for _, tt := range validSecurityCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			p := StubSecurityCfgParser{tt.cfg}
			_, err := LoadSecurityCfg(p)

			assertNoError(t, err)
		})
	}

	invalidSecurityCfgTests := []struct {
		name string
		cfg  *SecurityCfg
		want error
	}{
		{
			name: "Missing version",
			cfg: &SecurityCfg{
				BootMode: LocalBoot,
			},
			want: ErrSecurityCfgVersionMissmatch,
		},
		{
			name: "Version missmatch",
			cfg: &SecurityCfg{
				Version:  SecurityCfgVersion + 1,
				BootMode: LocalBoot,
			},
			want: ErrSecurityCfgVersionMissmatch,
		},
		{
			name: "Empty boot mode",
			cfg: &SecurityCfg{
				Version: SecurityCfgVersion,
			},
			want: ErrMissingBootMode,
		},
		{
			name: "Unknown boot mode",
			cfg: &SecurityCfg{
				Version:  SecurityCfgVersion,
				BootMode: 3,
			},
			want: ErrUnknownBootMode,
		},
	}

	for _, tt := range invalidSecurityCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			p := StubSecurityCfgParser{tt.cfg}
			_, err := LoadSecurityCfg(p)

			assertError(t, err, tt.want)
		})
	}
}

func TestBootMode(t *testing.T) {
	tests := []struct {
		name string
		mode BootMode
		want string
	}{
		{
			name: "String for default value",
			mode: UnsetBootMode,
			want: "unset",
		},
		{
			name: "String for 'LocalBoot'",
			mode: LocalBoot,
			want: "local",
		},
		{
			name: "String for 'NetworkBoot'",
			mode: NetworkBoot,
			want: "network",
		},
		{
			name: "String for unknown value",
			mode: 3,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
