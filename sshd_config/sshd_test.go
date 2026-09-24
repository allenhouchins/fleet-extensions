package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

func TestParseConfig(t *testing.T) {
	output := "port 22\n" +
		"listenaddress 0.0.0.0:22\n" +
		"listenaddress [::]:22\n" +
		"PermitRootLogin prohibit-password\n" +
		"\n" +
		"subsystem sftp /usr/libexec/sftp-server\r\n" +
		"persourcepenalties crash:90.000000 authfail:5.000000\n" +
		"bannerkeywordonly\n"

	want := []configEntry{
		{"port", "22"},
		{"listenaddress", "0.0.0.0:22"},
		{"listenaddress", "[::]:22"},
		{"permitrootlogin", "prohibit-password"},
		{"subsystem", "sftp /usr/libexec/sftp-server"},
		{"persourcepenalties", "crash:90.000000 authfail:5.000000"},
		{"bannerkeywordonly", ""},
	}

	if got := parseConfig(output); !reflect.DeepEqual(got, want) {
		t.Errorf("parseConfig:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseConfigEmpty(t *testing.T) {
	if got := parseConfig(""); len(got) != 0 {
		t.Errorf("parseConfig(\"\") = %#v, want no entries", got)
	}
}

func TestUnsupportedFlag(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   bool
	}{
		{"bsd libc", "/usr/sbin/sshd: illegal option -- G\n", true},
		{"glibc", "sshd: invalid option -- 'G'\n", true},
		{"openssh getopt", "sshd: unknown option -- G\n", true},
		{"musl", "sshd: unrecognized option: G\n", true},
		{"usage only", "usage: sshd [-46DdeiqTt] [-C connection_spec]\n", true},
		{"bad config", "/etc/ssh/sshd_config: line 12: Bad configuration option: Foo\n", false},
		{"unsupported directive", "/etc/ssh/sshd_config line 3: Unsupported option UsePrivilegeSeparation\n", false},
		{"bad spec", "Invalid test mode specification foo\n", false},
		{"other flag", "sshd: illegal option -- Z\n", false},
		{"missing keys", "sshd: no hostkeys available -- exiting.\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unsupportedFlag.MatchString(tt.stderr); got != tt.want {
				t.Errorf("unsupportedFlag.MatchString(%q) = %v, want %v", tt.stderr, got, tt.want)
			}
		})
	}
}

func TestConnectionSpecs(t *testing.T) {
	tests := []struct {
		name string
		ctx  table.QueryContext
		want []string
	}{
		{"no constraints", table.QueryContext{}, nil},
		{
			"equals and in, deduplicated",
			queryContext(
				table.Constraint{Operator: table.OperatorEquals, Expression: "user=root"},
				table.Constraint{Operator: table.OperatorEquals, Expression: "user=alice,addr=10.0.0.1"},
				table.Constraint{Operator: table.OperatorEquals, Expression: "user=root"},
			),
			[]string{"user=root", "user=alice,addr=10.0.0.1"},
		},
		{
			"non-equality ignored",
			queryContext(table.Constraint{Operator: table.OperatorLike, Expression: "user=%"}),
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := connectionSpecs(tt.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("connectionSpecs = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func queryContext(constraints ...table.Constraint) table.QueryContext {
	return table.QueryContext{Constraints: map[string]table.ConstraintList{
		"connection_spec": {Affinity: table.ColumnTypeText, Constraints: constraints},
	}}
}

// Fake sshd builds. Each records its arguments, one invocation per line, so
// tests can assert which flags were tried.

// modernSSHD mirrors sshd 9.3+: -G works, and -C is refused without -T.
const modernSSHD = `#!/bin/sh
echo "$*" >> "$(dirname "$0")/calls"
case " $* " in
  *" -C "*)
    case " $* " in *" -T "*) ;; *)
      echo "Config test connection parameter (-C) provided without test mode (-T)" >&2
      exit 1 ;;
    esac ;;
esac
case "$1" in
  -G)
    echo "port 22"
    case " $* " in
      *" user=alice"*) echo "passwordauthentication no" ;;
      *) echo "passwordauthentication yes" ;;
    esac ;;
  *) exit 1 ;;
esac
`

// legacySSHD mirrors sshd before 9.3: -G is not an option at all.
const legacySSHD = `#!/bin/sh
echo "$*" >> "$(dirname "$0")/calls"
case "$1" in
  -G)
    echo "sshd: illegal option -- G" >&2
    echo "usage: sshd [-46DdeiqTt] [-C connection_spec]" >&2
    exit 1 ;;
  -T)
    echo "port 2222"
    echo "permitrootlogin without-password" ;;
esac
`

// brokenSSHD has an invalid configuration, which both flags report.
const brokenSSHD = `#!/bin/sh
echo "$*" >> "$(dirname "$0")/calls"
echo "/etc/ssh/sshd_config: line 12: Bad configuration option: Foo" >&2
echo "/etc/ssh/sshd_config: terminating, 1 bad configuration options" >&2
exit 255
`

func writeFakeSSHD(t *testing.T, script string) (sshdPath string, calls func() []string) {
	t.Helper()
	dir := t.TempDir()
	sshdPath = filepath.Join(dir, "sshd")
	if err := os.WriteFile(sshdPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return sshdPath, func() []string {
		data, err := os.ReadFile(filepath.Join(dir, "calls"))
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

func TestDumpConfig(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		spec      string
		wantCalls []string
		wantOut   string
		wantErr   string
	}{
		{
			name:      "modern, global config",
			script:    modernSSHD,
			wantCalls: []string{"-G"},
			wantOut:   "port 22\npasswordauthentication yes\n",
		},
		{
			name:      "modern, connection spec adds -T",
			script:    modernSSHD,
			spec:      "user=alice,host=h,addr=10.0.0.1",
			wantCalls: []string{"-G -T -C user=alice,host=h,addr=10.0.0.1"},
			wantOut:   "port 22\npasswordauthentication no\n",
		},
		{
			name:      "legacy falls back to -T",
			script:    legacySSHD,
			wantCalls: []string{"-G", "-T"},
			wantOut:   "port 2222\npermitrootlogin without-password\n",
		},
		{
			name:      "legacy falls back to -T with spec",
			script:    legacySSHD,
			spec:      "user=root",
			wantCalls: []string{"-G -T -C user=root", "-T -C user=root"},
			wantOut:   "port 2222\npermitrootlogin without-password\n",
		},
		{
			name:      "broken config is reported, not retried",
			script:    brokenSSHD,
			wantCalls: []string{"-G"},
			wantErr:   "-G: /etc/ssh/sshd_config: line 12: Bad configuration option: Foo /etc/ssh/sshd_config: terminating, 1 bad configuration options",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshdPath, calls := writeFakeSSHD(t, tt.script)

			out, _, err := dumpConfig(context.Background(), sshdPath, tt.spec)

			if tt.wantErr != "" {
				if err == nil || !strings.HasSuffix(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want suffix %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if out != tt.wantOut {
				t.Errorf("output = %q, want %q", out, tt.wantOut)
			}
			if got := calls(); !reflect.DeepEqual(got, tt.wantCalls) {
				t.Errorf("sshd invocations = %q, want %q", got, tt.wantCalls)
			}
		})
	}
}
