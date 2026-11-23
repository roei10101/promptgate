package detect

import (
	"strings"
	"testing"
)

// The fake credentials below are assembled at run time so that no
// credential-shaped literal is committed to the repository, which would trip
// secret scanners (including this project's own detectors).
var (
	fakeAWS     = "AKIA" + strings.Repeat("Q", 16)
	fakeGitHub  = "ghp_" + strings.Repeat("a1B2", 9)
	fakeFinePAT = "github_pat_" + strings.Repeat("a1B2_", 6)
	fakeSlack   = "xoxb-" + strings.Repeat("12345-", 3) + "abcdef"
	fakeLLMKey  = "sk-" + "proj-" + strings.Repeat("x9", 16)
	fakeJWT     = "eyJ" + strings.Repeat("a", 12) + ".eyJ" + strings.Repeat("b", 12) + "." + strings.Repeat("c", 12)
	fakePEM     = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA " + "PRIVATE KEY-----"
)

func TestSecretsDetectEachFormat(t *testing.T) {
	cases := []struct {
		name, secret, detector string
	}{
		{"aws access key id", fakeAWS, "aws_access_key_id"},
		{"aws temporary key id", "ASIA" + strings.Repeat("7", 16), "aws_access_key_id"},
		{"github classic token", fakeGitHub, "github_token"},
		{"github fine-grained token", fakeFinePAT, "github_token"},
		{"slack bot token", fakeSlack, "slack_token"},
		{"llm api key", fakeLLMKey, "llm_api_key"},
		{"jwt", fakeJWT, "jwt"},
		{"pem private key", fakePEM, "private_key"},
		{"pem key without a type", "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----", "private_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := "please debug this: " + tc.secret + " thanks"
			got := Scan(text, Secrets())
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(got), got)
			}
			if got[0].Detector != tc.detector {
				t.Errorf("detector = %q, want %q", got[0].Detector, tc.detector)
			}
			if matched := text[got[0].Start:got[0].End]; matched != tc.secret {
				t.Errorf("matched span %q, want the whole secret %q", matched, tc.secret)
			}
		})
	}
}

func TestSecretsIgnoreOrdinaryText(t *testing.T) {
	benign := []string{
		"",
		"What is the capital of France?",
		"My AWS account is misconfigured, the AKIA prefix docs are confusing.",
		"Use the sk-learn package and the ghp_ prefix convention.",
		"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
		"commit 5b313676b187cb2ece76cc5ba1b6f318f8d18fb5 broke the build",
		"eyJhbGciOiJub25lIn0 is only a JWT header, not a token",
		"XAKIA" + strings.Repeat("Q", 16), // prefix is not at a word boundary
	}
	for _, text := range benign {
		if got := Scan(text, Secrets()); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want no findings", text, got)
		}
	}
}

func TestScanReturnsSortedDisjointFindings(t *testing.T) {
	text := fakeGitHub + " and " + fakeAWS + " and " + fakeAWS
	got := Scan(text, Secrets())
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(got), got)
	}
	want := []string{"github_token", "aws_access_key_id", "aws_access_key_id"}
	prevEnd := 0
	for i, f := range got {
		if f.Detector != want[i] {
			t.Errorf("finding %d: detector = %q, want %q", i, f.Detector, want[i])
		}
		if f.Start < prevEnd {
			t.Errorf("finding %d overlaps the previous one: %+v", i, f)
		}
		prevEnd = f.End
	}
}

func TestScanDropsOverlappingFindings(t *testing.T) {
	// A private key that happens to contain a token-shaped line must be
	// reported once, as the enclosing key.
	text := "-----BEGIN " + "PRIVATE KEY-----\n" + fakeAWS + "\n-----END " + "PRIVATE KEY-----"
	got := Scan(text, Secrets())
	if len(got) != 1 || got[0].Detector != "private_key" {
		t.Fatalf("got %+v, want a single private_key finding", got)
	}
}

func TestTruncatedPrivateKeyIsMatchedToEndOfText(t *testing.T) {
	text := "key: -----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXk"
	got := Scan(text, Secrets())
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].End != len(text) {
		t.Errorf("End = %d, want %d (end of text)", got[0].End, len(text))
	}
}

func TestRedact(t *testing.T) {
	text := "id=" + fakeAWS + " token=" + fakeGitHub + "."
	got := Redact(text, Scan(text, Secrets()))
	want := "id=[REDACTED:aws_access_key_id] token=[REDACTED:github_token]."
	if got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
}

func TestRedactWithoutFindingsReturnsInput(t *testing.T) {
	if got := Redact("hello", nil); got != "hello" {
		t.Errorf("Redact = %q, want %q", got, "hello")
	}
}
