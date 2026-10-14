package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestAssessmentCommandHelpDocumentsOnlyTrustedWrapperInputs(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"execute", "--help"}, {"upload", "--help"}} {
		var out, errw bytes.Buffer
		if code := runAssessment(args, &out, &errw); code != 0 || !strings.Contains(out.String(), "assessment") || !strings.Contains(out.String(), "--report") || errw.Len() != 0 {
			t.Fatalf("help code/body: %s %s", out.String(), errw.String())
		}
	}
}

func TestAssessmentWrapperRejectsUnknownArgumentsWithoutEchoingSecrets(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown-SECRET"}, {"execute", "--command=SECRET"}, {"upload", "--token=SECRET"}, {"execute", "--tool=zgrab2", "positional-SECRET"}, {"upload", "--url=http://user:SECRET@broker/v1/report", "--tool=zgrab2", "--session=session-1"}} {
		var out, errw bytes.Buffer
		if code := runAssessment(args, &out, &errw); code == 0 {
			t.Fatal("invalid wrapper request accepted")
		}
		if strings.Contains(out.String()+errw.String(), "SECRET") {
			t.Fatal("wrapper leaked rejected argument")
		}
	}
}

func TestAssessmentExecuteInvalidRequestFailsWithoutAdvertisingSuccessfulScan(t *testing.T) {
	var out, errw bytes.Buffer
	if code := runAssessment([]string{"execute", "--tool=zgrab2", "--request=/nonexistent/SECRET", "--report=/nonexistent/report", "--done=/nonexistent/done"}, &out, &errw); code != 1 || out.Len() != 0 || !strings.Contains(errw.String(), "failed") || strings.Contains(errw.String(), "SECRET") {
		t.Fatalf("unsafe execution status: stdout=%s stderr=%s", out.String(), errw.String())
	}
}
