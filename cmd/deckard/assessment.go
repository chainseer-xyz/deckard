package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentexec"
	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

const assessmentUsage = `usage: deckard assessment execute --tool <zgrab2|zap|strix> --request <file> --report <file> --done <file>
       deckard assessment upload --tool <tool> --report <file> --done <file> --url <literal broker IP:port/v1/report> --token-file <file> --session <id> [--timeout 15m]
Trusted assessment Job wrappers only. Execute accepts the manager's bounded request file, not arbitrary scanner commands.
`

func runAssessment(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, assessmentUsage)
		return 1
	}
	command := args[0]
	if command == "--help" || command == "-h" || command == "help" {
		_, _ = fmt.Fprint(stdout, assessmentUsage)
		return 0
	}
	if command != "execute" && command != "upload" {
		_, _ = fmt.Fprint(stderr, assessmentUsage)
		return 1
	}
	return runAssessmentCommand(command, args[1:], stdout, stderr)
}

func runAssessmentCommand(command string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("assessment "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var tool, report, done, request, endpoint, tokenFile, session string
	var timeout time.Duration
	fs.StringVar(&tool, "tool", "", "manager-assigned tool")
	fs.StringVar(&report, "report", "", "fresh native report path")
	fs.StringVar(&done, "done", "", "exclusive completion marker")
	if command == "execute" {
		fs.StringVar(&request, "request", "", "manager request file")
	} else {
		fs.StringVar(&endpoint, "url", "", "literal report broker endpoint")
		fs.StringVar(&tokenFile, "token-file", "", "opaque upload token file")
		fs.StringVar(&session, "session", "", "manager session identity")
		fs.DurationVar(&timeout, "timeout", 15*time.Minute, "bounded wait and upload")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(stdout, assessmentUsage)
			return 0
		}
		_, _ = fmt.Fprint(stderr, assessmentUsage)
		return 1
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, assessmentUsage)
		return 1
	}
	var err error
	if command == "execute" {
		err = assessmentexec.Execute(context.Background(), assessmentexec.ExecuteOptions{Tool: assessmentjob.Tool(tool), RequestFile: request, ReportFile: report, DoneFile: done})
	} else {
		err = assessmentexec.Upload(context.Background(), assessmentexec.UploadOptions{Tool: assessmentjob.Tool(tool), ReportFile: report, DoneFile: done, URL: endpoint, TokenFile: tokenFile, Session: session, Timeout: timeout})
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "deckard assessment: "+command+" failed; no complete assessment is asserted")
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "deckard assessment: "+command+" finished")
	return 0
}
