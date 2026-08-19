package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/WH173H7/scopeforge/internal/artifact"
	"github.com/WH173H7/scopeforge/internal/dns"
	"github.com/WH173H7/scopeforge/internal/model"
	"github.com/WH173H7/scopeforge/internal/render"
	"github.com/WH173H7/scopeforge/internal/scope"
)

const version = "0.0.0-dev"

const dnsLookupTimeout = 5 * time.Second

var systemResolver = &net.Resolver{
	PreferGo: true,
	Dial: (&net.Dialer{
		Timeout: dnsLookupTimeout,
	}).DialContext,
}

const (
	exitSuccess    = 0
	exitInternal   = 1
	exitUsage      = 2
	exitValidation = 3
)

type stringList []string

func (values *stringList) String() string {
	return fmt.Sprint([]string(*values))
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type runEnv struct {
	resolver dns.Resolver
	now      func() time.Time
	newID    func(time.Time) (string, error)
}

func defaultEnv(resolver dns.Resolver) runEnv {
	return runEnv{
		resolver: resolver,
		now:      func() time.Time { return time.Now().UTC() },
		newID: func(now time.Time) (string, error) {
			return artifact.NewID(now, rand.Reader)
		},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(runContext(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultEnv(systemResolver)))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr, defaultEnv(systemResolver))
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer, env runEnv) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printUsage(stdout)
		return exitSuccess
	}

	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return exitSuccess
	}

	if args[0] == "validate-scope" {
		return runValidateScope(args[1:], stdout, stderr)
	}
	if args[0] == "run" {
		return runReconnaissance(ctx, args[1:], stdout, stderr, env)
	}
	if args[0] == "inspect-run" {
		return runInspect(args[1:], stdout, stderr)
	}

	fmt.Fprintf(stderr, "scopeforge: unknown command %q\n", args[0])
	printUsage(stderr)
	return exitUsage
}

func runReconnaissance(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	env runEnv,
) int {
	var targets stringList
	collector, format, saveDir := "", "text", ""
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&targets, "target", "exact DNS name to authorize (repeatable)")
	flags.StringVar(&collector, "collect", collector, "collector to run (dns)")
	flags.StringVar(&format, "format", format, "output format: text or json")
	flags.StringVar(&saveDir, "save-dir", saveDir, "directory for one JSON run artifact")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printRunUsage(stdout)
			return exitSuccess
		}
		return expectedError(stdout, stderr, format, "invalid_usage", "invalid command usage", exitUsage)
	}
	if flags.NArg() != 0 {
		return expectedError(stdout, stderr, format, "invalid_usage", "unexpected positional arguments", exitUsage)
	}
	if format != "text" && format != "json" {
		return expectedError(stdout, stderr, "text", "invalid_format", "format must be text or json", exitUsage)
	}
	if collector != "dns" {
		return expectedError(stdout, stderr, format, "unsupported_collector", "collector must be dns", exitUsage)
	}
	if len(targets) == 0 {
		return expectedError(stdout, stderr, format, "missing_target", "at least one target is required", exitValidation)
	}
	if strings.TrimSpace(saveDir) == "" && saveDir != "" {
		return expectedError(stdout, stderr, format, "invalid_usage", "save directory is invalid", exitUsage)
	}

	policy, err := scope.NewPolicy(targets, nil)
	if err != nil {
		return expectedError(stdout, stderr, format, "invalid_target", "target is invalid", exitValidation)
	}
	for _, target := range policy.Allowed {
		if target.Kind != model.TargetDNSName {
			return expectedError(stdout, stderr, format, "unsupported_target", "dns collection requires DNS targets", exitValidation)
		}
	}

	startedAt := env.now()
	runID, err := env.newID(startedAt)
	if err != nil {
		fmt.Fprintln(stderr, "scopeforge: internal_error: could not assign run ID")
		return exitInternal
	}
	runResult := model.Run{
		ID: runID, StartedAt: startedAt, Status: model.RunCompleted, Scope: policy,
		Observations: []model.Observation{}, Evidence: []model.Evidence{}, Errors: []model.RunError{},
	}
	for _, target := range policy.Allowed {
		evidence, failures, collectErr := dns.Collect(ctx, env.resolver, policy, target, dnsLookupTimeout)
		if collectErr != nil {
			fmt.Fprintln(stderr, "scopeforge: internal_error: authorization invariant failed")
			return exitInternal
		}
		runResult.Evidence = append(runResult.Evidence, evidence...)
		runResult.Errors = append(runResult.Errors, failures...)
		if ctx.Err() != nil {
			break
		}
	}
	finishedAt := env.now()
	runResult.FinishedAt = &finishedAt
	runResult.Status = runStatus(runResult)

	if format == "json" {
		err = render.RunJSON(stdout, runResult)
	} else {
		err = render.RunText(stdout, runResult)
	}
	if err != nil {
		fmt.Fprintln(stderr, "scopeforge: internal_error: could not write output")
		return exitInternal
	}
	if saveDir == "" {
		return exitSuccess
	}
	if err := artifact.Write(saveDir, runResult); err != nil {
		fmt.Fprintf(stderr, "scopeforge: artifact_write_failed: %s\n", artifactWriteMessage(err))
		return exitInternal
	}
	return exitSuccess
}

func artifactWriteMessage(err error) string {
	switch {
	case errors.Is(err, artifact.ErrExists):
		return "run artifact already exists"
	case errors.Is(err, artifact.ErrInvalidID):
		return "run ID is invalid"
	case errors.Is(err, artifact.ErrInvalidDir):
		return "save directory is invalid"
	default:
		return "could not write run artifact"
	}
}

func runStatus(run model.Run) model.RunStatus {
	actualFailures := 0
	for _, failure := range run.Errors {
		if failure.Code == "canceled" {
			return model.RunCanceled
		}
		if failure.Code != "no_result" && failure.Code != "evidence_limited" {
			actualFailures++
		}
	}
	if actualFailures == 0 {
		return model.RunCompleted
	}
	if len(run.Evidence) == 0 {
		return model.RunFailed
	}
	return model.RunPartial
}

func runValidateScope(args []string, stdout, stderr io.Writer) int {
	var targets, exclusions stringList
	format := "text"
	flags := flag.NewFlagSet("validate-scope", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&targets, "target", "exact DNS name or IP address to authorize (repeatable)")
	flags.Var(&exclusions, "exclude", "exact DNS name or IP address to exclude (repeatable)")
	flags.StringVar(&format, "format", format, "output format: text or json")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printValidateScopeUsage(stdout)
			return exitSuccess
		}
		return expectedError(stdout, stderr, format, "invalid_usage", "invalid command usage", exitUsage)
	}
	if flags.NArg() != 0 {
		return expectedError(stdout, stderr, format, "invalid_usage", "unexpected positional arguments", exitUsage)
	}
	if format != "text" && format != "json" {
		return expectedError(stdout, stderr, "text", "invalid_format", "format must be text or json", exitUsage)
	}
	if len(targets) == 0 {
		return expectedError(stdout, stderr, format, "missing_target", "at least one target is required", exitValidation)
	}

	policy, err := scope.NewPolicy(targets, exclusions)
	if err != nil {
		var inputError *scope.InputError
		if errors.As(err, &inputError) && inputError.IsExclusion() {
			return expectedError(stdout, stderr, format, "invalid_exclusion", "exclusion is invalid", exitValidation)
		}
		return expectedError(stdout, stderr, format, "invalid_target", "target is invalid", exitValidation)
	}
	effective := scope.EffectiveTargets(policy)
	if len(effective) == 0 {
		return expectedError(stdout, stderr, format, "empty_effective_scope", "all targets are excluded", exitValidation)
	}

	if format == "json" {
		err = render.ScopeJSON(stdout, policy, effective)
	} else {
		err = render.ScopeText(stdout, policy, effective)
	}
	if err != nil {
		fmt.Fprintln(stderr, "scopeforge: internal_error: could not write output")
		return exitInternal
	}
	return exitSuccess
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	runDir, id, format := "", "", "text"
	flags := flag.NewFlagSet("inspect-run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&runDir, "run-dir", runDir, "directory containing saved run artifacts")
	flags.StringVar(&id, "id", id, "generated run ID of the artifact to inspect")
	flags.StringVar(&format, "format", format, "output format: text or json")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printInspectRunUsage(stdout)
			return exitSuccess
		}
		return expectedError(stdout, stderr, format, "invalid_usage", "invalid command usage", exitUsage)
	}
	if flags.NArg() != 0 {
		return expectedError(stdout, stderr, format, "invalid_usage", "unexpected positional arguments", exitUsage)
	}
	if format != "text" && format != "json" {
		return expectedError(stdout, stderr, "text", "invalid_format", "format must be text or json", exitUsage)
	}
	if runDir == "" {
		return expectedError(stdout, stderr, format, "missing_run_dir", "run directory is required", exitValidation)
	}
	if id == "" {
		return expectedError(stdout, stderr, format, "missing_run_id", "run ID is required", exitValidation)
	}
	if !artifact.ValidID(id) {
		return expectedError(stdout, stderr, format, "invalid_run_id", "run ID is invalid", exitValidation)
	}

	loaded, err := artifact.Read(runDir, id)
	if err != nil {
		code, message, exitCode := inspectError(err)
		return expectedError(stdout, stderr, format, code, message, exitCode)
	}

	if format == "json" {
		err = render.RunJSON(stdout, loaded)
	} else {
		err = render.InspectText(stdout, loaded)
	}
	if err != nil {
		fmt.Fprintln(stderr, "scopeforge: internal_error: could not write output")
		return exitInternal
	}
	return exitSuccess
}

func inspectError(err error) (code, message string, exitCode int) {
	switch {
	case errors.Is(err, artifact.ErrNotFound):
		return "artifact_not_found", "run artifact not found", exitValidation
	case errors.Is(err, artifact.ErrTooLarge):
		return "artifact_too_large", "run artifact exceeds the read size limit", exitValidation
	case errors.Is(err, artifact.ErrUnsupportedSchema):
		return "unsupported_artifact_schema", "run artifact schema is unsupported", exitValidation
	case errors.Is(err, artifact.ErrIDMismatch):
		return "artifact_id_mismatch", "artifact ID does not match the requested ID", exitValidation
	case errors.Is(err, artifact.ErrInvalidID):
		return "invalid_run_id", "run ID is invalid", exitValidation
	case errors.Is(err, artifact.ErrInvalidDir):
		return "invalid_usage", "run directory is invalid", exitUsage
	case errors.Is(err, artifact.ErrInvalid):
		return "invalid_artifact", "run artifact is invalid", exitValidation
	default:
		return "artifact_read_failed", "could not read run artifact", exitInternal
	}
}

func expectedError(stdout, stderr io.Writer, format, code, message string, exitCode int) int {
	if format == "json" {
		if err := render.ErrorJSON(stdout, code, message); err != nil {
			fmt.Fprintln(stderr, "scopeforge: internal_error: could not write output")
			return exitInternal
		}
		return exitCode
	}
	fmt.Fprintf(stderr, "scopeforge: %s: %s\n", code, message)
	return exitCode
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: scopeforge <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	fmt.Fprintln(output, "  help            Show this help")
	fmt.Fprintln(output, "  inspect-run     Display a saved reconnaissance artifact")
	fmt.Fprintln(output, "  run             Collect evidence for an explicit scope")
	fmt.Fprintln(output, "  validate-scope  Validate and display an explicit scope policy")
	fmt.Fprintln(output, "  version         Show the version")
}

func printRunUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: scopeforge run --target VALUE --collect dns [options]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Options:")
	fmt.Fprintln(output, "  --target VALUE   Exact DNS name to authorize (repeatable)")
	fmt.Fprintln(output, "  --collect NAME   Collector to run (dns)")
	fmt.Fprintln(output, "  --format FORMAT  Output format: text or json (default text)")
	fmt.Fprintln(output, "  --save-dir DIR   Write one versioned JSON run artifact into DIR")
}

func printInspectRunUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: scopeforge inspect-run --run-dir DIR --id RUN_ID [options]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Options:")
	fmt.Fprintln(output, "  --run-dir DIR    Directory containing saved run artifacts")
	fmt.Fprintln(output, "  --id RUN_ID      Generated run ID of the artifact to inspect")
	fmt.Fprintln(output, "  --format FORMAT  Output format: text or json (default text)")
}

func printValidateScopeUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: scopeforge validate-scope --target VALUE [options]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Options:")
	fmt.Fprintln(output, "  --target VALUE   Exact DNS name or IP address to authorize (repeatable)")
	fmt.Fprintln(output, "  --exclude VALUE  Exact DNS name or IP address to exclude (repeatable)")
	fmt.Fprintln(output, "  --format FORMAT  Output format: text or json (default text)")
}
