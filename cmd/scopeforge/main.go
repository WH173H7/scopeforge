package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(runContext(ctx, os.Args[1:], os.Stdout, os.Stderr, systemResolver))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr, systemResolver)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer, resolver dns.Resolver) int {
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
		return runReconnaissance(ctx, args[1:], stdout, stderr, resolver)
	}

	fmt.Fprintf(stderr, "scopeforge: unknown command %q\n", args[0])
	printUsage(stderr)
	return exitUsage
}

func runReconnaissance(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	resolver dns.Resolver,
) int {
	var targets stringList
	collector, format := "", "text"
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&targets, "target", "exact DNS name to authorize (repeatable)")
	flags.StringVar(&collector, "collect", collector, "collector to run (dns)")
	flags.StringVar(&format, "format", format, "output format: text or json")

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

	policy, err := scope.NewPolicy(targets, nil)
	if err != nil {
		return expectedError(stdout, stderr, format, "invalid_target", "target is invalid", exitValidation)
	}
	for _, target := range policy.Allowed {
		if target.Kind != model.TargetDNSName {
			return expectedError(stdout, stderr, format, "unsupported_target", "dns collection requires DNS targets", exitValidation)
		}
	}

	runResult := model.Run{
		Status: model.RunCompleted, Scope: policy,
		Observations: []model.Observation{}, Evidence: []model.Evidence{}, Errors: []model.RunError{},
	}
	for _, target := range policy.Allowed {
		evidence, failures, collectErr := dns.Collect(ctx, resolver, policy, target, dnsLookupTimeout)
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
	return exitSuccess
}

func runStatus(run model.Run) model.RunStatus {
	actualFailures := 0
	for _, failure := range run.Errors {
		if failure.Code == "canceled" {
			return model.RunCanceled
		}
		if failure.Code != "no_result" {
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
}

func printValidateScopeUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: scopeforge validate-scope --target VALUE [options]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Options:")
	fmt.Fprintln(output, "  --target VALUE   Exact DNS name or IP address to authorize (repeatable)")
	fmt.Fprintln(output, "  --exclude VALUE  Exact DNS name or IP address to exclude (repeatable)")
	fmt.Fprintln(output, "  --format FORMAT  Output format: text or json (default text)")
}
