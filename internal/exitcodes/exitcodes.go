// Package exitcodes is used to coordinate exit codes used in internal commands.
package exitcodes

import (
	"errors"
	"fmt"
	"os"
)

// Possible exit codes used by internal commands.
const (
	FailedCheck = iota + 1
	BadInput
	UnexpectedFailure
)

// A FailedCheckError occurs when the system is not configured as expected.
type FailedCheckError struct {
	msg string
}

// ErrorFailedCheck creates a new FailedCheckError.
func ErrorFailedCheck(msg string) FailedCheckError {
	return FailedCheckError{msg}
}

// ErrorFailedCheckf creates a new FailedCheckError.
func ErrorFailedCheckf(msg string, a ...interface{}) FailedCheckError {
	return ErrorFailedCheck(fmt.Sprintf(msg, a...))
}

func (e FailedCheckError) Error() string {
	return e.msg
}

// A BadInputError occurs when a command is provided with bad input.
type BadInputError struct {
	msg   string
	cause error
}

// ErrorBadInput creates a new BadInputError.
func ErrorBadInput(msg string, cause error) BadInputError {
	return BadInputError{msg, cause}
}

func (e BadInputError) Error() string {
	if e.cause == nil {
		return e.msg
	}
	return fmt.Sprintf("%s: %v", e.msg, e.cause)
}

func (e BadInputError) Unwrap() error {
	return e.cause
}

// ExitWith prints the error message to stderr and exits the runtime with the appropriate exit code.
func ExitWith(err error) {
	fmt.Fprintln(os.Stderr, err)
	switch {
	case errors.As(err, new(FailedCheckError)):
		os.Exit(FailedCheck)
	case errors.As(err, new(BadInputError)):
		os.Exit(BadInput)
	default:
		os.Exit(UnexpectedFailure)
	}
}

// ErrorFromCode creates an error of the appropriate type based on the provided code.
func ErrorFromCode(code int, msg string) error {
	switch code {
	case FailedCheck:
		return ErrorFailedCheck(msg)
	case BadInput:
		return ErrorBadInput(msg, nil)
	default:
		return errors.New(msg)
	}
}
