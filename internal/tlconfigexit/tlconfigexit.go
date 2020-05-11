// Package tlconfigexit is used to coordinate exit codes with the tlconfig command.
package tlconfigexit

// Possible exit codes used by the tlconfig command.
const (
	CodeFailedCheck = iota + 1
	CodeBadInput
	CodeUnexpectedFailure
)
