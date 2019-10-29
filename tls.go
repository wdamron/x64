// +build !darwin

package x64

// Register where the Go runtime maintains a pointer to thread-local storage.
const reg_tls = GS
