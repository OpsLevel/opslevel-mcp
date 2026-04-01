package cmd

import (
"runtime"
"testing"
)

func TestGetGoInfo(t *testing.T) {
goInfo := getGoInfo()

if goInfo.Version == "" {
t.Error("Expected Go version to be set, got empty string")
}

if goInfo.Compiler == "" {
t.Error("Expected Go compiler to be set, got empty string")
}

if goInfo.OS == "" {
t.Error("Expected Go OS to be set, got empty string")
}

if goInfo.Arch == "" {
t.Error("Expected Go Arch to be set, got empty string")
}

// Verify values match runtime package
if goInfo.Version != runtime.Version() {
t.Errorf("Expected Version %s, got %s", runtime.Version(), goInfo.Version)
}

if goInfo.Compiler != runtime.Compiler {
t.Errorf("Expected Compiler %s, got %s", runtime.Compiler, goInfo.Compiler)
}

if goInfo.OS != runtime.GOOS {
t.Errorf("Expected OS %s, got %s", runtime.GOOS, goInfo.OS)
}

if goInfo.Arch != runtime.GOARCH {
t.Errorf("Expected Arch %s, got %s", runtime.GOARCH, goInfo.Arch)
}
}

func TestInitBuild(t *testing.T) {
// Save original values
originalVersion := version
originalCommit := commit

// Test with normal commit
version = "1.0.0"
commit = "abc123def456789"
initBuild()

if build.Version != "1.0.0" {
t.Errorf("Expected build.Version to be '1.0.0', got '%s'", build.Version)
}

if build.Commit != "abc123def456" {
t.Errorf("Expected build.Commit to be truncated to 12 chars, got '%s'", build.Commit)
}

// Test with short commit
commit = "short"
initBuild()

if build.Commit != "short" {
t.Errorf("Expected build.Commit to be 'short', got '%s'", build.Commit)
}

// Restore original values
version = originalVersion
commit = originalCommit
}

func TestBuildStructure(t *testing.T) {
// Test that Build struct can be instantiated
b := Build{
Version: "1.0.0",
Commit:  "abc123",
GoInfo: GoInfo{
Version:  "go1.20",
Compiler: "gc",
OS:       "linux",
Arch:     "amd64",
},
}

if b.Version != "1.0.0" {
t.Errorf("Expected Version '1.0.0', got '%s'", b.Version)
}

if b.Commit != "abc123" {
t.Errorf("Expected Commit 'abc123', got '%s'", b.Commit)
}

if b.GoInfo.Version != "go1.20" {
t.Errorf("Expected GoInfo.Version 'go1.20', got '%s'", b.GoInfo.Version)
}
}

func TestOpslevelVersionStructure(t *testing.T) {
// Test that OpslevelVersion struct can be instantiated
ov := OpslevelVersion{
Version: "1.0.0",
Commit:  "abc123",
}

if ov.Version != "1.0.0" {
t.Errorf("Expected Version '1.0.0', got '%s'", ov.Version)
}

if ov.Commit != "abc123" {
t.Errorf("Expected Commit 'abc123', got '%s'", ov.Commit)
}
}
