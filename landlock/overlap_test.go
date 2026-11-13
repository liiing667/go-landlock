//go:build linux

package landlock_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// TestOverlappingPathRulesRejected verifies that unsatisfiable
// conjunctions of filesystem rules (a read-only ancestor together
// with a read-write descendant) are rejected before the Landlock
// ruleset is submitted, instead of failing with EPERM/EACCES only
// after the domain got enforced.
func TestOverlappingPathRulesRejected(t *testing.T) {
	lltest.RequireABI(t, 1)

	dir := t.TempDir()
	parent := filepath.Join(dir, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatalf("os.MkdirAll: %v", err)
	}

	for _, tc := range []struct {
		name  string
		rules []landlock.Rule
	}{
		{
			name: "RODirsAncestorWithRWDirsDescendant",
			rules: []landlock.Rule{
				landlock.RODirs(parent),
				landlock.RWDirs(child),
			},
		},
		{
			name: "RulesGivenInReverseOrder",
			rules: []landlock.Rule{
				landlock.RWDirs(child),
				landlock.RODirs(parent),
			},
		},
		{
			name: "PathAccessROAncestorWithRWDescendant",
			rules: []landlock.Rule{
				landlock.PathAccess(ll.AccessFSReadFile|ll.AccessFSReadDir|ll.AccessFSExecute, parent),
				landlock.PathAccess(ll.AccessFSReadFile|ll.AccessFSWriteFile|ll.AccessFSTruncate, child),
			},
		},
		{
			name: "ConflictWrappedInCompositeRule",
			rules: []landlock.Rule{
				landlock.CompositeRule(
					landlock.RODirs(parent),
					landlock.RWDirs(child),
				),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := landlock.V7.RestrictPaths(tc.rules...)
			if err == nil {
				t.Fatalf("RestrictPaths: want an overlap error, got success")
			}
			if !strings.Contains(err.Error(), "overlapping path rules") {
				t.Errorf("RestrictPaths: want an 'overlapping path rules' error, got: %v", err)
			}
			if isGoLandlockBug(err) {
				t.Errorf("Overlap error must not be marked as a go-landlock bug, got: %v", err)
			}
		})
	}
}

// TestOverlappingPathRulesBestEffort verifies that the overlap check
// runs on the downgraded, effective rules. A conflict which remains
// after downgrade is still rejected, while rights dropped by the
// downgrade do not produce false positives.
func TestOverlappingPathRulesBestEffort(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		dir := lltest.TempDir(t)
		parent := filepath.Join(dir, "parent")
		child := filepath.Join(parent, "child")
		if err := os.MkdirAll(child, 0o700); err != nil {
			t.Fatalf("os.MkdirAll: %v", err)
		}

		// Best effort does not paper over a real conflict: The
		// write rights handled by the V7 kernel stay unsatisfiable
		// below the read-only ancestor, so this must still fail.
		err := landlock.V7.BestEffort().RestrictPaths(
			landlock.RODirs(parent),
			landlock.RWDirs(child),
		)
		if err == nil || !strings.Contains(err.Error(), "overlapping path rules") {
			t.Errorf("RestrictPaths: got %v, want an 'overlapping path rules' error", err)
		}
	})
}

// TestOverlappingPathRulesAcceptedCases ensures that rule
// combinations which are actually satisfiable keep working and get
// enforced as before.
func TestOverlappingPathRulesAcceptedCases(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		dir := lltest.TempDir(t)
		roDir := filepath.Join(dir, "ro")
		rwDir := filepath.Join(dir, "rw")
		nestedRO := filepath.Join(rwDir, "nested-ro")
		for _, d := range []string{roDir, rwDir, nestedRO} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatalf("os.MkdirAll(%q): %v", d, err)
			}
		}

		roFile := filepath.Join(roDir, "file")
		MustWriteFile(t, roFile)
		rwFile := filepath.Join(rwDir, "file")
		MustWriteFile(t, rwFile)
		nestedFile := filepath.Join(nestedRO, "file")
		MustWriteFile(t, nestedFile)

		// Satisfiable combinations:
		// - non-overlapping RO and RW directories
		// - an RW ancestor and an additional read-only rule on a
		//   nested directory (the nested rule cannot take away
		//   rights already granted by the RW ancestor, so this is
		//   not the rejected RO-ancestor/RW-descendant pattern)
		err := landlock.V7.RestrictPaths(
			landlock.RODirs(roDir),
			landlock.RWDirs(rwDir),
			landlock.RODirs(nestedRO),
		)
		if err != nil {
			t.Fatalf("RestrictPaths: got unexpected error %v", err)
		}

		if err := openForRead(roFile); err != nil {
			t.Errorf("openForRead(%q): %v", roFile, err)
		}
		if err := openForWrite(roFile); !errors.Is(err, syscall.EACCES) {
			t.Errorf("openForWrite(%q): got %v, want EACCES", roFile, err)
		}
		if err := openForWrite(rwFile); err != nil {
			t.Errorf("openForWrite(%q): %v", rwFile, err)
		}
		if err := openForRead(nestedFile); err != nil {
			t.Errorf("openForRead(%q): %v", nestedFile, err)
		}
	})
}

// TestOverlappingPathRulesIgnoreIfMissing verifies that missing
// IgnoreIfMissing paths do not participate in the overlap check,
// matching the semantics at rule submission time.
func TestOverlappingPathRulesIgnoreIfMissing(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		lltest.RequireABI(t, 1)

		dir := lltest.TempDir(t)
		missingParent := filepath.Join(dir, "missing-parent")
		missingChild := filepath.Join(missingParent, "missing-child")

		err := landlock.V7.RestrictPaths(
			landlock.RODirs(missingParent).IgnoreIfMissing(),
			landlock.RWDirs(missingChild).IgnoreIfMissing(),
		)
		if err != nil {
			t.Errorf("RestrictPaths: got unexpected error %v", err)
		}
	})
}

// TestOverlappingPathRulesSymlinkSemantics verifies that the overlap
// check is lexical and does not resolve symlinks, preserving the
// existing symlink handling of Landlock path rules.
func TestOverlappingPathRulesSymlinkSemantics(t *testing.T) {
	for _, tc := range []struct {
		name      string
		setup     func(t *testing.T) (ancestor, descendant string)
		wantError bool
	}{
		{
			name: "SymlinkOutsideLexicalHierarchyIsAccepted",
			setup: func(t *testing.T) (string, string) {
				dir := lltest.TempDir(t)
				roTarget := filepath.Join(dir, "ro-target")
				rwTarget := filepath.Join(dir, "rw-target")
				MustMkdir(t, roTarget)
				MustMkdir(t, rwTarget)
				link := filepath.Join(rwTarget, "link-to-ro")
				if err := os.Symlink(roTarget, link); err != nil {
					t.Fatalf("os.Symlink: %v", err)
				}
				return roTarget, rwTarget
			},
		},
		{
			name: "SymlinkBelowLexicalAncestorIsStillDetected",
			setup: func(t *testing.T) (string, string) {
				dir := lltest.TempDir(t)
				roTarget := filepath.Join(dir, "ro-target")
				rwTarget := filepath.Join(dir, "rw-target")
				MustMkdir(t, roTarget)
				MustMkdir(t, rwTarget)
				nestedLink := filepath.Join(roTarget, "nested-link")
				if err := os.Symlink(rwTarget, nestedLink); err != nil {
					t.Fatalf("os.Symlink: %v", err)
				}
				return roTarget, nestedLink
			},
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, 1)

				ancestor, descendant := tc.setup(t)
				err := landlock.V7.RestrictPaths(
					landlock.RODirs(ancestor),
					landlock.RWDirs(descendant),
				)
				switch {
				case tc.wantError && (err == nil || !strings.Contains(err.Error(), "overlapping path rules")):
					t.Errorf("RestrictPaths: got %v, want an 'overlapping path rules' error", err)
				case !tc.wantError && err != nil:
					t.Errorf("RestrictPaths: got unexpected error %v", err)
				}
			})
		})
	}
}
