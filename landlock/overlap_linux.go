//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// errOverlappingPathRules is returned when the filesystem rules can
// never be satisfied because a nested path requests access rights
// that an ancestor path does not grant.
var errOverlappingPathRules = errors.New("overlapping path rules form an unsatisfiable conjunction")

// pathRule is the effective part of a filesystem rule for the
// purposes of overlap checking: one clean path together with the
// access rights that would actually be added to the ruleset for it.
type pathRule struct {
	path   string
	access AccessFSSet
}

// collectPathRules flattens composite rules and keeps the effective
// filesystem rules which would actually be added to the ruleset.
//
// Rules whose access rights reduce to the empty set are skipped, as
// they are no-ops when added. Paths of IgnoreIfMissing rules which do
// not exist on the filesystem are skipped as well, mirroring the
// behavior of addPaths.
func collectPathRules(rules []Rule, c Config) []pathRule {
	var out []pathRule
	var walk func(Rule)
	walk = func(rule Rule) {
		switch r := rule.(type) {
		case FSRule:
			if r.internal {
				return
			}
			// Mirror FSRule.addToRuleset, which intersects the
			// rule's rights with the Config's handled access
			// rights before submission. This is a no-op for rules
			// which already enforce the subset property.
			access := r.accessFS
			access = access.intersect(c.HandledAccessFS)
			if access == 0 {
				return
			}
			for _, path := range r.paths {
				if r.ignoreMissing {
					if err := checkPathExists(path); errors.Is(err, unix.ENOENT) {
						continue
					}
				}
				out = append(out, pathRule{path: cleanPath(path), access: access})
			}
		case *compositeRule:
			for _, sub := range r.rules {
				walk(sub)
			}
		}
	}
	for _, rule := range rules {
		walk(rule)
	}
	return out
}

// cleanPath canonicalizes a rule path for lexical hierarchy checks.
// It keeps the same semantics as path/filepath.Clean: Relative paths
// stay relative, and symlinks are not resolved, so the existing
// symlink behavior of Landlock rules is preserved.
func cleanPath(path string) string {
	return filepath.Clean(path)
}

// checkPathExists probes for the existence of path using O_PATH, the
// same mechanism that addPath uses to open rule paths. This keeps
// IgnoreIfMissing semantics consistent with the actual rule
// submission: A missing path yields ENOENT, while symlinks are
// followed just like the kernel would follow them.
func checkPathExists(path string) error {
	fd, err := syscall.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}

// isAncestor reports whether ancestor is parent itself or a parent
// directory of parent in the lexical path hierarchy.
func isAncestor(ancestor, parent string) bool {
	if ancestor == parent {
		return true
	}
	return len(ancestor) < len(parent) &&
		parent[:len(ancestor)+1] == ancestor+string(filepath.Separator)
}

// isStrictAncestor reports whether ancestor is a parent directory of
// parent, excluding parent itself. Rules on the same path combine as
// a union, so only strictly enclosing paths can withhold rights.
func isStrictAncestor(ancestor, parent string) bool {
	return ancestor != parent && isAncestor(ancestor, parent)
}

// checkOverlappingPathRules verifies that no nested filesystem rule
// requests access rights which an ancestor rule withholds.
//
// Landlock combines the rules covering an object as a conjunction:
// An access right is granted below a path only if every rule on an
// ancestor path grants it. Granting e.g. read-only access on a
// directory and read-write access on a subdirectory therefore never
// grants any write access on the subdirectory and is rejected up
// front, instead of failing with EPERM/EACCES only after the
// Landlock domain got enforced.
//
// Rules on non-overlapping paths do not constrain each other, and
// rules with identical effective access rights on nested paths remain
// valid.
func checkOverlappingPathRules(rules []Rule, c Config) error {
	pathRules := collectPathRules(rules, c)

	for _, child := range pathRules {
		var ancestorAccess AccessFSSet
		hasAncestor := false
		for _, ancestor := range pathRules {
			if !isStrictAncestor(ancestor.path, child.path) {
				continue
			}
			hasAncestor = true
			ancestorAccess = ancestorAccess.union(ancestor.access)
		}
		if !hasAncestor {
			continue
		}
		if missing := child.access &^ ancestorAccess; missing != 0 {
			return fmt.Errorf("%w: path %q requires %v, but an ancestor path only grants %v",
				errOverlappingPathRules, child.path, child.access, ancestorAccess)
		}
	}
	return nil
}
