//go:build linux

package landlock

import (
	"errors"
	"os"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestOverlappingPathRulesDetection(t *testing.T) {
	cfg := Config{HandledAccessFS: accessFSReadWrite}

	for _, tc := range []struct {
		name      string
		rules     []Rule
		wantError bool
	}{
		{
			name: "RO ancestor with RW descendant is unsatisfiable",
			rules: []Rule{
				RODirs("/tmp/root"),
				RWDirs("/tmp/root/sub"),
			},
			wantError: true,
		},
		{
			name: "RW ancestor with RW descendant is fine",
			rules: []Rule{
				RWDirs("/tmp/root"),
				RWDirs("/tmp/root/sub"),
			},
		},
		{
			name: "RO ancestor with RO descendant is fine",
			rules: []Rule{
				RODirs("/tmp/root"),
				RODirs("/tmp/root/sub"),
			},
		},
		{
			name: "Non-overlapping paths do not constrain each other",
			rules: []Rule{
				RODirs("/tmp/ro"),
				RWDirs("/tmp/rw"),
			},
		},
		{
			name: "Path prefix without directory boundary is not an ancestor",
			rules: []Rule{
				RODirs("/tmp/root"),
				RWDirs("/tmp/rootbeer"),
			},
		},
		{
			name: "Equal paths union their access rights",
			rules: []Rule{
				PathAccess(ll.AccessFSReadFile, "/tmp/root"),
				PathAccess(ll.AccessFSReadFile|ll.AccessFSWriteFile, "/tmp/root"),
			},
		},
		{
			name: "Two RO ancestors together still withhold write from descendant",
			rules: []Rule{
				RODirs("/tmp/root"),
				RODirs("/tmp/root/mid"),
				RWDirs("/tmp/root/mid/sub"),
			},
			wantError: true,
		},
		{
			name: "PathAccess with extra rights inside a RO hierarchy is rejected",
			rules: []Rule{
				PathAccess(ll.AccessFSReadFile|ll.AccessFSReadDir, "/tmp/root"),
				PathAccess(ll.AccessFSReadFile|ll.AccessFSWriteFile, "/tmp/root/f"),
			},
			wantError: true,
		},
		{
			name: "Multiple paths in a single rule are all checked",
			rules: []Rule{
				RODirs("/tmp/root", "/tmp/other"),
				RWDirs("/tmp/root/sub"),
			},
			wantError: true,
		},
		{
			name: "Relative paths are handled like cleaned absolute paths",
			rules: []Rule{
				RODirs("root"),
				RWDirs("root/sub"),
			},
			wantError: true,
		},
		{
			name: "Trailing slashes and dot components do not change hierarchy",
			rules: []Rule{
				RODirs("/tmp/root/"),
				RWDirs("/tmp/root/./sub/"),
			},
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOverlappingPathRules(tc.rules, cfg)
			if tc.wantError && !errors.Is(err, errOverlappingPathRules) {
				t.Errorf("checkOverlappingPathRules: got %v, want errOverlappingPathRules", err)
			}
			if !tc.wantError && err != nil {
				t.Errorf("checkOverlappingPathRules: got unexpected error %v", err)
			}
		})
	}
}

func TestOverlappingPathRulesIgnoreIfMissing(t *testing.T) {
	cfg := Config{HandledAccessFS: accessFSReadWrite}

	t.Run("missing IgnoreIfMissing ancestor does not constrain descendant", func(t *testing.T) {
		err := checkOverlappingPathRules([]Rule{
			RODirs("/definitely/not/there/root").IgnoreIfMissing(),
			RWDirs("/definitely/not/there/root/sub").IgnoreIfMissing(),
		}, cfg)
		if err != nil {
			t.Errorf("checkOverlappingPathRules: got unexpected error %v", err)
		}
	})

	t.Run("existing IgnoreIfMissing ancestor still constrains descendant", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(dir+"/sub", 0o700); err != nil {
			t.Fatalf("os.Mkdir: %v", err)
		}
		err := checkOverlappingPathRules([]Rule{
			RODirs(dir).IgnoreIfMissing(),
			RWDirs(dir + "/sub").IgnoreIfMissing(),
		}, cfg)
		if !errors.Is(err, errOverlappingPathRules) {
			t.Errorf("checkOverlappingPathRules: got %v, want errOverlappingPathRules", err)
		}
	})
}

func TestOverlappingPathRulesInComposite(t *testing.T) {
	cfg := Config{HandledAccessFS: accessFSReadWrite}

	err := checkOverlappingPathRules([]Rule{
		CompositeRule(
			RODirs("/tmp/root"),
			CompositeRule(
				RWDirs("/tmp/root/sub"),
			),
		),
	}, cfg)
	if !errors.Is(err, errOverlappingPathRules) {
		t.Errorf("nested composite: got %v, want errOverlappingPathRules", err)
	}
}

func TestOverlappingPathRulesDowngradedRights(t *testing.T) {
	// The descendant only asks for rights which the V1 config does
	// not handle, so after best-effort downgrade it becomes a no-op
	// and must not be flagged.
	v1Cfg := V1
	err := checkOverlappingPathRules([]Rule{
		RWDirs("/tmp/root").intersectRights(v1Cfg.HandledAccessFS),
		RWDirs("/tmp/root/sub").intersectRights(AccessFSSet(ll.AccessFSTruncate)),
	}, v1Cfg)
	if err != nil {
		t.Errorf("checkOverlappingPathRules: got unexpected error %v", err)
	}
}

func TestCollectPathRulesFlattening(t *testing.T) {
	cfg := Config{HandledAccessFS: accessFSReadWrite}
	got := collectPathRules([]Rule{
		CompositeRule(
			RODirs("/a", "/b"),
			ConnectTCP(80),
			QuietPaths("/q"),
		),
		RWDirs("/a/c"),
	}, cfg)

	want := []pathRule{
		{path: "/a", access: accessFSRead},
		{path: "/b", access: accessFSRead},
		{path: "/a/c", access: accessFSReadWrite},
	}
	if len(got) != len(want) {
		t.Fatalf("collectPathRules: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("collectPathRules[%d]: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TestOverlappingPathRulesRejectedByCreateRuleset ensures that the
// check runs before the ruleset FD is created, so both Restrict and
// NewRulesetFD reject unsatisfiable rules up front.
func TestOverlappingPathRulesRejectedByCreateRuleset(t *testing.T) {
	for _, mode := range []struct {
		name string
		cfg  Config
	}{
		{name: "strict", cfg: Config{HandledAccessFS: accessFSReadWrite}},
		{name: "best_effort", cfg: Config{HandledAccessFS: accessFSReadWrite, bestEffort: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			fd, _, err := createRuleset(mode.cfg, abiInfos[3], []Rule{
				RODirs("/tmp/root"),
				RWDirs("/tmp/root/sub"),
			})
			if !errors.Is(err, errOverlappingPathRules) {
				t.Errorf("createRuleset: got %v, want errOverlappingPathRules", err)
			}
			if fd != -1 {
				t.Errorf("createRuleset: got fd %d, want -1", fd)
			}
		})
	}
}
