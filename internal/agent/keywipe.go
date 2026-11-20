package agent

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Some hosting providers leave their install script behind with a timer
// or cron job. Hostkey's firstscript.sh, for one, empties root's
// authorized_keys and is meant to delete itself after one run; when it
// hangs it never does, and runs again every hour, taking the panel's key
// with it (the desktop app then asks for the root password again and
// again). The agent looks for scheduled scripts that empty or delete that
// file and reports them, so the panel can tell the owner.

// keyWipe matches a command that empties or deletes authorized_keys:
// "> file" (not ">> file", which appends), truncate, rm, cp /dev/null.
var keyWipe = regexp.MustCompile(`(?:(?:^|[^>0-9&])>\s*|truncate\s+(?:-s\s*0\s+)?|rm\s+(?:-\w+\s+)*|cp\s+/dev/null\s+)["']?(?:/root|~|\$HOME|\$\{HOME\})/\.ssh/authorized_keys\b`)

// scriptPath: absolute paths in a command line.
var scriptPath = regexp.MustCompile(`/[\w.+\-/]+`)

const maxScript = 256 << 10

// Where scheduled jobs live; vars for the tests.
var (
	unitDirs  = []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}
	cronFiles = []string{"/etc/crontab", "/var/spool/cron/crontabs/root", "/var/spool/cron/root", "/etc/rc.local"}
	cronDirs  = []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily"}
)

// keyWipers caches findKeyWipers for keyWipersEvery: the status is
// gathered often, the scan reads a few hundred unit files.
var keyWipers struct {
	mu   sync.Mutex
	at   time.Time
	list []string
}

const keyWipersEvery = 10 * time.Minute

func cachedKeyWipers(now time.Time) []string {
	keyWipers.mu.Lock()
	defer keyWipers.mu.Unlock()
	if keyWipers.at.IsZero() || now.Sub(keyWipers.at) >= keyWipersEvery {
		keyWipers.list, keyWipers.at = findKeyWipers(), now
	}
	return keyWipers.list
}

// findKeyWipers returns "job → script" for each scheduled job (systemd
// timer or boot service, cron) whose command or script empties root's
// authorized_keys.
func findKeyWipers() []string {
	seen := map[string]bool{}
	var out []string
	note := func(job, script string) {
		k := job + " → " + script
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	check := func(job, cmd string) {
		if keyWipe.MatchString(cmd) {
			note(job, strings.TrimSpace(cmd))
			return
		}
		for _, p := range scriptPath.FindAllString(cmd, -1) {
			if wipes(p) {
				note(job, p)
			}
		}
	}
	for _, dir := range unitDirs {
		units, _ := filepath.Glob(filepath.Join(dir, "*.service"))
		for _, u := range units {
			name := filepath.Base(u)
			// Only what runs by itself: a timer's service, or one started
			// at boot (WantedBy). Ordinary daemons are left alone.
			timer := strings.TrimSuffix(u, ".service") + ".timer"
			b, err := os.ReadFile(u)
			if err != nil || len(b) > maxScript {
				continue
			}
			if !exists(timer) && !bytes.Contains(b, []byte("WantedBy=")) {
				continue
			}
			if exists(timer) {
				name = filepath.Base(timer)
			}
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				for _, key := range []string{"ExecStart=", "ExecStartPre=", "ExecStartPost="} {
					if strings.HasPrefix(line, key) {
						check(name, strings.TrimPrefix(line, key))
					}
				}
			}
		}
	}
	files := append([]string{}, cronFiles...)
	for _, dir := range cronDirs {
		m, _ := filepath.Glob(filepath.Join(dir, "*"))
		files = append(files, m...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || len(b) > maxScript || bytes.IndexByte(b, 0) >= 0 {
			continue
		}
		job := f
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			check(job, line)
		}
	}
	sort.Strings(out)
	return out
}

// wipes tells whether the text file at p (a script) empties root's
// authorized_keys.
func wipes(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxScript {
		return false
	}
	b, err := os.ReadFile(p)
	if err != nil || bytes.IndexByte(b, 0) >= 0 { // a binary
		return false
	}
	return keyWipe.Match(b)
}
