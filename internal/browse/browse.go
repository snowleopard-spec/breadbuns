// Package browse implements a small arrow-key folder browser used to pick
// a target directory, as a friendlier alternative to typing `cd` paths.
package browse

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ErrCancelled is returned by Pick when the user quits without choosing a
// folder.
var ErrCancelled = errors.New("browse: cancelled")

type model struct {
	cwd       string
	dirs      []string
	hasParent bool
	cursor    int
	err       error
	selected  string
	cancelled bool
}

func newModel(start string) *model {
	m := &model{cwd: start}
	m.reload()
	return m
}

func (m *model) reload() {
	m.err = nil
	m.cursor = 0
	entries, err := os.ReadDir(m.cwd)
	if err != nil {
		m.err = err
		m.dirs = nil
	} else {
		var dirs []string
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				dirs = append(dirs, e.Name())
			}
		}
		sort.Strings(dirs)
		m.dirs = dirs
	}
	parent := filepath.Dir(m.cwd)
	m.hasParent = parent != m.cwd
}

func (m *model) itemCount() int {
	n := 1 // "use this folder"
	if m.hasParent {
		n++
	}
	return n + len(m.dirs)
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch keyMsg.String() {
	case "ctrl+c", "q", "esc":
		m.cancelled = true
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < m.itemCount()-1 {
			m.cursor++
		}
	case "~":
		if home, err := os.UserHomeDir(); err == nil {
			m.cwd = home
			m.reload()
		}
	case "backspace", "left", "u":
		if m.hasParent {
			m.cwd = filepath.Dir(m.cwd)
			m.reload()
		}
	case "enter", " ", "right":
		idx := m.cursor
		if idx == 0 {
			m.selected = m.cwd
			return m, tea.Quit
		}
		idx--
		if m.hasParent {
			if idx == 0 {
				m.cwd = filepath.Dir(m.cwd)
				m.reload()
				return m, nil
			}
			idx--
		}
		if idx >= 0 && idx < len(m.dirs) {
			m.cwd = filepath.Join(m.cwd, m.dirs[idx])
			m.reload()
		}
	}
	return m, nil
}

func (m *model) View() string {
	var b strings.Builder
	b.WriteString("breadbuns — choose a folder\n\n")
	fmt.Fprintf(&b, "  %s\n\n", m.cwd)

	if m.err != nil {
		fmt.Fprintf(&b, "  (cannot read this directory: %v)\n\n", m.err)
	}

	line := func(i int, text string) {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}
		b.WriteString(prefix + text + "\n")
	}

	line(0, "[ Use this folder ]")
	idx := 1
	if m.hasParent {
		line(idx, ".. (parent directory)")
		idx++
	}
	for _, d := range m.dirs {
		line(idx, d+"/")
		idx++
	}

	b.WriteString("\n↑/↓ move   enter select/open folder   backspace up a level   ~ home   q cancel\n")
	return b.String()
}

// Pick launches an interactive, arrow-key-driven folder browser starting at
// start and returns the folder the user chose, or ErrCancelled if they quit
// without picking one.
func Pick(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		abs = start
	}
	m := newModel(abs)
	p := tea.NewProgram(m, tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		return "", err
	}
	fm := final.(*model)
	if fm.cancelled || fm.selected == "" {
		return "", ErrCancelled
	}
	return fm.selected, nil
}
