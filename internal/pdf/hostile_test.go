package pdf

import (
	"strings"
	"testing"
)

// A file nested far deeper than any real PDF must fail with an error, not
// overflow the stack.
func TestDeepNestingIsRejected(t *testing.T) {
	const levels = 100000
	src := strings.Repeat("[", levels) + strings.Repeat("]", levels)
	p := &parser{data: []byte(src)}
	if _, err := p.parseObject(); err != errTooDeep {
		t.Fatalf("expected errTooDeep, got %v", err)
	}

	src = strings.Repeat("<</K ", levels) + "1" + strings.Repeat(">>", levels)
	p = &parser{data: []byte(src)}
	if _, err := p.parseObject(); err != errTooDeep {
		t.Fatalf("expected errTooDeep for dicts, got %v", err)
	}

	// Realistic nesting must still parse.
	src = strings.Repeat("[", 50) + "1" + strings.Repeat("]", 50)
	p = &parser{data: []byte(src)}
	if _, err := p.parseObject(); err != nil {
		t.Fatalf("50 levels should parse: %v", err)
	}
}

// Cross-reference offsets come from the file itself; ones that point outside
// the file must resolve to nothing rather than index out of bounds.
func TestOutOfRangeXrefOffsets(t *testing.T) {
	d := &Document{
		data:        []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"),
		xref:        map[int]xrefEntry{1: {offset: -5}, 2: {offset: 1 << 40}, 3: {inStream: true, streamNum: 2}},
		trailer:     Dict{},
		objCache:    map[int]interface{}{},
		objGenCache: map[int]int{},
		objStmCache: map[int]map[int]interface{}{},
	}
	for _, n := range []int{1, 2, 3} {
		if v := d.Resolve(Ref{Num: n}); v != nil {
			t.Fatalf("object %d with bad offset resolved to %#v", n, v)
		}
	}
}
