package pdf

import (
	"fmt"
)

type xrefEntry struct {
	inStream      bool
	offset        int64
	gen           int
	streamNum     int
	indexInStream int
}

// loadXref walks the classic-table / xref-stream chain starting at
// startOffset, following /Prev (and /XRefStm for hybrid files), and returns
// the merged object locations plus the merged trailer (first-seen key wins,
// since we walk from newest revision to oldest).
func loadXref(data []byte, startOffset int64) (map[int]xrefEntry, Dict, error) {
	xref := map[int]xrefEntry{}
	trailer := Dict{}
	seen := map[int64]bool{}

	var walk func(offset int64) error
	walk = func(offset int64) error {
		if offset < 0 || offset >= int64(len(data)) || seen[offset] {
			return nil
		}
		seen[offset] = true

		p := &parser{data: data, pos: int(offset)}
		p.skipWhitespaceAndComments()
		if p.matchKeyword("xref") {
			t, prev, xrefStm, err := parseClassicXref(p, xref)
			if err != nil {
				return err
			}
			mergeTrailer(trailer, t)
			if xrefStm >= 0 {
				if err := walk(xrefStm); err != nil {
					return err
				}
			}
			if prev >= 0 {
				return walk(prev)
			}
			return nil
		}

		// Otherwise this should be an indirect object holding a
		// cross-reference stream.
		_, _, obj, err := p.parseIndirectObject()
		if err != nil {
			return fmt.Errorf("pdf: parsing xref stream at %d: %w", offset, err)
		}
		s, ok := obj.(*Stream)
		if !ok {
			return fmt.Errorf("pdf: expected xref stream at %d", offset)
		}
		t, err := parseXrefStream(s, xref)
		if err != nil {
			return err
		}
		mergeTrailer(trailer, t)
		if prev, ok := staticInt(t["Prev"]); ok {
			return walk(int64(prev))
		}
		return nil
	}

	if err := walk(startOffset); err != nil {
		return nil, nil, err
	}
	return xref, trailer, nil
}

func mergeTrailer(dst, src Dict) {
	for k, v := range src {
		if _, exists := dst[k]; !exists {
			dst[k] = v
		}
	}
}

// parseClassicXref parses "xref\n<subsections>\ntrailer\n<<...>>" and
// returns the trailer, /Prev offset (-1 if absent), and /XRefStm offset
// (-1 if absent). Entries are added to xref only if not already present.
func parseClassicXref(p *parser, xref map[int]xrefEntry) (Dict, int64, int64, error) {
	for {
		p.skipWhitespaceAndComments()
		if p.matchKeyword("trailer") {
			break
		}
		if b, ok := p.peekByte(); !ok || !(b >= '0' && b <= '9') {
			break
		}
		start, isInt, err := p.scanNumber()
		if err != nil || !isInt {
			return nil, -1, -1, fmt.Errorf("pdf: bad xref subsection header")
		}
		p.skipWhitespaceAndComments()
		count, isInt, err := p.scanNumber()
		if err != nil || !isInt {
			return nil, -1, -1, fmt.Errorf("pdf: bad xref subsection header")
		}
		for i := 0; i < int(count); i++ {
			p.skipWhitespaceAndComments()
			offVal, ok1, err := p.scanNumber()
			if err != nil {
				return nil, -1, -1, err
			}
			p.skipWhitespaceAndComments()
			genVal, ok2, err := p.scanNumber()
			if err != nil {
				return nil, -1, -1, err
			}
			p.skipWhitespaceAndComments()
			kind, _ := p.peekByte()
			if kind == 'n' || kind == 'f' {
				p.pos++
			}
			if !ok1 || !ok2 {
				continue
			}
			num := int(start) + i
			if kind == 'n' {
				if _, exists := xref[num]; !exists {
					xref[num] = xrefEntry{offset: int64(offVal), gen: int(genVal)}
				}
			}
		}
	}
	obj, err := p.parseObject()
	if err != nil {
		return nil, -1, -1, err
	}
	trailer, ok := obj.(Dict)
	if !ok {
		return nil, -1, -1, fmt.Errorf("pdf: expected trailer dictionary")
	}
	prev := int64(-1)
	if n, ok := staticInt(trailer["Prev"]); ok {
		prev = int64(n)
	}
	xrefStm := int64(-1)
	if n, ok := staticInt(trailer["XRefStm"]); ok {
		xrefStm = int64(n)
	}
	return trailer, prev, xrefStm, nil
}

// parseXrefStream decodes a cross-reference stream object and adds its
// entries to xref (only if not already present), returning its dict as the
// trailer for this revision.
func parseXrefStream(s *Stream, xref map[int]xrefEntry) (Dict, error) {
	raw, err := decodeStreamForStructure(s)
	if err != nil {
		return nil, err
	}
	wArr, ok := s.Dict["W"].(Array)
	if !ok || len(wArr) < 3 {
		return nil, fmt.Errorf("pdf: xref stream missing /W")
	}
	w := make([]int, 3)
	for i := 0; i < 3; i++ {
		n, _ := staticInt(wArr[i])
		w[i] = n
	}
	size, _ := staticInt(s.Dict["Size"])
	var index []int
	if idxArr, ok := s.Dict["Index"].(Array); ok {
		for _, e := range idxArr {
			n, _ := staticInt(e)
			index = append(index, n)
		}
	} else {
		index = []int{0, size}
	}

	recLen := w[0] + w[1] + w[2]
	pos := 0
	for si := 0; si+1 < len(index); si += 2 {
		startNum := index[si]
		count := index[si+1]
		for i := 0; i < count; i++ {
			if pos+recLen > len(raw) {
				break
			}
			f1 := readField(raw[pos:pos+w[0]], w[0], 1)
			f2 := readField(raw[pos+w[0]:pos+w[0]+w[1]], w[1], 0)
			f3 := readField(raw[pos+w[0]+w[1]:pos+recLen], w[2], 0)
			pos += recLen
			num := startNum + i
			if _, exists := xref[num]; exists {
				continue
			}
			switch f1 {
			case 1:
				xref[num] = xrefEntry{offset: f2, gen: int(f3)}
			case 2:
				xref[num] = xrefEntry{inStream: true, streamNum: int(f2), indexInStream: int(f3)}
			}
		}
	}
	return s.Dict, nil
}

// readField reads a big-endian field of the given byte width, defaulting to
// def when width is 0 (per spec, meaning "use the default value").
func readField(b []byte, width int, def int64) int64 {
	if width == 0 {
		return def
	}
	var v int64
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v
}
