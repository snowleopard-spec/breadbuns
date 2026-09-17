package pdf

import (
	"errors"
	"fmt"
	"strconv"
)

var errEOF = errors.New("pdf: unexpected end of input")

// parser is a recursive-descent reader over the raw file bytes.
type parser struct {
	data []byte
	pos  int
}

func isWhitespace(b byte) bool {
	switch b {
	case 0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20:
		return true
	}
	return false
}

func isDelimiter(b byte) bool {
	switch b {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func (p *parser) eof() bool { return p.pos >= len(p.data) }

func (p *parser) skipWhitespaceAndComments() {
	for !p.eof() {
		b := p.data[p.pos]
		if isWhitespace(b) {
			p.pos++
			continue
		}
		if b == '%' {
			for !p.eof() && p.data[p.pos] != '\n' && p.data[p.pos] != '\r' {
				p.pos++
			}
			continue
		}
		break
	}
}

func (p *parser) peekByte() (byte, bool) {
	if p.eof() {
		return 0, false
	}
	return p.data[p.pos], true
}

// matchKeyword tries to consume the given ASCII keyword at the current
// position (must not be followed by another regular character).
func (p *parser) matchKeyword(kw string) bool {
	end := p.pos + len(kw)
	if end > len(p.data) {
		return false
	}
	if string(p.data[p.pos:end]) != kw {
		return false
	}
	if end < len(p.data) {
		nb := p.data[end]
		if !isWhitespace(nb) && !isDelimiter(nb) {
			return false
		}
	}
	p.pos = end
	return true
}

// parseObject parses a single PDF object at the current position (a value,
// not a "N G obj" wrapper).
func (p *parser) parseObject() (interface{}, error) {
	p.skipWhitespaceAndComments()
	if p.eof() {
		return nil, errEOF
	}
	b := p.data[p.pos]
	switch {
	case b == '/':
		return p.parseName()
	case b == '(':
		return p.parseLiteralString()
	case b == '<':
		if p.pos+1 < len(p.data) && p.data[p.pos+1] == '<' {
			return p.parseDictOrStream()
		}
		return p.parseHexString()
	case b == '[':
		return p.parseArray()
	case b == '-' || b == '+' || b == '.' || (b >= '0' && b <= '9'):
		return p.parseNumberOrRef()
	default:
		save := p.pos
		if p.matchKeyword("true") {
			return true, nil
		}
		p.pos = save
		if p.matchKeyword("false") {
			return false, nil
		}
		p.pos = save
		if p.matchKeyword("null") {
			return nil, nil
		}
		return nil, fmt.Errorf("pdf: unexpected byte %q at offset %d", b, p.pos)
	}
}

func (p *parser) parseName() (Name, error) {
	p.pos++ // consume '/'
	start := p.pos
	var buf []byte
	for !p.eof() {
		b := p.data[p.pos]
		if isWhitespace(b) || isDelimiter(b) {
			break
		}
		if b == '#' && p.pos+2 < len(p.data) && isHex(p.data[p.pos+1]) && isHex(p.data[p.pos+2]) {
			if buf == nil {
				buf = append(buf, p.data[start:p.pos]...)
			}
			v := hexVal(p.data[p.pos+1])<<4 | hexVal(p.data[p.pos+2])
			buf = append(buf, v)
			p.pos += 3
			continue
		}
		if buf != nil {
			buf = append(buf, b)
		}
		p.pos++
	}
	if buf != nil {
		return Name(buf), nil
	}
	return Name(p.data[start:p.pos]), nil
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hexVal(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}

func (p *parser) parseLiteralString() (String, error) {
	p.pos++ // consume '('
	depth := 1
	var buf []byte
	for !p.eof() {
		b := p.data[p.pos]
		switch b {
		case '\\':
			p.pos++
			if p.eof() {
				break
			}
			e := p.data[p.pos]
			switch e {
			case 'n':
				buf = append(buf, '\n')
				p.pos++
			case 'r':
				buf = append(buf, '\r')
				p.pos++
			case 't':
				buf = append(buf, '\t')
				p.pos++
			case 'b':
				buf = append(buf, '\b')
				p.pos++
			case 'f':
				buf = append(buf, '\f')
				p.pos++
			case '(', ')', '\\':
				buf = append(buf, e)
				p.pos++
			case '\r':
				p.pos++
				if !p.eof() && p.data[p.pos] == '\n' {
					p.pos++
				}
			case '\n':
				p.pos++
			default:
				if e >= '0' && e <= '7' {
					n := 0
					for i := 0; i < 3 && !p.eof() && p.data[p.pos] >= '0' && p.data[p.pos] <= '7'; i++ {
						n = n*8 + int(p.data[p.pos]-'0')
						p.pos++
					}
					buf = append(buf, byte(n))
				} else {
					buf = append(buf, e)
					p.pos++
				}
			}
		case '(':
			depth++
			buf = append(buf, b)
			p.pos++
		case ')':
			depth--
			p.pos++
			if depth == 0 {
				return String{Bytes: buf}, nil
			}
			buf = append(buf, b)
		default:
			buf = append(buf, b)
			p.pos++
		}
	}
	return String{}, errEOF
}

func (p *parser) parseHexString() (String, error) {
	p.pos++ // consume '<'
	var digits []byte
	for !p.eof() {
		b := p.data[p.pos]
		if b == '>' {
			p.pos++
			if len(digits)%2 == 1 {
				digits = append(digits, '0')
			}
			out := make([]byte, len(digits)/2)
			for i := 0; i < len(out); i++ {
				out[i] = hexVal(digits[2*i])<<4 | hexVal(digits[2*i+1])
			}
			return String{Bytes: out}, nil
		}
		if isHex(b) {
			digits = append(digits, b)
		}
		p.pos++
	}
	return String{}, errEOF
}

func (p *parser) parseArray() (Array, error) {
	p.pos++ // consume '['
	var arr Array
	for {
		p.skipWhitespaceAndComments()
		if p.eof() {
			return nil, errEOF
		}
		if p.data[p.pos] == ']' {
			p.pos++
			return arr, nil
		}
		obj, err := p.parseObject()
		if err != nil {
			return nil, err
		}
		arr = append(arr, obj)
	}
}

func (p *parser) parseDictOrStream() (interface{}, error) {
	p.pos += 2 // consume '<<'
	d := Dict{}
	for {
		p.skipWhitespaceAndComments()
		if p.eof() {
			return nil, errEOF
		}
		if p.data[p.pos] == '>' {
			p.pos++
			if !p.eof() && p.data[p.pos] == '>' {
				p.pos++
			}
			break
		}
		if p.data[p.pos] != '/' {
			return nil, fmt.Errorf("pdf: expected name key in dict at offset %d", p.pos)
		}
		key, err := p.parseName()
		if err != nil {
			return nil, err
		}
		val, err := p.parseObject()
		if err != nil {
			return nil, err
		}
		d[key] = val
	}

	save := p.pos
	p.skipWhitespaceAndComments()
	if p.matchKeyword("stream") {
		// Per spec: "stream" is followed by CRLF or LF (not bare CR).
		if !p.eof() && p.data[p.pos] == '\r' {
			p.pos++
		}
		if !p.eof() && p.data[p.pos] == '\n' {
			p.pos++
		}
		dataStart := p.pos
		length, ok := staticInt(d["Length"])
		var dataEnd int
		if ok && dataStart+length <= len(p.data) {
			dataEnd = dataStart + length
			// Sanity-check: "endstream" should appear shortly after.
			probe := parser{data: p.data, pos: dataEnd}
			probe.skipWhitespaceAndComments()
			if !probe.matchKeyword("endstream") {
				dataEnd = -1
			}
		} else {
			dataEnd = -1
		}
		if dataEnd < 0 {
			// /Length was indirect, wrong, or missing: scan for "endstream".
			idx := indexOf(p.data, dataStart, []byte("endstream"))
			if idx < 0 {
				return nil, errEOF
			}
			dataEnd = idx
			// Trim a single trailing EOL that precedes "endstream".
			if dataEnd > dataStart && p.data[dataEnd-1] == '\n' {
				dataEnd--
				if dataEnd > dataStart && p.data[dataEnd-1] == '\r' {
					dataEnd--
				}
			}
		}
		data := p.data[dataStart:dataEnd]
		p.pos = dataEnd
		p.skipWhitespaceAndComments()
		p.matchKeyword("endstream")
		return &Stream{Dict: d, Data: data}, nil
	}
	p.pos = save
	return d, nil
}

func indexOf(hay []byte, from int, needle []byte) int {
	if from < 0 || from > len(hay) {
		return -1
	}
	for i := from; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

// staticInt returns v as an int if it's directly an integer (not an
// indirect reference that needs resolving via a Document).
func staticInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

func (p *parser) parseNumberOrRef() (interface{}, error) {
	start := p.pos
	num, isInt, err := p.scanNumber()
	if err != nil {
		return nil, err
	}
	if isInt && num >= 0 {
		save := p.pos
		p.skipWhitespaceAndComments()
		genStart := p.pos
		if !p.eof() && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			gen, isGenInt, gerr := p.scanNumber()
			if gerr == nil && isGenInt && gen >= 0 {
				afterGen := p.pos
				p.skipWhitespaceAndComments()
				if !p.eof() && p.data[p.pos] == 'R' {
					next := p.pos + 1
					if next >= len(p.data) || isWhitespace(p.data[next]) || isDelimiter(p.data[next]) {
						p.pos = next
						return Ref{Num: int(num), Gen: int(gen)}, nil
					}
				}
				_ = afterGen
			}
		}
		p.pos = save
		_ = genStart
	}
	_ = start
	if isInt {
		return int64(num), nil
	}
	return float64(num), nil
}

// scanNumber scans a PDF numeric token and reports whether it was a pure
// integer (no '.' and no exponent).
func (p *parser) scanNumber() (float64, bool, error) {
	start := p.pos
	if !p.eof() && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
		p.pos++
	}
	isInt := true
	for !p.eof() {
		b := p.data[p.pos]
		if b >= '0' && b <= '9' {
			p.pos++
			continue
		}
		if b == '.' {
			isInt = false
			p.pos++
			continue
		}
		break
	}
	text := string(p.data[start:p.pos])
	if text == "" || text == "-" || text == "+" {
		return 0, false, fmt.Errorf("pdf: invalid number at offset %d", start)
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, false, err
	}
	return f, isInt, nil
}

// parseIndirectObject parses "N G obj ... endobj" starting at pos and
// returns the object number, generation, and value.
func (p *parser) parseIndirectObject() (num, gen int, obj interface{}, err error) {
	p.skipWhitespaceAndComments()
	n, isInt, err := p.scanNumber()
	if err != nil || !isInt {
		return 0, 0, nil, fmt.Errorf("pdf: expected object number: %w", err)
	}
	p.skipWhitespaceAndComments()
	g, isInt, err := p.scanNumber()
	if err != nil || !isInt {
		return 0, 0, nil, fmt.Errorf("pdf: expected generation number: %w", err)
	}
	p.skipWhitespaceAndComments()
	if !p.matchKeyword("obj") {
		return 0, 0, nil, fmt.Errorf("pdf: expected 'obj' keyword at offset %d", p.pos)
	}
	val, err := p.parseObject()
	if err != nil {
		return 0, 0, nil, err
	}
	p.skipWhitespaceAndComments()
	p.matchKeyword("endobj")
	return int(n), int(g), val, nil
}
