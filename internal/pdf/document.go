package pdf

import (
	"fmt"
	"os"
)

// Document is a parsed PDF file: enough structure to enumerate every
// indirect object and rewrite the document.
type Document struct {
	Version string // e.g. "1.7"

	data    []byte
	xref    map[int]xrefEntry
	trailer Dict

	objCache    map[int]interface{}
	objGenCache map[int]int
	objStmCache map[int]map[int]interface{} // streamObjNum -> (member obj num -> value)

	// streamDecrypt, when set, is applied to the raw bytes of object
	// streams before they are decoded. In an encrypted file the object
	// streams themselves are encrypted, so their members cannot be read
	// until the file key is known (see SetStreamDecryptor).
	streamDecrypt Transform
}

// Load reads and parses a PDF file from disk.
func Load(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses PDF file content already in memory.
func Parse(data []byte) (*Document, error) {
	version := "1.7"
	if len(data) >= 8 && string(data[0:5]) == "%PDF-" {
		version = string(data[5:8])
	}

	off := lastIndexOf(data, []byte("startxref"))
	if off < 0 {
		return nil, fmt.Errorf("pdf: no startxref found")
	}
	p := &parser{data: data, pos: off + len("startxref")}
	p.skipWhitespaceAndComments()
	startOffset, isInt, err := p.scanNumber()
	if err != nil || !isInt {
		return nil, fmt.Errorf("pdf: invalid startxref")
	}

	xref, trailer, err := loadXref(data, int64(startOffset))
	if err != nil {
		return nil, err
	}
	if trailer["Root"] == nil {
		return nil, fmt.Errorf("pdf: no /Root in trailer (unsupported or corrupt PDF)")
	}

	return &Document{
		Version:     version,
		data:        data,
		xref:        xref,
		trailer:     trailer,
		objCache:    map[int]interface{}{},
		objGenCache: map[int]int{},
		objStmCache: map[int]map[int]interface{}{},
	}, nil
}

func lastIndexOf(hay, needle []byte) int {
	for i := len(hay) - len(needle); i >= 0; i-- {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

// Trailer returns the merged trailer dictionary.
func (d *Document) Trailer() Dict { return d.trailer }

// IsEncrypted reports whether the document's trailer declares an /Encrypt
// dictionary.
func (d *Document) IsEncrypted() bool {
	_, ok := d.trailer["Encrypt"]
	return ok
}

// EncryptDict resolves and returns the /Encrypt dictionary, if any.
func (d *Document) EncryptDict() (Dict, bool) {
	v, ok := d.trailer["Encrypt"]
	if !ok {
		return nil, false
	}
	resolved := d.Resolve(v)
	dict, ok := resolved.(Dict)
	return dict, ok
}

// SetStreamDecryptor installs fn as the decryptor for object-stream data and
// discards any objects cached so far, so that members of (encrypted)
// object streams can be read. Call it after authenticating the password.
func (d *Document) SetStreamDecryptor(fn Transform) {
	d.streamDecrypt = fn
	d.objCache = map[int]interface{}{}
	d.objGenCache = map[int]int{}
	d.objStmCache = map[int]map[int]interface{}{}
}

// InObjectStream reports whether object num is stored inside an object
// stream (as opposed to directly in the file body).
func (d *Document) InObjectStream(num int) bool {
	entry, ok := d.xref[num]
	return ok && entry.inStream
}

// Resolve follows an indirect reference to its value; non-reference values
// are returned unchanged.
func (d *Document) Resolve(obj interface{}) interface{} {
	ref, ok := obj.(Ref)
	if !ok {
		return obj
	}
	return d.get(ref.Num)
}

func (d *Document) get(num int) interface{} {
	if v, ok := d.objCache[num]; ok {
		return v
	}
	entry, ok := d.xref[num]
	if !ok {
		return nil
	}
	var val interface{}
	if entry.inStream {
		val = d.getFromObjStream(entry.streamNum, num)
		d.objGenCache[num] = 0
	} else if !d.validOffset(entry.offset) {
		val = nil
	} else {
		p := &parser{data: d.data, pos: int(entry.offset)}
		n, g, v, err := p.parseIndirectObject()
		if err != nil || n != num {
			val = nil
		} else {
			val = v
			d.objGenCache[num] = g
		}
	}
	d.objCache[num] = val
	return val
}

// validOffset reports whether a byte offset taken from the file's own
// cross-reference data actually lies inside the file. Offsets are untrusted
// input: a corrupt or hostile xref must not send the parser out of bounds.
func (d *Document) validOffset(off int64) bool {
	return off >= 0 && off < int64(len(d.data))
}

func (d *Document) getFromObjStream(streamNum, wantNum int) interface{} {
	members, ok := d.objStmCache[streamNum]
	if !ok {
		members = d.decodeObjStream(streamNum)
		d.objStmCache[streamNum] = members
	}
	return members[wantNum]
}

func (d *Document) decodeObjStream(streamNum int) map[int]interface{} {
	out := map[int]interface{}{}
	entry, ok := d.xref[streamNum]
	if !ok || entry.inStream || !d.validOffset(entry.offset) {
		return out
	}
	p := &parser{data: d.data, pos: int(entry.offset)}
	_, _, obj, err := p.parseIndirectObject()
	if err != nil {
		return out
	}
	s, ok := obj.(*Stream)
	if !ok {
		return out
	}
	if d.streamDecrypt != nil {
		plain, err := d.streamDecrypt(s.Data)
		if err != nil {
			return out
		}
		s = &Stream{Dict: s.Dict, Data: plain}
	}
	raw, err := decodeStreamForStructure(s)
	if err != nil {
		return out
	}
	n := dictInt(s.Dict, "N", 0)
	first := dictInt(s.Dict, "First", 0)

	hp := &parser{data: raw, pos: 0}
	type pair struct{ num, off int }
	pairs := make([]pair, 0, n)
	for i := 0; i < n; i++ {
		hp.skipWhitespaceAndComments()
		numVal, _, err := hp.scanNumber()
		if err != nil {
			break
		}
		hp.skipWhitespaceAndComments()
		offVal, _, err := hp.scanNumber()
		if err != nil {
			break
		}
		pairs = append(pairs, pair{int(numVal), int(offVal)})
	}
	for _, pr := range pairs {
		pos := first + pr.off
		if pos < 0 || pos > len(raw) {
			continue
		}
		op := &parser{data: raw, pos: pos}
		v, err := op.parseObject()
		if err != nil {
			continue
		}
		out[pr.num] = v
	}
	return out
}

// AllObjects returns every "real" indirect object number in the document,
// i.e. excluding cross-reference streams, object-stream containers (whose
// members are already included individually), any linearization
// dictionary, and the /Encrypt dictionary itself (which per spec is never
// encrypted/decrypted and must not be swept up by a content transform).
// Object streams are effectively flattened.
func (d *Document) AllObjects() []int {
	skip := -1
	if ref, ok := d.trailer["Encrypt"].(Ref); ok {
		skip = ref.Num
	}
	var nums []int
	for num, entry := range d.xref {
		if num == skip {
			continue
		}
		if entry.inStream {
			nums = append(nums, num)
			continue
		}
		val := d.get(num)
		if s, ok := val.(*Stream); ok {
			if t, _ := s.Dict["Type"].(Name); t == "XRef" || t == "ObjStm" {
				continue
			}
		}
		// A linearization dictionary describes byte offsets of the file it
		// was written in; since we rewrite the file it would be stale (and
		// misleading to readers), so drop it.
		if dict, ok := val.(Dict); ok {
			if _, linearized := dict["Linearized"]; linearized {
				continue
			}
		}
		nums = append(nums, num)
	}
	return nums
}

// GenOf returns the generation number recorded for an object (0 for
// objects inside object streams, which are always generation 0).
func (d *Document) GenOf(num int) int {
	d.get(num) // ensure cache populated
	return d.objGenCache[num]
}
