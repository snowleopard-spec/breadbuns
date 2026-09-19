package pdf

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"
	"strconv"
)

// Transform is applied to the raw bytes of every string and every stream's
// data while rewriting a document (used to encrypt or decrypt content).
type Transform func(data []byte) ([]byte, error)

// WriteOptions controls how Write re-serializes a document.
type WriteOptions struct {
	// Transform, if non-nil, is applied to every literal string and every
	// stream's bytes in the document.
	Transform Transform
	// EncryptDict, if non-nil, is written as a new top-level object and
	// referenced from the trailer's /Encrypt entry. If nil, the output
	// trailer has no /Encrypt entry at all.
	EncryptDict Dict
}

// Write re-serializes doc as a brand-new, classically-cross-referenced PDF
// file, applying opts.Transform to every string/stream along the way.
func Write(doc *Document, opts WriteOptions) ([]byte, error) {
	nums := doc.AllObjects()
	sort.Ints(nums)

	// Per ISO 32000-2 §7.6.3.2, when the /Encrypt dictionary carries
	// /EncryptMetadata false the document-level XMP metadata stream is
	// stored in the clear and must be neither decrypted nor re-encrypted.
	plainMetadata := false
	if enc, ok := doc.EncryptDict(); ok {
		if v, ok := enc["EncryptMetadata"].(bool); ok && !v {
			plainMetadata = true
		}
	}
	skipStreamData := func(s *Stream) bool {
		if plainMetadata {
			if t, _ := s.Dict["Type"].(Name); t == "Metadata" {
				return true
			}
		}
		return hasIdentityCryptFilter(s)
	}

	type outObj struct {
		num, gen int
		val      interface{}
	}
	objs := make([]outObj, 0, len(nums)+1)
	maxNum := 0
	for _, num := range nums {
		if num > maxNum {
			maxNum = num
		}
		val := doc.Resolve(Ref{Num: num})
		if val == nil {
			continue
		}
		cloned := Clone(val)
		fn := opts.Transform
		// When the source document is encrypted, members of object streams
		// were never individually encrypted (only the enclosing stream was,
		// and that has already been decrypted to read them), so their
		// strings must be copied through untouched.
		if fn != nil && doc.IsEncrypted() && doc.InObjectStream(num) {
			fn = nil
		}
		transformed, err := transformObject(cloned, fn, skipStreamData)
		if err != nil {
			return nil, fmt.Errorf("pdf: object %d: %w", num, err)
		}
		objs = append(objs, outObj{num: num, gen: doc.GenOf(num), val: transformed})
	}

	encryptRef := Ref{}
	if opts.EncryptDict != nil {
		maxNum++
		encryptRef = Ref{Num: maxNum, Gen: 0}
		objs = append(objs, outObj{num: maxNum, gen: 0, val: opts.EncryptDict})
	}

	trailer := Dict{}
	for _, k := range []Name{"Root", "Info"} {
		if v, ok := doc.trailer[k]; ok {
			trailer[k] = v
		}
	}
	if id, ok := doc.trailer["ID"]; ok {
		trailer["ID"] = id
	} else {
		id1 := randomBytes(16)
		trailer["ID"] = Array{String{Bytes: id1}, String{Bytes: id1}}
	}
	if opts.EncryptDict != nil {
		trailer["Encrypt"] = encryptRef
	}

	var buf bytes.Buffer
	version := doc.Version
	if opts.EncryptDict != nil && version < "1.7" {
		version = "1.7"
	}
	fmt.Fprintf(&buf, "%%PDF-%s\n%%\xE2\xE3\xCF\xD3\n", version)

	offsets := make(map[int]int64, len(objs))
	gens := make(map[int]int, len(objs))
	for _, o := range objs {
		offsets[o.num] = int64(buf.Len())
		gens[o.num] = o.gen
		fmt.Fprintf(&buf, "%d %d obj\n", o.num, o.gen)
		writeObject(&buf, o.val)
		buf.WriteString("\nendobj\n")
	}

	xrefOffset := int64(buf.Len())
	size := maxNum + 1
	buf.WriteString("xref\n")
	fmt.Fprintf(&buf, "0 %d\n", size)
	buf.WriteString("0000000000 65535 f \n")
	for n := 1; n < size; n++ {
		off, ok := offsets[n]
		if !ok {
			buf.WriteString("0000000000 00000 f \n")
			continue
		}
		fmt.Fprintf(&buf, "%010d %05d n \n", off, gens[n])
	}

	trailer["Size"] = int64(size)
	buf.WriteString("trailer\n")
	writeObject(&buf, trailer)
	buf.WriteString("\nstartxref\n")
	fmt.Fprintf(&buf, "%d\n%%%%EOF", xrefOffset)

	return buf.Bytes(), nil
}

// hasIdentityCryptFilter reports whether the stream declares an explicit
// /Crypt filter using the Identity crypt filter (the default /Name), which
// per §7.4.10 means the stream's data is stored unencrypted regardless of
// the document's encryption, so it must pass through untouched in both
// directions.
func hasIdentityCryptFilter(s *Stream) bool {
	filters := filterNames(s.Dict["Filter"])
	parms := decodeParms(s.Dict["DecodeParms"], len(filters))
	for i, f := range filters {
		if f != "Crypt" {
			continue
		}
		name := Name("Identity")
		if i < len(parms) && parms[i] != nil {
			if n, ok := parms[i]["Name"].(Name); ok {
				name = n
			}
		}
		if name == "Identity" {
			return true
		}
	}
	return false
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// transformObject applies fn to every string and stream body within obj.
// skipStreamData, if non-nil, exempts a stream's *data* (never its
// dictionary's strings) from the transform.
func transformObject(obj interface{}, fn Transform, skipStreamData func(*Stream) bool) (interface{}, error) {
	switch v := obj.(type) {
	case Array:
		for i, e := range v {
			t, err := transformObject(e, fn, skipStreamData)
			if err != nil {
				return nil, err
			}
			v[i] = t
		}
		return v, nil
	case Dict:
		for k, e := range v {
			t, err := transformObject(e, fn, skipStreamData)
			if err != nil {
				return nil, err
			}
			v[k] = t
		}
		return v, nil
	case *Stream:
		if _, err := transformObject(v.Dict, fn, skipStreamData); err != nil {
			return nil, err
		}
		if fn != nil && skipStreamData != nil && skipStreamData(v) {
			fn = nil
		}
		if fn != nil {
			data, err := fn(v.Data)
			if err != nil {
				return nil, err
			}
			v.Data = data
		}
		v.Dict["Length"] = int64(len(v.Data))
		return v, nil
	case String:
		if fn == nil {
			return v, nil
		}
		b, err := fn(v.Bytes)
		if err != nil {
			return nil, err
		}
		return String{Bytes: b}, nil
	default:
		return v, nil
	}
}

func writeObject(buf *bytes.Buffer, obj interface{}) {
	switch v := obj.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int64:
		buf.WriteString(strconv.FormatInt(v, 10))
	case int:
		buf.WriteString(strconv.Itoa(v))
	case float64:
		buf.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
	case Name:
		writeName(buf, v)
	case String:
		writeHexString(buf, v.Bytes)
	case Ref:
		fmt.Fprintf(buf, "%d %d R", v.Num, v.Gen)
	case Array:
		buf.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				buf.WriteByte(' ')
			}
			writeObject(buf, e)
		}
		buf.WriteByte(']')
	case Dict:
		writeDict(buf, v)
	case *Stream:
		writeDict(buf, v.Dict)
		buf.WriteString("\nstream\n")
		buf.Write(v.Data)
		buf.WriteString("\nendstream")
	default:
		buf.WriteString("null")
	}
}

func writeDict(buf *bytes.Buffer, d Dict) {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	buf.WriteString("<<")
	for _, k := range keys {
		buf.WriteByte('/')
		writeNameBody(buf, Name(k))
		buf.WriteByte(' ')
		writeObject(buf, d[Name(k)])
		buf.WriteByte(' ')
	}
	buf.WriteString(">>")
}

func writeName(buf *bytes.Buffer, n Name) {
	buf.WriteByte('/')
	writeNameBody(buf, n)
}

func writeNameBody(buf *bytes.Buffer, n Name) {
	for i := 0; i < len(n); i++ {
		b := n[i]
		if b == '#' || isWhitespace(b) || isDelimiter(b) || b < 0x21 || b > 0x7E {
			fmt.Fprintf(buf, "#%02X", b)
		} else {
			buf.WriteByte(b)
		}
	}
}

func writeHexString(buf *bytes.Buffer, b []byte) {
	const hexDigits = "0123456789ABCDEF"
	buf.WriteByte('<')
	for _, c := range b {
		buf.WriteByte(hexDigits[c>>4])
		buf.WriteByte(hexDigits[c&0x0F])
	}
	buf.WriteByte('>')
}
