// Package pdf implements just enough of the PDF (ISO 32000) object model to
// locate every indirect object in a file, rewrite their strings and streams,
// and re-serialize the document with a fresh classic cross-reference table.
// It intentionally does not aim to be a general-purpose PDF library.
package pdf

import "fmt"

// Name is a PDF name object, e.g. /Type.
type Name string

// Ref is an indirect reference, e.g. "12 0 R".
type Ref struct {
	Num int
	Gen int
}

// String is a PDF string object (literal or hex in the source; we don't
// distinguish once parsed, since we always re-emit as hex).
type String struct {
	Bytes []byte
}

// Array is a PDF array object.
type Array []interface{}

// Dict is a PDF dictionary object.
type Dict map[Name]interface{}

// Stream is a PDF stream object: a dictionary plus the raw (still filtered/
// encoded, and possibly still encrypted) bytes as stored in the file.
type Stream struct {
	Dict Dict
	Data []byte
}

func (r Ref) String() string {
	return fmt.Sprintf("%d %d R", r.Num, r.Gen)
}

// Clone deep-copies an object graph rooted at obj so callers can mutate a
// copy (e.g. to encrypt strings/streams) without touching the parsed cache.
func Clone(obj interface{}) interface{} {
	switch v := obj.(type) {
	case Array:
		out := make(Array, len(v))
		for i, e := range v {
			out[i] = Clone(e)
		}
		return out
	case Dict:
		out := make(Dict, len(v))
		for k, e := range v {
			out[k] = Clone(e)
		}
		return out
	case *Stream:
		data := make([]byte, len(v.Data))
		copy(data, v.Data)
		return &Stream{Dict: Clone(v.Dict).(Dict), Data: data}
	case String:
		b := make([]byte, len(v.Bytes))
		copy(b, v.Bytes)
		return String{Bytes: b}
	default:
		return v
	}
}
