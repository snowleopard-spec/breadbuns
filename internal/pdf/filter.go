package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// decodeStreamForStructure decodes a stream's data using its /Filter chain,
// for streams we need to read as *structure* (xref streams, object
// streams). It does not need to handle every PDF filter, only the ones
// commonly used for those two purposes (FlateDecode, optionally with a PNG
// predictor).
func decodeStreamForStructure(s *Stream) ([]byte, error) {
	filters := filterNames(s.Dict["Filter"])
	parms := decodeParms(s.Dict["DecodeParms"], len(filters))
	data := s.Data
	for i, f := range filters {
		switch f {
		case "FlateDecode", "Fl":
			out, err := flateDecode(data)
			if err != nil {
				return nil, err
			}
			data = out
		default:
			return nil, fmt.Errorf("pdf: unsupported structural filter %q", f)
		}
		if i < len(parms) {
			data = applyPredictor(data, parms[i])
		}
	}
	return data, nil
}

func filterNames(v interface{}) []Name {
	switch f := v.(type) {
	case Name:
		return []Name{f}
	case Array:
		out := make([]Name, 0, len(f))
		for _, e := range f {
			if n, ok := e.(Name); ok {
				out = append(out, n)
			}
		}
		return out
	default:
		return nil
	}
}

func decodeParms(v interface{}, n int) []Dict {
	out := make([]Dict, n)
	switch p := v.(type) {
	case Dict:
		if n > 0 {
			out[0] = p
		}
	case Array:
		for i, e := range p {
			if i >= n {
				break
			}
			if d, ok := e.(Dict); ok {
				out[i] = d
			}
		}
	}
	return out
}

func flateDecode(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("pdf: flate decode: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("pdf: flate decode: %w", err)
	}
	return out, nil
}

// applyPredictor reverses a PNG or TIFF predictor as described by /DecodeParms.
func applyPredictor(data []byte, parms Dict) []byte {
	if parms == nil {
		return data
	}
	predictor := dictInt(parms, "Predictor", 1)
	if predictor <= 1 {
		return data
	}
	columns := dictInt(parms, "Columns", 1)
	colors := dictInt(parms, "Colors", 1)
	bpc := dictInt(parms, "BitsPerComponent", 8)
	bytesPerPixel := (colors*bpc + 7) / 8
	if bytesPerPixel < 1 {
		bytesPerPixel = 1
	}
	rowBytes := (columns*colors*bpc + 7) / 8

	if predictor == 2 {
		return applyTIFFPredictor(data, rowBytes, bytesPerPixel)
	}
	// PNG predictors (predictor >= 10): each row is prefixed with a filter
	// type byte.
	var out bytes.Buffer
	prev := make([]byte, rowBytes)
	stride := rowBytes + 1
	for off := 0; off+stride <= len(data); off += stride {
		filterType := data[off]
		row := make([]byte, rowBytes)
		copy(row, data[off+1:off+stride])
		for i := 0; i < rowBytes; i++ {
			var a, b, c byte
			if i >= bytesPerPixel {
				a = row[i-bytesPerPixel]
				c = prev[i-bytesPerPixel]
			}
			b = prev[i]
			switch filterType {
			case 0: // None
			case 1: // Sub
				row[i] += a
			case 2: // Up
				row[i] += b
			case 3: // Average
				row[i] += byte((int(a) + int(b)) / 2)
			case 4: // Paeth
				row[i] += paeth(a, b, c)
			}
		}
		out.Write(row)
		prev = row
	}
	return out.Bytes()
}

func paeth(a, b, c byte) byte {
	pa := abs(int(b) - int(c))
	pb := abs(int(a) - int(c))
	pc := abs(int(a) + int(b) - 2*int(c))
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func applyTIFFPredictor(data []byte, rowBytes, bytesPerPixel int) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	for off := 0; off+rowBytes <= len(out); off += rowBytes {
		for i := bytesPerPixel; i < rowBytes; i++ {
			out[off+i] += out[off+i-bytesPerPixel]
		}
	}
	return out
}

func dictInt(d Dict, key Name, def int) int {
	if v, ok := d[key]; ok {
		if n, ok := staticInt(v); ok {
			return n
		}
	}
	return def
}
