# breadbuns

A single-binary, interactive Go CLI that locks and unlocks every PDF in a folder
using Adobe's native password protection, the ISO 32000-2 AES-256 Standard
Security Handler. A file locked by breadbuns opens in Acrobat, Preview or any
other reader with that reader's own password prompt, and breadbuns can remove
the password again from its own files and from AES-256 files produced by
Acrobat, qpdf and similar tools. No Adobe software is involved at any point.

Version 1.2. See `breadbuns-user-manual.pdf` for the end-user walkthrough;
this file covers what the manual deliberately leaves out: the source, the
architecture, and the edge cases the code handles.

## Purpose

- **Batch password protection without Acrobat.** Pick a folder with the
  arrow keys, choose lock or unlock, review the candidate list, confirm, type
  one password, and every matching PDF is processed.
- **Standards-based output.** The result is not a wrapper or a container. It
  is a spec-compliant encrypted PDF (V5/R6, AESV3 crypt filter) that
  independent tooling such as `qpdf --check` accepts.
- **No stored secrets.** The password is read with terminal echo off, used to
  derive keys in memory, and never written anywhere. There is no recovery
  path if it is forgotten.

## Usage

```sh
cd /path/to/breadbuns
go build -o breadbuns .
./breadbuns
```

There are no flags or arguments. The program runs a fixed sequence:

1. Folder picker (full-screen, arrow keys; `~` jumps home, `q` cancels).
2. Mode menu: `1` encrypt, `2` decrypt, `q` quit.
3. Candidate listing. Encrypt mode lists unlocked PDFs whose name does not
   already end in `_locked`; decrypt mode lists PDFs whose trailer carries an
   `/Encrypt` entry. Unreadable PDFs are reported separately, never silently
   dropped. Only the top level of the folder is scanned.
4. Confirmation, then one password for the whole batch (typed twice when
   encrypting).
5. Per-file results: succeeded, failed with a reason, and, for decrypts, any
   integrity warnings.

Encrypting copies `report.pdf` to `report_locked.pdf` and leaves the original
untouched. Decrypting replaces the file in place via a temp file and rename,
so a failed decrypt never leaves a half-written file. An unlock has no undo.

## Architecture

```
main.go                     orchestration, prompts, per-file encrypt/decrypt
internal/browse/browse.go   bubbletea folder picker
internal/pdf/               minimal PDF object model, parser and writer
  types.go                  object types and deep Clone
  parser.go                 recursive-descent tokenizer for the raw bytes
  xref.go                   classic xref tables and xref streams, /Prev chain
  filter.go                 FlateDecode and PNG/TIFF predictors for structure
  document.go               Document: object lookup, object streams, AllObjects
  writer.go                 re-serialization with a per-object Transform hook
internal/pdfcrypt/          ISO 32000-2 Standard Security Handler, revision 6
  hash.go                   Algorithm 2.B hardened hash and raw AES-CBC helpers
  standard.go               /Encrypt dictionary build, Authenticate, VerifyPerms
  aes.go                    content encryption (AESV3), PKCS7, ECB for /Perms
```

The two internal packages are deliberately layered. `pdf` knows nothing about
encryption: it exposes a `Transform` function type that the writer applies to
every string and stream body, plus a hook for decrypting object streams during
parsing. `pdfcrypt` knows nothing about file structure: it takes and returns
byte slices and a `pdf.Dict`. `main.go` is the only place that wires the two
together.

### The core idea: rewrite, never patch

breadbuns does not modify a PDF incrementally. It parses the whole file into an
object graph, walks every object applying a transform (encrypt or decrypt) to
every string and stream, and writes a brand-new file with a fresh classic
cross-reference table. This makes encryption a single uniform sweep, but it
means incremental-update history is discarded and anything the parser cannot
read cannot be written back.

Third-party dependencies are limited to the folder picker (`bubbletea`) and
password entry (`golang.org/x/term`). All PDF parsing, writing and cryptography
is hand-written on the Go standard library.

### `main.go`

`run()` drives the interactive sequence above and holds the two per-file
operations.

- `encryptFile` reads the source, writes the `_locked` copy first (so an
  early failure can remove it), parses the original, generates a random
  32-byte file key, builds the `/Encrypt` dictionary, and calls `pdf.Write`
  with an encrypting transform and the dictionary. The output overwrites the
  copy.
- `decryptFile` loads the file, resolves its `/Encrypt` dictionary,
  authenticates the password to recover the file key, checks the `/Perms`
  integrity block (a failure becomes a warning, not an error), installs the
  decryptor on the document so object streams can be read, then writes with a
  decrypting transform and no `/Encrypt` dictionary. Output goes to
  `<file>.tmp` and is renamed over the original.
- `readPassword` uses `term.ReadPassword` on a terminal and falls back to a
  plain line read otherwise, which is what lets the tests drive it.

### `internal/browse/browse.go`

A small `bubbletea` model. It lists the non-hidden subdirectories of the
current path plus a `[ Use this folder ]` entry and a `..` entry when a parent
exists. Arrow keys or `j`/`k` move, enter or right descends or selects,
backspace or left ascends, `~` jumps to the home directory, `q`, `Esc` or
`Ctrl-C` cancels. `Pick(start)` runs the program in the alternate screen and
returns the chosen absolute path or `ErrCancelled`. It has no tests because
it is pure terminal interaction.

### `internal/pdf/types.go`

The object model: `Name`, `Ref` (indirect reference), `String` (raw bytes,
literal and hex forms are not distinguished after parsing), `Array`, `Dict`,
and `*Stream` (a dict plus the raw, still-filtered, possibly still-encrypted
bytes). `Clone` deep-copies a graph so the writer can transform a copy without
disturbing the parsed cache.

### `internal/pdf/parser.go`

A recursive-descent reader over the raw bytes. It handles whitespace and
comments, names with `#xx` escapes, literal strings with all escape forms and
nested parentheses, hex strings, arrays, dictionaries, numbers, `N G R`
references, and `N G obj ... endobj` wrappers.

Stream bodies are located using `/Length` when it is a direct integer and the
`endstream` keyword follows where expected. Otherwise the parser scans forward
for `endstream` and trims one trailing end-of-line, so a wrong or indirect
`/Length` still yields the right bytes.

Nesting depth is capped at 512 levels. A file with a million nested brackets
returns `errTooDeep` rather than overflowing the stack.

### `internal/pdf/xref.go`

`loadXref` starts at the `startxref` offset and walks the revision chain
backwards: classic `xref` tables (following `/Prev` and, for hybrid files,
`/XRefStm`) and cross-reference stream objects (following `/Prev`). Entries
and trailer keys are merged first-seen-wins, so the newest revision takes
precedence. A `seen` set guards against loops. Xref streams are decoded with
`/W` field widths and optional `/Index` subsections; type 1 entries record a
byte offset, type 2 entries record which object stream holds the object.

### `internal/pdf/filter.go`

Decoding for streams that must be read as structure: xref streams and object
streams. Only FlateDecode is supported, optionally followed by a PNG predictor
(None, Sub, Up, Average, Paeth) or the TIFF predictor. Content streams and
images are never decoded; their bytes are transformed opaquely.

### `internal/pdf/document.go`

`Document` holds the raw bytes, the merged xref map and trailer, and lazy
caches for resolved objects. `Resolve` follows a `Ref` to its value, either by
parsing at a file offset or by decoding the enclosing object stream and
picking out the member. Offsets from the xref are treated as untrusted and
checked against the file length before use.

`SetStreamDecryptor` installs a function applied to object-stream bytes before
inflation and clears every cache. In an encrypted file the object streams are
themselves encrypted, so their members cannot be read until the file key is
known. It must be called after `Authenticate` and before any object is
resolved for writing.

`AllObjects` returns the object numbers to carry into the output. It skips
xref streams, object-stream containers (their members are listed
individually, flattening them), the linearization dictionary (its offsets
would be stale after a rewrite), and the `/Encrypt` dictionary itself.

### `internal/pdf/writer.go`

`Write` sorts the object numbers, clones and transforms each object, appends
the new `/Encrypt` dictionary as one more object if given, and emits a
`%PDF-x.y` header, every object, a classic xref table with a free entry for
each gap, and a trailer carrying `/Root`, `/Info`, `/ID` (generated if
missing), `/Size` and optionally `/Encrypt`. Encrypted output is stamped at
least PDF 1.7. Dictionaries are written with sorted keys and all strings as
hex, so output is deterministic given the same inputs and key material.

`transformObject` recurses through arrays, dicts and streams, applying the
transform to every `String` and every stream body, then rewriting `/Length`
to the new byte count. Three exemptions are described in the next section.

### `internal/pdfcrypt/hash.go`

Algorithm 2.B from ISO 32000-2 section 7.6.4.3.4, the "hardened" iterated hash
used by revision 6. Each round encrypts 64 repetitions of password, current
hash and optional extra data with AES-128-CBC keyed from the hash itself, then
picks SHA-256, SHA-384 or SHA-512 by the byte sum of the first block modulo
three. It runs at least 64 rounds and stops once the last byte of the
ciphertext is no greater than the round number minus 32. The first 32 bytes
of the final hash are the result.

### `internal/pdfcrypt/standard.go`

- `BuildEncryptDict` produces a V5/R6 dictionary. The password is UTF-8,
  truncated to 127 bytes. Random 8-byte validation and key salts are drawn
  for the user and owner entries; `/U` and `/O` are hash ‖ validation salt ‖
  key salt (48 bytes), and `/UE` and `/OE` are the file key encrypted with
  AES-256-CBC, no padding, zero IV, under an intermediate key derived from the
  key salt. The same password fills both roles: breadbuns has no separate
  owner concept. `/P` is -4 (all permissions granted), and `/Perms` seals
  those bits.
- `Authenticate` refuses anything but V5 with R5 or R6, tries the user
  password path first, then the owner path, using constant-time comparison,
  and returns the recovered 32-byte file key or `ErrIncorrectPassword`.
- `VerifyPerms` decrypts the 16-byte `/Perms` block with the file key in AES
  ECB and checks the `adb` marker, that the embedded permission bits match
  `/P`, and that the metadata flag matches `/EncryptMetadata`.

### `internal/pdfcrypt/aes.go`

Content encryption for the AESV3 crypt filter: a random 16-byte IV followed by
AES-256-CBC ciphertext with PKCS7 padding, keyed directly with the file key.
`DecryptData` validates length and padding. Empty input maps to empty output
in both directions. The ECB helpers exist only for the `/Perms` block.

## Special handling

These are the cases that took real debugging, or that a naive implementation
gets wrong. Most were surfaced by the first Acrobat-encrypted file breadbuns
was asked to unlock, which failed twice before version 1.2.

- **Acrobat pads `/U` and `/O` to 127 bytes.** The spec defines 48
  significant bytes. `Authenticate` accepts anything at least 48 bytes long
  and uses only that prefix, so Acrobat files authenticate.
- **Object streams are encrypted as a whole, and their members are not.**
  Modern writers store most objects inside compressed object streams. In an
  encrypted file, the container stream is encrypted once; the members inside
  were never individually encrypted. Two rules follow. The parser must decrypt
  the container before inflating it (`SetStreamDecryptor`), or the page tree
  reads back empty. And the writer must copy the strings of object-stream
  members through untouched during a decrypt, or they would be "decrypted"
  into garbage.
- **The `/Encrypt` dictionary is excluded from the transform walk.** Per spec
  it is never encrypted. Without the exclusion, the freshly appended dictionary
  is swept up on the next pass and the file corrupts. The round-trip test
  caught this.
- **`/EncryptMetadata false` leaves the XMP stream in the clear.** When the
  encryption dictionary says so, the document-level `/Metadata` stream is
  stored unencrypted and must be neither decrypted nor re-encrypted. The
  writer skips it. The `cleartext_metadata.pdf` fixture, made with qpdf,
  covers this. breadbuns' own output always encrypts metadata.
- **Streams with an Identity `/Crypt` filter pass through untouched.** A
  stream may declare that it is stored unencrypted regardless of the document
  setting. The writer honours this in both directions.
- **Stream dictionaries are transformed, stream data may be exempt.** The
  exemptions above apply to a stream's bytes only; strings inside its
  dictionary are always transformed.
- **`/Perms` mismatch is a warning, not a refusal.** A failed integrity check
  means the dictionary was altered after writing, or the writer was sloppy.
  The file still decrypts, so the user is told rather than blocked.
- **Untrusted input is bounded.** Xref offsets that point outside the file
  resolve to nothing instead of indexing out of bounds. Object nesting is
  capped at 512. Malformed AES lengths and bad PKCS7 padding return errors
  rather than panicking.
- **Linearization is dropped.** A linearization dictionary describes byte
  offsets of the original file. After a rewrite it would be wrong and
  misleading, so it is not carried over.
- **Wrong `/Length` values are tolerated.** If the declared stream length does
  not land on `endstream`, the parser scans for it instead.
- **Failed operations leave no trace.** A failed encrypt removes the partial
  `_locked` copy. A failed decrypt never touches the original because the
  output goes to a temp file first.

## Limitations

- **AES-256 only.** RC4 and AES-128 files (Acrobat's "Acrobat 7 and earlier"
  compatibility settings) are recognised and reported as unsupported, never
  opened. This buys one uniform code path.
- **One password, full permissions.** There is no owner-versus-user
  distinction and no way to restrict printing or copying.
- **Structural streams must be FlateDecode.** Xref and object streams using
  other filters cannot be read, so the file cannot be rewritten.
- **Top-level folder only, PDF only, interactive only.** No recursion, no
  other formats, and the folder picker needs a real terminal.

## Testing

```sh
go test ./...
```

| Test file | What it proves |
|---|---|
| `internal/pdf/roundtrip_test.go` | Encrypt then decrypt reproduces every stream byte; wrong password is rejected; if `qpdf` is installed, it reports R = 6, decrypts the file itself, and rejects a wrong password. |
| `internal/pdf/hostile_test.go` | 100,000 nested brackets return `errTooDeep`; 50 levels still parse; out-of-range xref offsets resolve to nil. |
| `internal/pdfcrypt/standard_test.go` | `VerifyPerms` accepts a fresh dictionary and rejects a flipped ciphertext byte, an altered `/P`, an altered `/EncryptMetadata`, and a missing block. |
| `main_test.go` | `encryptFile` leaves the original byte-identical, produces an encrypted `_locked` copy, a wrong-password decrypt leaves it encrypted, the right password unlocks it. |
| `acrobat_test.go` | The Acrobat fixture (linearized, object streams, padded `/U`) unlocks with its page tree intact, re-locks, unlocks again, and passes `qpdf --check` with three pages. The qpdf cleartext-metadata fixture unlocks with its XMP stream readable. |

`testdata/` holds three fixtures: `sample.pdf` (plain), `acrobat_aes256.pdf`
(Acrobat, password `claude`) and `cleartext_metadata.pdf` (qpdf, password
`claude`). Tests that need `qpdf` skip cleanly when it is not on the path;
install it with `brew install qpdf` for the independent validation.

## History

- **1.0 (2026-09-18)** Initial build: parser, writer, R6 handler, folder
  picker, encrypt-to-copy and decrypt-in-place.
- **1.1 (2026-09-19)** Decrypt third-party AES-256 files. Padded `/U` and
  `/O` accepted, object streams decrypted before inflation, object-stream
  member strings exempt from the writer's transform, `/EncryptMetadata false`
  and the Identity crypt filter honoured.
- **1.2 (2026-09-19)** Hardening: `/Perms` verified on unlock with a warning
  on mismatch, parser nesting capped, xref offsets bounds-checked.
