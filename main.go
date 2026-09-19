// Command breadbuns encrypts or decrypts PDF files in a folder using
// Adobe's native, standards-based password protection (ISO 32000-2 AES-256
// Standard Security Handler) — so opening a locked file shows Acrobat's
// usual password prompt, no Adobe software involved in producing it.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"breadbuns/internal/browse"
	"breadbuns/internal/pdf"
	"breadbuns/internal/pdfcrypt"

	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "breadbuns:", err)
		os.Exit(1)
	}
}

func run() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("breadbuns — PDF locker")
	fmt.Println()

	start, err := os.Getwd()
	if err != nil {
		start = "."
	}

	var folder string
	for {
		picked, err := browse.Pick(start)
		if err != nil {
			if errors.Is(err, browse.ErrCancelled) {
				fmt.Println("Cancelled.")
				return nil
			}
			return err
		}
		fmt.Printf("Selected folder: %s\n", picked)
		if confirmYesNo(reader, "Use this folder?", true) {
			folder = picked
			break
		}
		start = picked
	}

	mode, err := askMode(reader)
	if err != nil {
		return err
	}
	if mode == "" {
		fmt.Println("Cancelled.")
		return nil
	}

	entries, err := os.ReadDir(folder)
	if err != nil {
		return fmt.Errorf("reading folder: %w", err)
	}

	var candidates []string
	var unreadable []string
	for _, f := range entries {
		if f.IsDir() || !strings.EqualFold(filepath.Ext(f.Name()), ".pdf") {
			continue
		}
		path := filepath.Join(folder, f.Name())
		doc, err := pdf.Load(path)
		if err != nil {
			unreadable = append(unreadable, f.Name())
			continue
		}
		encrypted := doc.IsEncrypted()
		switch mode {
		case "encrypt":
			if encrypted || isLockedName(f.Name()) {
				continue
			}
			candidates = append(candidates, f.Name())
		case "decrypt":
			if !encrypted {
				continue
			}
			candidates = append(candidates, f.Name())
		}
	}
	sort.Strings(candidates)

	fmt.Println()
	if len(candidates) == 0 {
		fmt.Printf("No files to %s in %s.\n", mode, folder)
		reportUnreadable(unreadable)
		return nil
	}

	fmt.Printf("Found %d file(s) to %s:\n", len(candidates), mode)
	for _, name := range candidates {
		fmt.Println("  -", name)
	}
	reportUnreadable(unreadable)
	fmt.Println()

	if !confirmYesNo(reader, fmt.Sprintf("Proceed with %sing these %d file(s)?", mode, len(candidates)), true) {
		fmt.Println("Cancelled.")
		return nil
	}

	password, err := askPassword(mode == "encrypt")
	if err != nil {
		return err
	}
	if password == "" {
		fmt.Println("Cancelled.")
		return nil
	}

	var succeeded, failed []string
	for _, name := range candidates {
		src := filepath.Join(folder, name)
		var procErr error
		if mode == "encrypt" {
			procErr = encryptFile(src, password)
		} else {
			procErr = decryptFile(src, password)
		}
		if procErr != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", name, procErr))
		} else {
			succeeded = append(succeeded, resultName(name, mode))
		}
	}

	fmt.Println()
	fmt.Printf("Done: %d succeeded, %d failed.\n", len(succeeded), len(failed))
	if len(succeeded) > 0 {
		fmt.Println("\nSucceeded:")
		for _, n := range succeeded {
			fmt.Println("  -", n)
		}
	}
	if len(failed) > 0 {
		fmt.Println("\nFailed:")
		for _, n := range failed {
			fmt.Println("  -", n)
		}
	}
	return nil
}

func isLockedName(name string) bool {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	return strings.HasSuffix(strings.ToLower(base), "_locked")
}

func resultName(original, mode string) string {
	if mode != "encrypt" {
		return original
	}
	ext := filepath.Ext(original)
	base := strings.TrimSuffix(original, ext)
	return base + "_locked" + ext
}

func reportUnreadable(unreadable []string) {
	if len(unreadable) == 0 {
		return
	}
	fmt.Printf("(%d PDF file(s) could not be read and were skipped: %s)\n", len(unreadable), strings.Join(unreadable, ", "))
}

func askMode(reader *bufio.Reader) (string, error) {
	for {
		fmt.Println("What would you like to do?")
		fmt.Println("  1) Encrypt PDFs (lock with a password)")
		fmt.Println("  2) Decrypt PDFs (remove a password)")
		fmt.Println("  q) Quit")
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		switch strings.TrimSpace(line) {
		case "1":
			return "encrypt", nil
		case "2":
			return "decrypt", nil
		case "q", "Q":
			return "", nil
		}
		fmt.Println("Please enter 1, 2, or q.")
	}
}

func confirmYesNo(reader *bufio.Reader, prompt string, def bool) bool {
	suffix := "[Y/n]"
	if !def {
		suffix = "[y/N]"
	}
	for {
		fmt.Printf("%s %s ", prompt, suffix)
		line, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		fmt.Println("Please answer y or n.")
	}
}

func askPassword(confirm bool) (string, error) {
	fmt.Print("Password: ")
	pw1, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Println()
	if pw1 == "" {
		return "", nil
	}
	if confirm {
		fmt.Print("Confirm password: ")
		pw2, err := readPassword()
		if err != nil {
			return "", err
		}
		fmt.Println()
		if pw1 != pw2 {
			return "", errors.New("passwords did not match; please run again")
		}
	}
	return pw1, nil
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	b, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func encryptFile(src, password string) error {
	ext := filepath.Ext(src)
	base := strings.TrimSuffix(src, ext)
	dst := base + "_locked" + ext

	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading original: %w", err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("creating copy: %w", err)
	}

	doc, err := pdf.Parse(data)
	if err != nil {
		os.Remove(dst)
		return fmt.Errorf("parsing PDF: %w", err)
	}

	fileKey, err := pdfcrypt.GenerateFileKey()
	if err != nil {
		os.Remove(dst)
		return err
	}
	encDict := pdfcrypt.BuildEncryptDict(password, fileKey)

	out, err := pdf.Write(doc, pdf.WriteOptions{
		Transform:   func(b []byte) ([]byte, error) { return pdfcrypt.EncryptData(fileKey, b) },
		EncryptDict: encDict,
	})
	if err != nil {
		os.Remove(dst)
		return fmt.Errorf("encrypting: %w", err)
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return fmt.Errorf("writing encrypted copy: %w", err)
	}
	return nil
}

func decryptFile(src, password string) error {
	doc, err := pdf.Load(src)
	if err != nil {
		return fmt.Errorf("parsing PDF: %w", err)
	}

	encDict, ok := doc.EncryptDict()
	if !ok {
		return errors.New("file is not encrypted")
	}

	fileKey, err := pdfcrypt.Authenticate(encDict, password)
	if err != nil {
		return err
	}
	decrypt := func(b []byte) ([]byte, error) { return pdfcrypt.DecryptData(fileKey, b) }
	// Object streams (used by Acrobat and most modern writers) are
	// encrypted as a whole; the parser needs the key to read their members.
	doc.SetStreamDecryptor(decrypt)

	out, err := pdf.Write(doc, pdf.WriteOptions{Transform: decrypt})
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	tmp := src + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return fmt.Errorf("writing: %w", err)
	}
	if err := os.Rename(tmp, src); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing original: %w", err)
	}
	return nil
}
