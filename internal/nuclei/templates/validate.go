package templates

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Limits bounds a template tree before it is used by nuclei.
type Limits struct {
	MinTemplates     int
	MinHTTPTemplates int
	MaxBytes         int64
	MaxFiles         int
}

// Validate checks the filesystem safety and parseability of a template tree.
// It never follows symlinks while walking and rejects links that resolve
// outside the tree. Tree.Skipped reports malformed template headers.
func Validate(root string, limits Limits) (*Tree, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	var bytesTotal int64
	files := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		files++
		if limits.MaxFiles > 0 && files > limits.MaxFiles {
			return fmt.Errorf("more than %d files", limits.MaxFiles)
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("dangling symlink %s", relative(root, path))
			}
			if !within(real, target) {
				return fmt.Errorf("symlink %s escapes the template directory", relative(root, path))
			}
		case entry.IsDir():
			return nil
		case !entry.Type().IsRegular():
			return fmt.Errorf("special file %s", relative(root, path))
		default:
			info, err := entry.Info()
			if err != nil {
				return err
			}
			bytesTotal += info.Size()
			if limits.MaxBytes > 0 && bytesTotal > limits.MaxBytes {
				return fmt.Errorf("larger than %d bytes", limits.MaxBytes)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	tree, err := Scan(root)
	if err != nil {
		return nil, err
	}
	if limits.MinTemplates > 0 && len(tree.Templates) < limits.MinTemplates {
		return nil, fmt.Errorf("only %d templates (minimum %d)", len(tree.Templates), limits.MinTemplates)
	}
	if limits.MinHTTPTemplates > 0 {
		httpN := 0
		for _, m := range tree.Templates {
			if m.Protocol == "http" {
				httpN++
			}
		}
		if httpN < limits.MinHTTPTemplates {
			return nil, fmt.Errorf("only %d http templates (minimum %d)", httpN, limits.MinHTTPTemplates)
		}
	}
	if total := len(tree.Templates) + tree.Skipped; tree.Skipped > 0 && tree.Skipped*10 > total {
		return nil, fmt.Errorf("%d of %d template files are unparseable", tree.Skipped, total)
	}
	return tree, nil
}

func relative(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}

func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ValidateCustom applies the same safety bounds used for an official release,
// while allowing a small operator pack and any supported network protocol.
func ValidateCustom(root string, maxBytes int64, maxFiles int) (*Tree, error) {
	return Validate(root, Limits{MinTemplates: 1, MaxBytes: maxBytes, MaxFiles: maxFiles})
}

// IsRegularFile reports whether path is a regular file without following a
// link outside root. It is used when turning relative template paths into argv.
func IsRegularFile(root, path string) bool {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !within(root, real) {
		return false
	}
	info, err := os.Stat(real)
	return err == nil && info.Mode().IsRegular()
}
