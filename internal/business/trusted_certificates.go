package business

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

var (
	ErrEmptySubject = errors.New("trusted subject cannot be empty")
	ErrEmptyRegion  = errors.New("region name cannot be empty")
)

// loadTrustedSubjects loads the subjects of client certificates and their respective regions.
// Validates that the file path is safe and that no empty subjects or regions are present.
func loadTrustedSubjects(file string) (map[string]string, error) {
	// SECURITY: Validate file path to prevent path traversal
	if file == "" {
		return nil, errors.New("trusted subjects file path cannot be empty")
	}

	// Clean and validate path
	cleanPath := filepath.Clean(file)

	// Reject path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("path traversal detected in trusted subjects file: %s", file)
	}

	returnedMapping := make(map[string]string)

	mappingBytes, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("could not read trusted subjects file: %w", err)
	}

	var fileMapping map[string][]string

	err = yaml.Unmarshal(mappingBytes, &fileMapping)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal trusted subjects yaml: %w", err)
	}

	// SECURITY: Validate no empty regions or subjects
	for region, subjects := range fileMapping {
		// Reject empty region names
		if strings.TrimSpace(region) == "" {
			return nil, ErrEmptyRegion
		}

		for _, subject := range subjects {
			// Reject empty subjects
			if strings.TrimSpace(subject) == "" {
				return nil, fmt.Errorf("%w in region %s", ErrEmptySubject, region)
			}

			// Store the mapping
			returnedMapping[subject] = region
		}
	}

	return returnedMapping, nil
}
