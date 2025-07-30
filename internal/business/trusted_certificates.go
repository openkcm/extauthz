package business

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// loadTrustedSubjects loads the subjects of client certificates and their respective regions.
func loadTrustedSubjects(file string) (map[string]string, error) {
	returnedMapping := make(map[string]string)

	mappingBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read trusted subjects file: %w", err)
	}

	var fileMapping map[string][]string

	err = yaml.Unmarshal(mappingBytes, &fileMapping)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal trusted subjects yaml: %w", err)
	}

	for reg, val := range fileMapping {
		for _, sub := range val {
			returnedMapping[sub] = reg
		}
	}

	return returnedMapping, nil
}
