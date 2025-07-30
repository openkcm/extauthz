package business

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var mappingYaml = `---
region1:
  - "CN=client1"
  - "CN=client2"
region2:
  - "CN=client3"`

func TestLoadTrustedSubjects(t *testing.T) {
	// Create a temporary file
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "trustedSubjects.yaml")
	tempFile2 := filepath.Join(tempDir, "doesNotExist.yaml")

	// create the test cases
	tests := []struct {
		name      string
		yaml      string
		writeTo   string
		readFrom  string
		wantError bool
		want      map[string]string
	}{
		{
			name:      "zero values",
			yaml:      "",
			writeTo:   tempFile,
			readFrom:  tempFile,
			wantError: false,
			want:      map[string]string{},
		}, {
			name:      "file not found",
			yaml:      "",
			writeTo:   tempFile,
			readFrom:  tempFile2,
			wantError: true,
		}, {
			name:      "unmarshal error",
			yaml:      "invalid yaml",
			writeTo:   tempFile,
			readFrom:  tempFile,
			wantError: true,
		}, {
			name:      "empty yaml",
			yaml:      ``,
			writeTo:   tempFile,
			readFrom:  tempFile,
			wantError: false,
			want:      map[string]string{},
		}, {
			name:      "valid yaml",
			yaml:      mappingYaml,
			writeTo:   tempFile,
			readFrom:  tempFile,
			wantError: false,
			want:      map[string]string{"CN=client1": "region1", "CN=client2": "region1", "CN=client3": "region2"},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			err := os.WriteFile(tc.writeTo, []byte(tc.yaml), 0640)
			if err != nil {
				t.Errorf("could not write file: %v, got: %s", tc.writeTo, err)
			}

			// Act
			got, err := loadTrustedSubjects(tc.readFrom)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}

				if got != nil {
					t.Errorf("expected nil map, but got: %+v", got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				} else {
					if !reflect.DeepEqual(got, tc.want) {
						t.Errorf("expected: %+v, got: %+v", tc.want, got)
					}
				}
			}
		})
	}
}
