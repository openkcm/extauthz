package business

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestLoadTrustedSubjectsSecurityValidation(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		yaml          string
		fileName      string
		wantError     bool
		expectedError string
	}{
		{
			name:          "reject empty subject",
			yaml:          "region1:\n  - \"CN=valid\"\n  - \"\"",
			fileName:      "test.yaml",
			wantError:     true,
			expectedError: "trusted subject cannot be empty",
		},
		{
			name:          "reject empty region",
			yaml:          "\"\":\n  - \"CN=test\"",
			fileName:      "test.yaml",
			wantError:     true,
			expectedError: "region name cannot be empty",
		},
		{
			name:          "reject path traversal with dots",
			yaml:          "region1:\n  - \"CN=test\"",
			fileName:      "../../etc/passwd",
			wantError:     true,
			expectedError: "path traversal detected",
		},
		{
			name:          "reject empty file path",
			yaml:          "",
			fileName:      "",
			wantError:     true,
			expectedError: "file path cannot be empty",
		},
		{
			name:          "accept whitespace-only subjects as empty",
			yaml:          "region1:\n  - \"  \"",
			fileName:      "test.yaml",
			wantError:     true,
			expectedError: "trusted subject cannot be empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var filePath string
			if tc.fileName != "" && !strings.Contains(tc.fileName, "..") {
				filePath = filepath.Join(tempDir, tc.fileName)
				err := os.WriteFile(filePath, []byte(tc.yaml), 0640)
				if err != nil {
					t.Fatalf("could not write file: %v", err)
				}
			} else {
				filePath = tc.fileName
			}

			got, err := loadTrustedSubjects(filePath)

			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				} else if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error containing %q, got: %v", tc.expectedError, err)
				}
				if got != nil {
					t.Errorf("expected nil map, but got: %+v", got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}
