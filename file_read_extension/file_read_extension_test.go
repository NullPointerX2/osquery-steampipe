package main

import (
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

const testFileContent = "This\nis\na\ntest\n!"

func createTestFile(t *testing.T, dir, name string) *os.File {
	f, err := os.Create(path.Join(dir, name))
	assert.NoError(t, err)

	_, err = f.WriteString(testFileContent)
	assert.NoError(t, err)
	return f
}

func TestFileExists(t *testing.T) {
	t.Run("returns false if file does not exist", func(t *testing.T) {
		f := path.Join(t.TempDir(), "doesnt_exist")
		assert.False(t, fileExists(f), "file should exists")
	})

	t.Run("returns true if file exists", func(t *testing.T) {
		f, err := os.Create(path.Join(t.TempDir(), "file"))
		assert.NoError(t, err)
		assert.True(t, fileExists(f.Name()), "file should exists")
	})
}

func TestReadFileContent(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		f := path.Join(t.TempDir(), "doesnt_exist")
		_, err := readFileContent(f)
		assert.ErrorIs(t, err, ErrFileNotFound)
	})

	t.Run("existing file", func(t *testing.T) {
		f := createTestFile(t, t.TempDir(), "file")

		content, err := readFileContent(f.Name())
		assert.NoError(t, err)
		assert.Equal(t, testFileContent, content.Content)
		assert.Equal(t, f.Name(), content.Path)
	})

}

func TestProcessFile(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		f := path.Join(t.TempDir(), "doesnt_exist")
		_, err := processFile(f, false)
		assert.ErrorIs(t, err, ErrFileNotFound)
	})

	t.Run("existing file", func(t *testing.T) {
		f := createTestFile(t, t.TempDir(), "file")

		result, err := processFile(f.Name(), false)
		assert.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, testFileContent, result[0].Content)
		assert.Equal(t, f.Name(), result[0].Path)
	})

	t.Run("multiple files", func(t *testing.T) {
		dir := t.TempDir()
		f1 := createTestFile(t, dir, "file1")
		f2 := createTestFile(t, dir, "file2")
		createTestFile(t, dir, "another_file")

		result, err := processFile(path.Join(dir, "file*"), true)
		assert.NoError(t, err)
		assert.Len(t, result, 2)

		assert.Equal(t, testFileContent, result[0].Content)
		assert.Equal(t, f1.Name(), result[0].Path)

		assert.Equal(t, testFileContent, result[1].Content)
		assert.Equal(t, f2.Name(), result[1].Path)
	})
}
