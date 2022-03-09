package secrets

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
	//"fmt"

	"github.com/stretchr/testify/assert"
)

func StrToTempFile(contents string) (string, error) {
	file, err := ioutil.TempFile("", "temp-*.json")
	if err != nil {
		return "", err
	}
	if _, err = file.Write([]byte(contents)); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func TestJSONSyncSecrets(t *testing.T) {
	fileOne, err := StrToTempFile(`{"settings":{"LABEL":"thisisatoken"},"tokens":{"token":{"access":"thisisatoken"}},"google_ids":["asdf@asdfasdf.cz"], "gitlab_claims":["4247/master"]}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(fileOne)
	fm, err := CreateNewJSONFileManager(fileOne)
	fm.SyncSecrets()
	assert.NoError(t, err)
	exp, err := fm.GetSetting("LABEL")
	assert.Equal(t, "thisisatoken", exp)
	assert.NoError(t, err)
	assert.Equal(t, true, fm.DoesTokenExist("thisisatoken"))
	assert.Equal(t, true, fm.IsGoogleIDInList("asdf@asdfasdf.cz"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("4247/master"))

	// add new secrets
	newStr := `{"settings":{"LABEL":"thisisatoken", "LABEL2":"alsotoken"},"tokens":{"token":{"access":"thisisatoken", "access2":"alsotoken"}},"google_ids":["asdf@asdfasdf.cz", "temp"], "gitlab_claims":["4247/master", "42/temp"]}`
	ioutil.WriteFile(fileOne, []byte(newStr), 0644)
	fm.SyncSecrets()
	exp, err = fm.GetSetting("LABEL")
	assert.Equal(t, "thisisatoken", exp)
	assert.NoError(t, err)
	exp, err = fm.GetSetting("LABEL2")
	assert.Equal(t, "alsotoken", exp)
	assert.NoError(t, err)
	assert.Equal(t, true, fm.DoesTokenExist("thisisatoken"))
	assert.Equal(t, true, fm.DoesTokenExist("alsotoken"))
	assert.Equal(t, true, fm.IsGoogleIDInList("asdf@asdfasdf.cz"))
	assert.Equal(t, true, fm.IsGoogleIDInList("temp"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("4247/master"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("42/temp"))

	// remove secrets
	remStr := `{"settings":{"LABEL":"thisisatoken"},"tokens":{"token":{"access":"thisisatoken"}},"google_ids":["asdf@asdfasdf.cz"], "gitlab_claims":["4247/master"]}`
	ioutil.WriteFile(fileOne, []byte(remStr), 0644)
	fm.SyncSecrets()
	exp, err = fm.GetSetting("LABEL")
	assert.Equal(t, "thisisatoken", exp)
	assert.NoError(t, err)
	exp, err = fm.GetSetting("LABEL2")
	assert.Error(t, err)
	assert.Equal(t, true, fm.DoesTokenExist("thisisatoken"))
	assert.Equal(t, false, fm.DoesTokenExist("alsotoken"))
	assert.Equal(t, true, fm.IsGoogleIDInList("asdf@asdfasdf.cz"))
	assert.Equal(t, false, fm.IsGoogleIDInList("temp"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("4247/master"))
	assert.Equal(t, false, fm.IsGitlabClaimInList("42/temp"))
}

func TestCreateNewJSONFileManager(t *testing.T) {
	fileOne, err := StrToTempFile("{}")
	if err != nil {
		panic(err)
	}
	defer os.Remove(fileOne)
	fileTwo, err := StrToTempFile("{}")
	if err != nil {
		panic(err)
	}
	defer os.Remove(fileTwo)
	testsHappy := map[string][]string{
		fileOne: []string{fileOne},
		strings.Join([]string{fileOne, fileTwo}, ":"): []string{fileOne, fileTwo},
	}
	for test, expected := range testsHappy {
		fm, err := CreateNewJSONFileManager(test)
		assert.Equal(t, expected, fm.paths)
		assert.NoError(t, err)
	}

	testsError := []string{"non-existent-file.what"}
	for test := range testsError {
		_, err := CreateNewJSONFileManager(testsError[test])
		assert.Error(t, err)
	}

}

func TestJSONDoesTokenExist(t *testing.T) {
	fileOne, err := StrToTempFile(`{"tokens": {"app1": {"access1":"tokenval1", "access2":"tokenval2"}, "app2": {"access3":"tokenval3"}}}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(fileOne)

	tests := map[string]bool{
		"tokenval1": true,
		"tokenval2": true,
		"tokenval3": true,
		"tokenval4": false,
	}
	fm, err := CreateNewJSONFileManager(fileOne)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range tests {
		assert.Equal(t, expected, fm.DoesTokenExist(test))
	}
}
func TestJSONIsGoogleIDInList(t *testing.T) {
	fileOne, err := StrToTempFile(`{"google_ids": ["email1@gserviceaccount.com", "email2@gserviceaccount.com"]}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(fileOne)

	tests := map[string]bool{
		"email1@gserviceaccount.com": true,
		"email2@gserviceaccount.com": true,
		"email3@gserviceaccount.com": false,
	}
	fm, err := CreateNewJSONFileManager(fileOne)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range tests {
		assert.Equal(t, expected, fm.IsGoogleIDInList(test))
	}
}
func TestJSONIsGitlabClaimInList(t *testing.T) {
	fileOne, err := StrToTempFile(`{"gitlab_claims": ["1/master", "2/master", "3/not-master"]}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(fileOne)

	tests := map[string]bool{
		"1/master":     true,
		"2/master":     true,
		"3/master":     false,
		"3/not-master": true,
		"4/master":     false,
		"2/not-master": false,
	}
	fm, err := CreateNewJSONFileManager(fileOne)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range tests {
		assert.Equal(t, expected, fm.IsGitlabClaimInList(test))
	}
}
func TestJSONGetSetting(t *testing.T) {
	fileOne, err := StrToTempFile(`{"settings":{"label1":"setting1", "label2":"setting2"}}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(fileOne)

	testsHappy := map[string]string{
		"label1": "setting1",
		"label2": "setting2",
	}
	fm, err := CreateNewJSONFileManager(fileOne)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range testsHappy {
		res, err := fm.GetSetting(test)
		assert.Equal(t, expected, res)
		assert.NoError(t, err)
	}

	testsError := []string{
		"label3",
	}
	for test := range testsError {
		_, err := fm.GetSetting(testsError[test])
		assert.Error(t, err)
	}
}
