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
	file_one, err := StrToTempFile(`{"settings":{"LABEL":"thisisatoken"},"tokens":{"token":{"access":"thisisatoken"}},"google_ids":["asdf@asdfasdf.cz"], "gitlab_claims":["4247/master"]}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(file_one)
	fm, err := CreateNewJSONFileManager(file_one)
	fm.SyncSecrets()
	assert.NoError(t, err)
	exp, err := fm.GetSetting("LABEL")
	assert.Equal(t, "thisisatoken", exp)
	assert.NoError(t, err)
	assert.Equal(t, true, fm.DoesTokenExist("thisisatoken"))
	assert.Equal(t, true, fm.IsGoogleIDInList("asdf@asdfasdf.cz"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("4247/master"))

	// add new secrets
	new_str := `{"settings":{"LABEL":"thisisatoken", "LABEL2":"alsotoken"},"tokens":{"token":{"access":"thisisatoken", "access2":"alsotoken"}},"google_ids":["asdf@asdfasdf.cz", "temp"], "gitlab_claims":["4247/master", "42/temp"]}`
	ioutil.WriteFile(file_one, []byte(new_str), 0644)
	fm.SyncSecrets()
	exp, err = fm.GetSetting("LABEL")
	assert.Equal(t, "thisisatoken", exp)
	assert.NoError(t, err)
	exp, err = fm.GetSetting("LABEL")
	assert.Equal(t, "alsotoken", exp)
	assert.NoError(t, err)
	assert.Equal(t, true, fm.DoesTokenExist("thisisatoken"))
	assert.Equal(t, true, fm.DoesTokenExist("alsotoken"))
	assert.Equal(t, true, fm.IsGoogleIDInList("asdf@asdfasdf.cz"))
	assert.Equal(t, true, fm.IsGoogleIDInList("temp"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("4247/master"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("42/temp"))

	// remove secrets
	rem_str := `{"settings":{"LABEL":"thisisatoken"},"tokens":{"token":{"access":"thisisatoken"}},"google_ids":["asdf@asdfasdf.cz"], "gitlab_claims":["4247/master"]}`
	ioutil.WriteFile(file_one, []byte(rem_str), 0644)
	fm.SyncSecrets()
	exp, err = fm.GetSetting("LABEL")
	assert.Equal(t, "thisisatoken", exp)
	assert.NoError(t, err)
	exp, err = fm.GetSetting("LABEL")
	assert.Error(t, err)
	assert.Equal(t, true, fm.DoesTokenExist("thisisatoken"))
	assert.Equal(t, false, fm.DoesTokenExist("alsotoken"))
	assert.Equal(t, true, fm.IsGoogleIDInList("asdf@asdfasdf.cz"))
	assert.Equal(t, false, fm.IsGoogleIDInList("temp"))
	assert.Equal(t, true, fm.IsGitlabClaimInList("4247/master"))
	assert.Equal(t, false, fm.IsGitlabClaimInList("42/temp"))
}

func TestCreateNewJSONFileManager(t *testing.T) {
	file_one, err := StrToTempFile("{}")
	if err != nil {
		panic(err)
	}
	defer os.Remove(file_one)
	file_two, err := StrToTempFile("{}")
	if err != nil {
		panic(err)
	}
	defer os.Remove(file_two)
	tests_happy := map[string][]string{
		file_one: []string{file_one},
		strings.Join([]string{file_one, file_two}, ":"): []string{file_one, file_two},
	}
	for test, expected := range tests_happy {
		fm, err := CreateNewJSONFileManager(test)
		assert.Equal(t, expected, fm.paths)
		assert.NoError(t, err)
	}

	tests_error := []string{"non-existent-file.what"}
	for test := range tests_error {
		_, err := CreateNewJSONFileManager(tests_error[test])
		assert.Error(t, err)
	}

}

func TestJSONDoesTokenExist(t *testing.T) {
	file_one, err := StrToTempFile(`{"tokens": {"app1": {"access1":"tokenval1", "access2":"tokenval2"}, "app2": {"access3":"tokenval3"}}}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(file_one)

	tests := map[string]bool{
		"tokenval1": true,
		"tokenval2": true,
		"tokenval3": true,
		"tokenval4": false,
	}
	fm, err := CreateNewJSONFileManager(file_one)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range tests {
		assert.Equal(t, expected, fm.DoesTokenExist(test))
	}
}
func TestJSONIsGoogleIDInList(t *testing.T) {
	file_one, err := StrToTempFile(`{"google_ids": ["email1@gserviceaccount.com", "email2@gserviceaccount.com"]}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(file_one)

	tests := map[string]bool{
		"email1@gserviceaccount.com": true,
		"email2@gserviceaccount.com": true,
		"email3@gserviceaccount.com": false,
	}
	fm, err := CreateNewJSONFileManager(file_one)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range tests {
		assert.Equal(t, expected, fm.IsGoogleIDInList(test))
	}
}
func TestJSONIsGitlabClaimInList(t *testing.T) {
	file_one, err := StrToTempFile(`{"gitlab_claims": ["1/master", "2/master", "3/not-master"]}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(file_one)

	tests := map[string]bool{
		"1/master":     true,
		"2/master":     true,
		"3/master":     false,
		"3/not-master": true,
		"4/master":     false,
		"2/not-master": false,
	}
	fm, err := CreateNewJSONFileManager(file_one)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range tests {
		assert.Equal(t, expected, fm.IsGitlabClaimInList(test))
	}
}
func TestJSONGetSetting(t *testing.T) {
	file_one, err := StrToTempFile(`{"settings":{"label1":"setting1", "label2":"setting2"}}`)
	if err != nil {
		panic(err)
	}
	defer os.Remove(file_one)

	tests_happy := map[string]string{
		"label1": "setting1",
		"label2": "setting2",
	}
	fm, err := CreateNewJSONFileManager(file_one)
	fm.SyncSecrets()
	assert.NoError(t, err)
	for test, expected := range tests_happy {
		res, err := fm.GetSetting(test)
		assert.Equal(t, expected, res)
		assert.NoError(t, err)
	}

	tests_unhappy := []string{
		"label3",
	}
	for test := range tests_unhappy {
		_, err := fm.GetSetting(tests_unhappy[test])
		assert.Error(t, err)
	}
}
