package rest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockTeamsGetter struct {
	mock.Mock
}

func (tg *mockTeamsGetter) GetTeams() (map[string]int, error) {
	args := tg.Called()
	return args.Get(0).(map[string]int), args.Error(1)
}

func TestInternalError(t *testing.T) {
	s := Server{}
	errMessage := "internal error that shouldn't be exposed"
	tg := &mockTeamsGetter{}
	s.oktaService = tg
	tg.On("GetTeams").Return(map[string]int{}, errors.New(errMessage))

	request, _ := http.NewRequest("GET", "/", nil)

	w := httptest.NewRecorder()

	handler := s.handleTeamsGET()
	handler.ServeHTTP(w, request)

	assert.Equal(t, 500, w.Code)
	assert.NotEqual(t, errMessage, w.Body.String())
	tg.AssertExpectations(t)
}

func TestGetTeams(t *testing.T) {
	s := Server{}
	tg := &mockTeamsGetter{}
	tg.On("GetTeams").Return(map[string]int{"team1": 3, "team2": 1, "team3": 1}, nil)
	s.oktaService = tg

	request, _ := http.NewRequest("GET", "/", nil)

	w := httptest.NewRecorder()

	handler := s.handleTeamsGET()
	handler.ServeHTTP(w, request)

	var expected = "{\"team1\":3,\"team2\":1,\"team3\":1}\n"
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expected, w.Body.String())
	tg.AssertExpectations(t)
}