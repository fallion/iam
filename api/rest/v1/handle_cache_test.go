package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCacheStatusGet(t *testing.T) {
	// Success response
	userService := &mockOktaService{}
	request, _ := http.NewRequest("GET", "/v1/cache/status", nil)
	request.Header.Set("User-Agent", "whatever/0 (Kiwi.com test)")
	response := httptest.NewRecorder()
	server := setupServer()
	server.OktaService = userService
	testMSG := SimpleResponse{Msg: "Last cache sync at: 1-01-01T00:00:00.0Z"}

	handler := server.handleCacheStatusGET()

	handler.ServeHTTP(response, request)
	assert.Equal(t, 200, response.Code, "Returns 200 on success")

	responseJSON := response.Body.Bytes()
	var responseMSG SimpleResponse
	_ = json.Unmarshal(responseJSON, &responseMSG)

	assert.Equal(t, testMSG, responseMSG, "Returns correct body")
}

func TestCacheSyncGet(t *testing.T) {
	// Success response
	userService := &mockOktaService{}
	request, _ := http.NewRequest("GET", "/v1/cache/sync", nil)
	request.Header.Set("User-Agent", "whatever/0 (Kiwi.com test)")
	response := httptest.NewRecorder()
	server := setupServer()
	server.OktaService = userService
	testMSG := SimpleResponse{Msg: "Manual cache sync started."}

	handler := server.handleCacheSyncGET()

	handler.ServeHTTP(response, request)
	assert.Equal(t, 200, response.Code, "Returns 200 on success")

	responseJSON := response.Body.Bytes()
	var responseMSG SimpleResponse
	_ = json.Unmarshal(responseJSON, &responseMSG)

	assert.Equal(t, testMSG, responseMSG, "Returns correct body")
}
