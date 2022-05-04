package rest

import (
	"log"
	"net/http"
)

// a SimpleResponse struct
type SimpleResponse struct {
	Msg string `json:"msg"`
}

// handleCacheSyncGET forces a cache sync.
func (s *Server) handleCacheSyncGET() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		span, _ := s.Tracer.StartSpanWithContext(r.Context(), "user-data", "okta-controller", "http")
		defer s.Tracer.FinishSpan(span)

		log.Println("Start manual cache sync.")
		go s.OktaService.SyncUsers()
		go s.OktaService.SyncGroups()

		response := SimpleResponse{Msg: "Manual cache sync started."}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// handleCacheStatusGET returns the timestamp of last cache update.
func (s *Server) handleCacheStatusGET() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		span, _ := s.Tracer.StartSpanWithContext(r.Context(), "user-data", "okta-controller", "http")
		defer s.Tracer.FinishSpan(span)

		timestamp := s.OktaService.GetLastSyncTime()

		response := SimpleResponse{Msg: "Last cache sync at: " + timestamp}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
