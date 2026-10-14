package api

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/go-chi/chi/v5"
)

type AssessmentRunner interface {
	Start(context.Context, assessmentjob.Request) (assessmentjob.Session, error)
	Get(context.Context, string) (assessmentjob.Session, error)
}

func (s *Server) assessmentCapabilities(w http.ResponseWriter, r *http.Request) {
	if newQuery(r).reject(w) {
		return
	}
	tools := []string{}
	enabled := s.d.Assessments != nil
	if enabled {
		for tool := range s.d.Assessment.Images {
			tools = append(tools, tool)
		}
		sort.Strings(tools)
	}
	writeJSON(w, http.StatusOK, struct {
		Enabled         bool     `json:"enabled"`
		Tools           []string `json:"tools"`
		ResultsAdditive bool     `json:"results_additive"`
		TimeoutSeconds  int64    `json:"timeout_seconds"`
	}{enabled, tools, true, int64(s.d.Assessment.Timeout.Seconds())})
}

func (s *Server) startAssessment(w http.ResponseWriter, r *http.Request) {
	if s.d.Assessments == nil {
		writeError(w, 501, "not_implemented", "isolated assessment execution is not enabled")
		return
	}
	if newQuery(r).reject(w) {
		return
	}
	var request assessmentjob.Request
	if !decodeBody(w, r, &request) {
		return
	}
	session, err := s.d.Assessments.Start(r.Context(), request)
	if errors.Is(err, assessmentjob.ErrRefused) {
		writeError(w, 403, "assessment_refused", "assessment requires current owned targets, available capacity and verified containment")
		return
	}
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	s.log.Info("assessment started", "session", session.ID, "tool", session.Tool, "actor", identityFrom(r.Context()).Actor())
	writeJSON(w, http.StatusAccepted, session)
}

func (s *Server) getAssessment(w http.ResponseWriter, r *http.Request) {
	if s.d.Assessments == nil {
		writeError(w, 501, "not_implemented", "isolated assessment execution is not enabled")
		return
	}
	if newQuery(r).reject(w) {
		return
	}
	id := chi.URLParam(r, "session")
	if len(id) == 0 || len(id) > 64 {
		writeError(w, 404, "not_found", "unknown assessment session")
		return
	}
	session, err := s.d.Assessments.Get(r.Context(), id)
	if errors.Is(err, assessmentjob.ErrRefused) {
		writeError(w, 404, "not_found", "unknown assessment session")
		return
	}
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	writeJSON(w, 200, session)
}
