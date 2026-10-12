package server

import (
	"errors"
	"net/http"
	"strconv"

	"deaconguard/internal/compliance"
	"deaconguard/internal/policy"
	"deaconguard/internal/store"
)

type policyResponse struct {
	store.PolicyRecord
	Controls int `json:"controls"`
}

func describePolicy(record store.PolicyRecord) policyResponse {
	response := policyResponse{PolicyRecord: record}
	if parsed, err := policy.Parse([]byte(record.Source)); err == nil {
		response.Controls = len(parsed.Controls)
	}
	return response
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	records, err := store.ListPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	policies := make([]policyResponse, 0, len(records))
	for _, record := range records {
		policies = append(policies, describePolicy(record))
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies, "example": policy.Example, "files": policy.Files})
}

type policySourceRequest struct {
	Source string `json:"source"`
}

func (s *Server) addPolicy(w http.ResponseWriter, r *http.Request) {
	var request policySourceRequest
	if !readJSON(w, r, &request) {
		return
	}
	parsed, err := policy.Parse([]byte(request.Source))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	record, err := store.AddPolicy(parsed.Name, request.Source, s.actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "policy.add", parsed.Name, describePolicyCount(parsed))
	writeJSON(w, http.StatusCreated, describePolicy(record))
}

func describePolicyCount(parsed policy.Policy) string {
	if len(parsed.Controls) == 1 {
		return "1 control"
	}
	return strconv.Itoa(len(parsed.Controls)) + " controls"
}

type policyUpdateRequest struct {
	Source  *string `json:"source"`
	Enabled *bool   `json:"enabled"`
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	var request policyUpdateRequest
	if !readJSON(w, r, &request) {
		return
	}
	id := r.PathValue("id")
	var record store.PolicyRecord
	var err error
	switch {
	case request.Source != nil:
		parsed, parseErr := policy.Parse([]byte(*request.Source))
		if parseErr != nil {
			writeError(w, http.StatusBadRequest, parseErr)
			return
		}
		record, err = store.UpdatePolicy(id, parsed.Name, *request.Source)
		if err == nil {
			s.audit(r, "policy.update", parsed.Name, describePolicyCount(parsed))
		}
	case request.Enabled != nil:
		record, err = store.SetPolicyEnabled(id, *request.Enabled)
		if err == nil {
			action := "policy.disable"
			if *request.Enabled {
				action = "policy.enable"
			}
			s.audit(r, action, record.Name, "")
		}
	default:
		writeError(w, http.StatusBadRequest, errors.New("nothing to change"))
		return
	}
	if errors.Is(err, store.ErrUnknownPolicy) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, describePolicy(record))
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	record, err := store.GetPolicy(r.PathValue("id"))
	if err == nil {
		err = store.DeletePolicy(record.ID)
	}
	if errors.Is(err, store.ErrUnknownPolicy) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "policy.delete", record.Name, "")
	w.WriteHeader(http.StatusNoContent)
}

// listFrameworks names the compliance frameworks audits are mapped to.
func (s *Server) listFrameworks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, compliance.Frameworks())
}
