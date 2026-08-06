package apihttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ztap/internal/cluster"
)

type clusterNodeInfo struct {
	ID       string            `json:"id"`
	Address  string            `json:"address"`
	Role     string            `json:"role"`
	State    cluster.NodeState `json:"state"`
	JoinedAt string            `json:"joined_at"`
	LastSeen string            `json:"last_seen"`
	Metadata map[string]string `json:"metadata"`
}

type clusterStatusResponse struct {
	Leader     *clusterNodeInfo  `json:"leader,omitempty"`
	IsLeader   bool              `json:"is_leader"`
	Nodes      []clusterNodeInfo `json:"nodes"`
	UpdatedAt  string            `json:"updated_at"`
	TotalNodes int               `json:"total_nodes"`
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	if s.clusterElection == nil {
		writeError(w, http.StatusNotImplemented, errors.New("cluster election not configured"))
		return
	}

	nodes := s.clusterElection.GetNodes()
	leader := s.clusterElection.GetLeader()
	resp := clusterStatusResponse{
		IsLeader:   s.clusterElection.IsLeader(),
		Nodes:      convertNodes(nodes),
		UpdatedAt:  time.Now().UTC().Format(timeFormat),
		TotalNodes: len(nodes),
	}
	if leader != nil {
		info := toNodeInfo(leader)
		resp.Leader = &info
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleClusterNodesRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/cluster/nodes" {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if s.clusterElection == nil {
		writeError(w, http.StatusNotImplemented, errors.New("cluster election not configured"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		nodes := convertNodes(s.clusterElection.GetNodes())
		writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
	case http.MethodPost:
		var node cluster.Node
		if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
			return
		}
		node.ID = strings.TrimSpace(node.ID)
		node.Address = strings.TrimSpace(node.Address)
		if node.ID == "" || node.Address == "" {
			writeError(w, http.StatusBadRequest, errors.New("node id and address are required"))
			return
		}
		if node.State == "" {
			node.State = cluster.StateHealthy
		}
		if node.JoinedAt.IsZero() {
			node.JoinedAt = time.Now()
		}
		node.LastSeen = time.Now()
		if node.Metadata == nil {
			node.Metadata = map[string]string{}
		}
		if err := s.clusterElection.RegisterNode(&node); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, toNodeInfo(&node))
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleClusterNodesRoutes(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/cluster/nodes/") {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if s.clusterElection == nil {
		writeError(w, http.StatusNotImplemented, errors.New("cluster election not configured"))
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/cluster/nodes/"), "/")
	if len(parts) != 1 {
		writeError(w, http.StatusNotFound, errors.New("invalid node path"))
		return
	}
	nodeID := strings.TrimSpace(parts[0])
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node id is required"))
		return
	}
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w)
		return
	}
	if err := s.clusterElection.DeregisterNode(nodeID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func convertNodes(nodes []*cluster.Node) []clusterNodeInfo {
	resp := make([]clusterNodeInfo, 0, len(nodes))
	for _, node := range nodes {
		resp = append(resp, toNodeInfo(node))
	}
	return resp
}

func toNodeInfo(node *cluster.Node) clusterNodeInfo {
	if node == nil {
		return clusterNodeInfo{}
	}
	info := clusterNodeInfo{
		ID:       node.ID,
		Address:  node.Address,
		Role:     node.Role,
		State:    node.State,
		JoinedAt: node.JoinedAt.UTC().Format(timeFormat),
		LastSeen: node.LastSeen.UTC().Format(timeFormat),
		Metadata: node.Metadata,
	}
	return info
}
