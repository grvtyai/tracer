package runnerclient

import (
	"context"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

func (c *Client) Health(ctx context.Context) (api.Health, error) {
	var out api.Health
	return out, c.do(ctx, "GET", "/health", nil, &out)
}

func (c *Client) Capabilities(ctx context.Context) (api.Capabilities, error) {
	var out api.Capabilities
	return out, c.do(ctx, "GET", "/capabilities", nil, &out)
}

func (c *Client) StartRun(ctx context.Context, req api.StartRunRequest) (api.StartRunResponse, error) {
	var out api.StartRunResponse
	return out, c.do(ctx, "POST", "/runs", req, &out)
}

func (c *Client) ListRuns(ctx context.Context) (api.RunList, error) {
	var out api.RunList
	return out, c.do(ctx, "GET", "/runs", nil, &out)
}

func (c *Client) RunStatus(ctx context.Context, runID string) (api.RunStatus, error) {
	var out api.RunStatus
	return out, c.do(ctx, "GET", "/runs/"+runID+"/status", nil, &out)
}

func (c *Client) RunEvidence(ctx context.Context, runID string) (api.EvidenceResponse, error) {
	var out api.EvidenceResponse
	return out, c.do(ctx, "GET", "/runs/"+runID+"/evidence", nil, &out)
}

func (c *Client) RunJobs(ctx context.Context, runID string) (api.JobsResponse, error) {
	var out api.JobsResponse
	return out, c.do(ctx, "GET", "/runs/"+runID+"/jobs", nil, &out)
}

func (c *Client) CancelRun(ctx context.Context, runID string) error {
	return c.do(ctx, "DELETE", "/runs/"+runID, nil, nil)
}
