package orchestrator

import (
	"fmt"
	"slices"
	"sync"
)

// FindingCandidate is a worker-reported, unverified issue.
type FindingCandidate struct {
	CandidateID      string
	WorkerID         int
	Title            string
	Severity         string
	Endpoint         string
	FlowIDs          []string
	Summary          string
	EvidenceNotes    string
	ReproductionHint string
	Status           string // pending | verified | dismissed
}

// CandidatePool is a concurrent-safe pool.
type CandidatePool struct {
	mu      sync.Mutex
	byID    map[string]*FindingCandidate
	order   []string
	counter int
}

// NewCandidatePool builds an empty pool.
func NewCandidatePool() *CandidatePool {
	return &CandidatePool{byID: map[string]*FindingCandidate{}}
}

// AddInput is the set of fields for Add.
type AddInput struct {
	WorkerID         int
	Title            string
	Severity         string
	Endpoint         string
	FlowIDs          []string
	Summary          string
	EvidenceNotes    string
	ReproductionHint string
}

// Add records a new candidate attributed to workerID and returns its ID.
func (p *CandidatePool) Add(in AddInput) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counter++
	cid := fmt.Sprintf("c%03d", p.counter)
	p.byID[cid] = &FindingCandidate{
		CandidateID:      cid,
		WorkerID:         in.WorkerID,
		Title:            in.Title,
		Severity:         in.Severity,
		Endpoint:         in.Endpoint,
		FlowIDs:          slices.Clone(in.FlowIDs),
		Summary:          in.Summary,
		EvidenceNotes:    in.EvidenceNotes,
		ReproductionHint: in.ReproductionHint,
		Status:           "pending",
	}
	p.order = append(p.order, cid)
	return cid
}

// Mark sets the status of a candidate if present.
func (p *CandidatePool) Mark(id, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.byID[id]; c != nil {
		c.Status = status
	}
}

// Pending returns a snapshot of pending candidates in insertion order.
func (p *CandidatePool) Pending() []FindingCandidate {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []FindingCandidate
	for _, id := range p.order {
		if c := p.byID[id]; c != nil && c.Status == "pending" {
			out = append(out, *c)
		}
	}
	return out
}

// Counter returns the current total of minted candidates.
func (p *CandidatePool) Counter() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counter
}

// IDsSinceForWorker returns candidate IDs minted after counterBefore attributed to workerID.
func (p *CandidatePool) IDsSinceForWorker(counterBefore, workerID int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for i := counterBefore + 1; i <= p.counter; i++ {
		cid := fmt.Sprintf("c%03d", i)
		if c := p.byID[cid]; c != nil && c.WorkerID == workerID {
			out = append(out, cid)
		}
	}
	return out
}
