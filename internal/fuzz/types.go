// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

package fuzz

import (
	"fmt"
	"strings"
	"time"
)

// FuzzerInput represents a single fuzzing input with validation helpers.
type FuzzerInput struct {
	EnvelopeXdr   string
	LedgerEntries map[string]string
	Timestamp     int64
	Args          []string
	Seed          uint64
}

// Validate checks that the input has the minimum structure required by the fuzzer.
func (input *FuzzerInput) Validate() error {
	if input == nil {
		return fmt.Errorf("fuzzer input required")
	}

	if strings.TrimSpace(input.EnvelopeXdr) == "" {
		return fmt.Errorf("envelope XDR required")
	}

	return nil
}

// FuzzingStats represents statistics from a fuzzing run
type FuzzingStats struct {
	StartTime          time.Time
	EndTime            time.Time
	ExecutionCount     uint64
	CrashCount         uint64
	NewCoverageCount   uint64
	CorpusSize         int
	CoverageEntryCount int
	UniqueInputsCount  int
}

// Duration returns the total execution time
func (s *FuzzingStats) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return 0
	}
	return s.EndTime.Sub(s.StartTime)
}

// ExecutionsPerSecond calculates throughput
func (s *FuzzingStats) ExecutionsPerSecond() float64 {
	d := s.Duration()
	if d == 0 {
		return 0
	}
	return float64(s.ExecutionCount) / d.Seconds()
}

// CoverageStatistics represents aggregate coverage statistics
type CoverageStatistics struct {
	CorpusSize                int
	UniqueCoverageCount       int
	CrashCount                int
	ExecutionCount            uint64
	MaxCoverage               uint32
	AvgCoverage               uint32
	TimeSinceLastCoverageGrow time.Duration
}

// String returns a human-readable representation of coverage statistics
func (cs CoverageStatistics) String() string {
	return fmt.Sprintf(
		"CoverageStats{corpus_size=%d, unique_coverage=%d, crashes=%d, executions=%d, max_coverage=%d, avg_coverage=%d, time_since_grow=%v}",
		cs.CorpusSize, cs.UniqueCoverageCount, cs.CrashCount, cs.ExecutionCount,
		cs.MaxCoverage, cs.AvgCoverage, cs.TimeSinceLastCoverageGrow,
	)
}

// String returns a human-readable representation of fuzzing statistics
func (s *FuzzingStats) String() string {
	return fmt.Sprintf(
		"FuzzingStats{duration=%v, executions=%d, crashes=%d, new_coverage=%d, corpus_size=%d, coverage_entries=%d, exec/sec=%.2f}",
		s.Duration(), s.ExecutionCount, s.CrashCount, s.NewCoverageCount,
		s.CorpusSize, s.CoverageEntryCount, s.ExecutionsPerSecond(),
	)
}
