package testutils

import (
	"time"

	"github.com/ethereum-optimism/optimism/op-node/metrics"
	"github.com/ethereum-optimism/optimism/op-service/eth"
)

// TestDerivationMetrics implements the metrics used in the derivation pipeline as no-op operations.
// Optionally a test may hook into the metrics
type TestDerivationMetrics struct {
	FnRecordL1ReorgDepth      func(d uint64)
	FnRecordL1Ref             func(name string, ref eth.L1BlockRef)
	FnRecordL2Ref             func(name string, ref eth.L2BlockRef)
	FnRecordUnsafePayloads    func(length uint64, memSize uint64, next eth.BlockID)
	FnRecordChannelInputBytes func(inputCompressedBytes int)
}

func (t *TestDerivationMetrics) RecordL1ReorgDepth(d uint64) {
	if t.FnRecordL1ReorgDepth != nil {
		t.FnRecordL1ReorgDepth(d)
	}
}

func (t *TestDerivationMetrics) RecordL1Ref(name string, ref eth.L1BlockRef) {
	if t.FnRecordL1Ref != nil {
		t.FnRecordL1Ref(name, ref)
	}
}

func (t *TestDerivationMetrics) RecordL2Ref(name string, ref eth.L2BlockRef) {
	if t.FnRecordL2Ref != nil {
		t.FnRecordL2Ref(name, ref)
	}
}

func (t *TestDerivationMetrics) RecordUnsafePayloadsBuffer(length uint64, memSize uint64, next eth.BlockID) {
	if t.FnRecordUnsafePayloads != nil {
		t.FnRecordUnsafePayloads(length, memSize, next)
	}
}

func (t *TestDerivationMetrics) RecordChannelInputBytes(inputCompressedBytes int) {
	if t.FnRecordChannelInputBytes != nil {
		t.FnRecordChannelInputBytes(inputCompressedBytes)
	}
}

func (t *TestDerivationMetrics) RecordHeadChannelOpened() {
}

func (t *TestDerivationMetrics) RecordChannelTimedOut() {
}

func (t *TestDerivationMetrics) RecordFrame() {
}

func (n *TestDerivationMetrics) RecordDerivedBatches(batchType string) {
}

func (n *TestDerivationMetrics) CountSequencedTxsBySource(count int, source string) {
}

func (n *TestDerivationMetrics) RecordBuilderRequestTime(duration time.Duration) {
}

func (n *TestDerivationMetrics) RecordBuilderRequestFail() {
}

func (n *TestDerivationMetrics) RecordBuilderRequestTimeout() {
}

func (n *TestDerivationMetrics) RecordSequencerProfit(profit float64, source metrics.PayloadSource) {
}

func (n *TestDerivationMetrics) RecordSequencerPayloadInserted(source metrics.PayloadSource) {
}

func (n *TestDerivationMetrics) RecordPayloadGas(gas float64, source string) {
}

func (n *TestDerivationMetrics) RecordBuilderPayloadBytes(bytes int) {
}

type TestRPCMetrics struct{}

func (n *TestRPCMetrics) RecordRPCServerRequest(method string) func() {
	return func() {}
}

func (n *TestRPCMetrics) RecordRPCClientRequest(method string) func(err error) {
	return func(err error) {}
}

func (n *TestRPCMetrics) RecordRPCClientResponse(method string, err error) {}
