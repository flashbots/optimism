package derive

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"

	opMetrics "github.com/ethereum-optimism/optimism/op-node/metrics"
	"github.com/ethereum-optimism/optimism/op-node/rollup/builder"
	"github.com/ethereum-optimism/optimism/op-service/eth"
)

type BuilderPayloadManager struct {
	builder builder.PayloadBuilder
	metrics Metrics
}

func NewBuilderPayloadManager(builder builder.PayloadBuilder, metrics Metrics) *BuilderPayloadManager {
	return &BuilderPayloadManager{
		builder: builder,
		metrics: metrics,
	}
}

func (bpm *BuilderPayloadManager) requestPayloadFromBuilder(ctx context.Context, l2head eth.L2BlockRef, log log.Logger) (*PayloadRequestResult, error) {
	start := time.Now()
	payload, err := bpm.builder.GetPayload(ctx, l2head, log, bpm.metrics)
	bpm.metrics.RecordBuilderRequestTime(time.Since(start))
	if err != nil {
		return &PayloadRequestResult{success: false, error: err}, err
	}
	return &PayloadRequestResult{success: true, envelope: payload}, nil
}

func (bpm *BuilderPayloadManager) getPayloadWithBuilderPayload(ctx context.Context, log log.Logger, eng ExecEngine, payloadInfo eth.PayloadInfo, l2head eth.L2BlockRef) (
	*eth.ExecutionPayloadEnvelope, *PayloadRequestResult, error) {
	// if builder is not enabled, return early with default path.
	if !bpm.builder.Enabled() {
		payload, err := eng.GetPayload(ctx, payloadInfo)
		return payload, nil, err
	}

	log.Debug("requesting payload from builder", l2head.String(), "payloadInfo", payloadInfo)
	ctxTimeout, cancel := context.WithTimeout(ctx, bpm.builder.Timeout())
	defer cancel()

	builderResult, err := bpm.requestPayloadFromBuilder(ctxTimeout, l2head, log)
	if err != nil {
		log.Warn("failed to get payload from builder", "error", err)
		bpm.metrics.RecordBuilderRequestFail()
	}

	envelope, err := eng.GetPayload(ctx, payloadInfo)
	if err != nil {
		log.Error("failed to get payload from engine", "error", err.Error())
		return envelope, nil, err
	}

	if builderResult != nil && builderResult.success {
		log.Info("received payload from builder", "hash", builderResult.envelope.ExecutionPayload.BlockHash.String(), "number", uint64(builderResult.envelope.ExecutionPayload.BlockNumber))
		builderResult.envelope.ParentBeaconBlockRoot = envelope.ParentBeaconBlockRoot
		return envelope, builderResult, nil
	}

	return envelope, builderResult, nil
}

func (bpm *BuilderPayloadManager) weiToGwei(v *eth.Uint256Quantity) uint64 {
	if v == nil {
		return 0
	}
	gweiPerEth := uint256.NewInt(1e9)
	copied := uint256.NewInt(0).Set((*uint256.Int)(v))
	copied.Div(copied, gweiPerEth)
	return uint64(copied.Uint64())
}

func (bpm *BuilderPayloadManager) RecordMetrics(envelope *eth.ExecutionPayloadEnvelope, source opMetrics.PayloadSource) {
	bpm.metrics.RecordSequencerProfit(float64(bpm.weiToGwei(envelope.BlockValue)), source)
	bpm.metrics.RecordPayloadGas(float64(envelope.ExecutionPayload.GasUsed), string(source))
	bpm.metrics.CountSequencedTxsBySource(len(envelope.ExecutionPayload.Transactions), string(source))
}
