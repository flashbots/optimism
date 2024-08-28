package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum-optimism/optimism/op-node/rollup/builder"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// isDepositTx checks an opaqueTx to determine if it is a Deposit Transaction
// It has to return an error in the case the transaction is empty
func isDepositTx(opaqueTx eth.Data) (bool, error) {
	if len(opaqueTx) == 0 {
		return false, errors.New("empty transaction")
	}
	return opaqueTx[0] == types.DepositTxType, nil
}

// lastDeposit finds the index of last deposit at the start of the transactions.
// It walks the transactions from the start until it finds a non-deposit tx.
// An error is returned if any looked at transaction cannot be decoded
func lastDeposit(txns []eth.Data) (int, error) {
	var lastDeposit int
	for i, tx := range txns {
		deposit, err := isDepositTx(tx)
		if err != nil {
			return 0, fmt.Errorf("invalid transaction at idx %d", i)
		}
		if deposit {
			lastDeposit = i
		} else {
			break
		}
	}
	return lastDeposit, nil
}

func sanityCheckPayload(payload *eth.ExecutionPayload) error {
	// Sanity check payload before inserting it
	if len(payload.Transactions) == 0 {
		return errors.New("no transactions in returned payload")
	}
	if payload.Transactions[0][0] != types.DepositTxType {
		return fmt.Errorf("first transaction was not deposit tx. Got %v", payload.Transactions[0][0])
	}
	// Ensure that the deposits are first
	lastDeposit, err := lastDeposit(payload.Transactions)
	if err != nil {
		return fmt.Errorf("failed to find last deposit: %w", err)
	}
	// Ensure no deposits after last deposit
	for i := lastDeposit + 1; i < len(payload.Transactions); i++ {
		tx := payload.Transactions[i]
		deposit, err := isDepositTx(tx)
		if err != nil {
			return fmt.Errorf("failed to decode transaction idx %d: %w", i, err)
		}
		if deposit {
			return fmt.Errorf("deposit tx (%d) after other tx in l2 block with prev deposit at idx %d", i, lastDeposit)
		}
	}
	return nil
}

var ErrEngineSyncing = errors.New("engine is syncing")

type BlockInsertionErrType uint

const (
	// BlockInsertOK indicates that the payload was successfully executed and appended to the canonical chain.
	BlockInsertOK BlockInsertionErrType = iota
	// BlockInsertTemporaryErr indicates that the insertion failed but may succeed at a later time without changes to the payload.
	BlockInsertTemporaryErr
	// BlockInsertPrestateErr indicates that the pre-state to insert the payload could not be prepared, e.g. due to missing chain data.
	BlockInsertPrestateErr
	// BlockInsertPayloadErr indicates that the payload was invalid and cannot become canonical.
	BlockInsertPayloadErr
)

// startPayload starts an execution payload building process in the provided Engine, with the given attributes.
// The severity of the error is distinguished to determine whether the same payload attributes may be re-attempted later.
func startPayload(ctx context.Context, eng ExecEngine, fc eth.ForkchoiceState, attrs *eth.PayloadAttributes) (id eth.PayloadID, errType BlockInsertionErrType, err error) {
	fcRes, err := eng.ForkchoiceUpdate(ctx, &fc, attrs)
	if err != nil {
		var inputErr eth.InputError
		if errors.As(err, &inputErr) {
			switch inputErr.Code {
			case eth.InvalidForkchoiceState:
				return eth.PayloadID{}, BlockInsertPrestateErr, fmt.Errorf("pre-block-creation forkchoice update was inconsistent with engine, need reset to resolve: %w", inputErr.Unwrap())
			case eth.InvalidPayloadAttributes:
				return eth.PayloadID{}, BlockInsertPayloadErr, fmt.Errorf("payload attributes are not valid, cannot build block: %w", inputErr.Unwrap())
			default:
				if inputErr.Code.IsEngineError() {
					return eth.PayloadID{}, BlockInsertPrestateErr, fmt.Errorf("unexpected engine error code in forkchoice-updated response: %w", err)
				} else {
					return eth.PayloadID{}, BlockInsertTemporaryErr, fmt.Errorf("unexpected generic error code in forkchoice-updated response: %w", err)
				}
			}
		} else {
			return eth.PayloadID{}, BlockInsertTemporaryErr, fmt.Errorf("failed to create new block via forkchoice: %w", err)
		}
	}

	switch fcRes.PayloadStatus.Status {
	// TODO(proto): snap sync - specify explicit different error type if node is syncing
	case eth.ExecutionInvalid, eth.ExecutionInvalidBlockHash:
		return eth.PayloadID{}, BlockInsertPayloadErr, eth.ForkchoiceUpdateErr(fcRes.PayloadStatus)
	case eth.ExecutionValid:
		id := fcRes.PayloadID
		if id == nil {
			return eth.PayloadID{}, BlockInsertTemporaryErr, errors.New("nil id in forkchoice result when expecting a valid ID")
		}
		return *id, BlockInsertOK, nil
	case eth.ExecutionSyncing:
		return eth.PayloadID{}, BlockInsertTemporaryErr, ErrEngineSyncing
	default:
		return eth.PayloadID{}, BlockInsertTemporaryErr, eth.ForkchoiceUpdateErr(fcRes.PayloadStatus)
	}
}

type PayloadRequestResult struct {
	success  bool
	envelope *eth.ExecutionPayloadEnvelope
	error    error
}

func requestPayloadFromBuilder(ctx context.Context, builder builder.PayloadBuilder, l2head eth.L2BlockRef, log log.Logger, metrics Metrics, results chan<- *PayloadRequestResult) {
	start := time.Now()
	payload, err := builder.GetPayload(ctx, l2head, log, metrics)
	metrics.RecordBuilderRequestTime(time.Since(start))
	if err != nil {
		results <- &PayloadRequestResult{success: false, error: err}
		return
	}
	results <- &PayloadRequestResult{success: true, envelope: payload}
}

// makes parallel request to builder and engine to get the payload
func getPayloadWithBuilderPayload(ctx context.Context, log log.Logger, eng ExecEngine, payloadInfo eth.PayloadInfo, l2head eth.L2BlockRef, builder builder.PayloadBuilder, metrics Metrics) (
	*eth.ExecutionPayloadEnvelope, *PayloadRequestResult, error) {
	// if builder is not enabled, return early with default path.
	if !builder.Enabled() {
		payload, err := eng.GetPayload(ctx, payloadInfo)
		return payload, nil, err
	}

	log.Debug("requesting payload from builder", l2head.String(), "payloadInfo", payloadInfo)
	ctxTimeout, cancel := context.WithTimeout(ctx, builder.Timeout())
	defer cancel()

	result := make(chan *PayloadRequestResult, 1)
	go requestPayloadFromBuilder(ctxTimeout, builder, l2head, log, metrics, result)
	envelope, err := eng.GetPayload(ctx, payloadInfo)
	if err != nil {
		log.Error("failed to get payload from engine", "error", err.Error())
		return envelope, nil, err
	}

	// select the payload from builder if possible
	select {
	case <-ctxTimeout.Done():
		metrics.RecordBuilderRequestTimeout()
		log.Warn("builder request timed out", "error", ctxTimeout.Err())
		return envelope, &PayloadRequestResult{success: false, error: ctxTimeout.Err()}, nil
	case builderPayload := <-result:
		if builderPayload.error != nil {
			metrics.RecordBuilderRequestFail()
			log.Warn("failed to get payload from builder", "error", builderPayload.error)
			return envelope, builderPayload, nil
		}
		log.Info("received payload from builder", "hash", builderPayload.envelope.ExecutionPayload.BlockHash.String(), "number", uint64(builderPayload.envelope.ExecutionPayload.BlockNumber))
		// TODO: ParentBeaconBlockRoot should have been delivered by the builder. Revisit when the builder API spec supports BeaconRoot.
		builderPayload.envelope.ParentBeaconBlockRoot = envelope.ParentBeaconBlockRoot
		return envelope, builderPayload, nil
	}
}
