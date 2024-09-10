package builder

import (
	"context"
	"errors"
	"time"

	"github.com/ethereum-optimism/optimism/op-node/rollup/engine"
	"github.com/ethereum-optimism/optimism/op-node/rollup/event"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/log"
)

type Metrics interface {
	RecordBuilderPayloadBytes(num int)
}

type PayloadBuilder interface {
	Enabled() bool
	Timeout() time.Duration
	GetPayload(ctx context.Context, ref eth.L2BlockRef, log log.Logger, metrics Metrics) (*eth.ExecutionPayloadEnvelope, error)
}

type NoOpBuilder struct{}

func (n *NoOpBuilder) GetPayload(_ context.Context, _ eth.L2BlockRef, _ log.Logger, _ Metrics) (*eth.ExecutionPayloadEnvelope, error) {
	return nil, errors.New("Builder not enabled")
}

func (n *NoOpBuilder) Enabled() bool {
	return false
}

func (n *NoOpBuilder) Timeout() time.Duration {
	return 0
}

var _ PayloadBuilder = &NoOpBuilder{}

type Builder struct {
	metrics Metrics

	ctx    context.Context
	log    log.Logger
	client PayloadBuilder

	emitter event.Emitter
}

func NewBuilder(log log.Logger, ctx context.Context, client PayloadBuilder, metrics Metrics) *Builder {
	return &Builder{
		log:     log,
		ctx:     ctx,
		client:  client,
		metrics: metrics,
	}
}

func (b *Builder) AttachEmitter(emitter event.Emitter) {
	b.emitter = emitter
}

func (b *Builder) OnEvent(ev event.Event) bool {
	switch x := ev.(type) {
	case engine.BuildStartedEvent:
		b.onBuildStarted(x)
	default:
		return false
	}
	return true
}

func (b Builder) onBuildStarted(ev engine.BuildStartedEvent)
