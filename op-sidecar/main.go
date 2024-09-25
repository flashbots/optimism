package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	trace2 "go.opentelemetry.io/otel/trace" // this rename is ugly
)

// Using a custom go.mod because the OTEL library creates conflicts with other op-node dependencies
// Anyway, this project will most likely live outside op-stack too.

var (
	defaultJwtTokenStr = "688f5d737bad920bdfb2fc2f488d6b6209eebda1dae949a8de91398d932c517a"
	defaultOpgethURL   = "http://localhost:8551"
	defaultBuilderURL  = "http://localhost:8552"
)

var (
	jwtTokenStr = flag.String("jwt-token", defaultJwtTokenStr, "JWT token to authenticate with the RPC")
	opgethURL   = flag.String("opgeth-url", defaultOpgethURL, "URL of the op-geth RPC")
	builderURL  = flag.String("builder-url", defaultBuilderURL, "URL of the builder RPC")
	tracing     = flag.Bool("tracing", false, "Enable tracing")
	logLevelStr = flag.String("log-level", "INFO", "")
	boostSync   = flag.Bool("boost-sync", true, "Enable boost sync")
)

func main() {
	flag.Parse()

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(*logLevelStr)); err != nil {
		log.Error("Failed to parse log level", "err", err)
		os.Exit(1)
	}

	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, logLevel, true)))
	srv := rpc.NewServer()

	jwtToken, err := hex.DecodeString(*jwtTokenStr)
	if err != nil {
		log.Error("Failed to decode JWT token", "err", err)
		os.Exit(1)
	}

	opGethRef, err := rpc.DialOptions(context.Background(), *opgethURL, rpc.WithHTTPAuth(node.NewJWTAuth([32]byte(jwtToken))))
	if err != nil {
		log.Error("Failed to connect to RPC", "err", err)
		os.Exit(1)
	}

	builderRef, err := rpc.DialOptions(context.Background(), *builderURL, rpc.WithHTTPAuth(node.NewJWTAuth([32]byte(jwtToken))))
	if err != nil {
		log.Error("Failed to connect to RPC", "err", err)
		os.Exit(1)
	}

	backend := &backend{
		clt:                               opGethRef,
		builder:                           builderRef,
		builderBlock:                      make(chan *header),
		payloadIdToPayloadTracker:         lru.NewCache[engine.PayloadID, *payloadTracker](100),
		payloadTimestampToPayloadTracker:  lru.NewCache[uint64, *payloadTracker](100),
		payloadParentRootToPayloadTracker: lru.NewCache[common.Hash, *payloadTracker](100),
	}
	if err := srv.RegisterName("eth", &ethBackend{backend}); err != nil {
		log.Error("Failed to register 'eth' backend", "err", err)
		os.Exit(1)
	}
	if err := srv.RegisterName("engine", &engineBackend{backend}); err != nil {
		log.Error("Failed to register 'engine' backend", "err", err)
		os.Exit(1)
	}

	go backend.trackBuilderBlock()

	if *tracing {
		if err := startTracing(); err != nil {
			log.Error("Failed to start tracing", "err", err)
			os.Exit(1)
		}
	}

	// Create a new ServeMux
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.ServeHTTP)

	// Set up the server
	server := &http.Server{
		Addr:    ":8081", // You can change the port as needed
		Handler: mux,
	}

	fmt.Println("Starting server on :8081")
	if err := server.ListenAndServe(); err != nil {
		fmt.Println("Server error: ", err)
		os.Exit(1)
	}
}

func startTracing() error {
	headers := map[string]string{
		"content-type": "application/json",
	}

	exporter, err := otlptrace.New(
		context.Background(),
		otlptracehttp.NewClient(
			otlptracehttp.WithEndpoint("localhost:4318"),
			otlptracehttp.WithHeaders(headers),
			otlptracehttp.WithInsecure(),
		),
	)
	if err != nil {
		return fmt.Errorf("creating new exporter: %w", err)
	}

	tracerprovider := trace.NewTracerProvider(
		trace.WithBatcher(
			exporter,
			trace.WithMaxExportBatchSize(trace.DefaultMaxExportBatchSize),
			trace.WithBatchTimeout(trace.DefaultScheduleDelay*time.Millisecond),
			trace.WithMaxExportBatchSize(trace.DefaultMaxExportBatchSize),
		),
		trace.WithResource(
			resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String("builder-boost"),
			),
		),
	)

	otel.SetTracerProvider(tracerprovider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return nil
}

// TODO: Not sure why types.Header was not working
type header struct {
	Hash       common.Hash    `json:"hash"`
	ParentHash common.Hash    `json:"parentHash"`
	Number     hexutil.Uint64 `json:"number"`
	StateRoot  common.Hash    `json:"stateRoot"`
}

func (b *backend) trackBuilderBlock() error {
	var lastHead *header

	for {
		// TODO: This is not ideal, a better solution would be to use a ws connection. But, I did not
		// wanted to deal with reconnecting for now.
		<-time.After(20 * time.Millisecond)

		var newHead *header
		if err := b.builder.Call(&newHead, "eth_getBlockByNumber", rpc.LatestBlockNumber, false); err == nil {
			if lastHead == nil || newHead.Number > lastHead.Number {
				lastHead = newHead

				select {
				case b.builderBlock <- newHead:
				default:
				}
			}
		}
	}
}

type backend struct {
	clt     *rpc.Client
	builder *rpc.Client

	// Ideally, we only keep one payload a time, since only one block is being built at a time.
	// But, since I am not sure about the workflow between op-node <> op-geth, we will keep multiple
	// payload entries for now. Using an LRU cache so that I do not have to worry about cleaning up.
	payloadIdToPayloadTracker         *lru.Cache[engine.PayloadID, *payloadTracker]
	payloadTimestampToPayloadTracker  *lru.Cache[uint64, *payloadTracker]
	payloadParentRootToPayloadTracker *lru.Cache[common.Hash, *payloadTracker]

	// notification for builder block
	builderBlock chan *header
}

type payloadTracker struct {
	builderHasPayload bool

	traceCtx  context.Context
	traceSpan trace2.Span

	deliveredCh chan struct{}
}

func (p *payloadTracker) Close() {
	p.traceSpan.End()
}

var (
	tracer = otel.Tracer("builder-boost")
)

func getCallTraceCtx(ctx context.Context) context.Context {
	// from the context extract the tracepoint to send over the http request
	// and create a new context with that kv to be sent over jsonrpc
	headers := http.Header{}

	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, propagation.HeaderCarrier(headers))

	return rpc.NewContextWithHeaders(ctx, headers)
}

func (b *backend) ForkchoiceUpdatedV3(update engine.ForkchoiceStateV1, params *engine.PayloadAttributes) (*engine.ForkChoiceResponse, error) {
	var result engine.ForkChoiceResponse
	if err := b.clt.Call(&result, "engine_forkchoiceUpdatedV3", update, params); err != nil {
		return nil, err
	}

	log.Info("ForkchoiceUpdatedV3", "head", update.HeadBlockHash, "payloadID", result.PayloadID)

	// if there are attributes, relay the info to the builder too
	if params != nil && !params.NoTxPool {
		log.Info("ForkchoiceUpdatedV3 with attributes", "parentBlock", params.BeaconRoot, "timestamp", params.Timestamp)

		_, ok := b.payloadParentRootToPayloadTracker.Get(update.HeadBlockHash)
		if ok {
			// Log it for now, later on figure out what we do here.
			log.Error("Payload already exists for this parent block", "parentBlock", params.BeaconRoot)
		}

		// Start the trace with contextual attributes
		traceCtx, span := tracer.Start(context.Background(), "fcu")
		span.SetAttributes(attribute.Int64("timestamp", int64(params.Timestamp)))
		span.SetAttributes(attribute.String("headBlockHash", update.HeadBlockHash.String()))
		span.SetAttributes(attribute.String("parentHash", params.BeaconRoot.String()))
		span.SetAttributes(attribute.String("payloadID", result.PayloadID.String()))

		// get the last block of this fella
		var lastBlock header
		if err := b.builder.Call(&lastBlock, "eth_getBlockByNumber", rpc.LatestBlockNumber, false); err != nil {
			log.Error("Failed to get last block", "err", err)

			// just return the default op-geth response
			return &result, nil
		}

		if result.PayloadID == nil {
			panic(fmt.Sprintf("BUG: Unexpected nil payloadID in ForkchoiceUpdatedV3 result with params: %v", result))
		}

		// create a new payload lifecycle for this payload and store it
		pTracker := &payloadTracker{traceCtx: traceCtx, traceSpan: span, deliveredCh: make(chan struct{})}

		b.payloadIdToPayloadTracker.Add(*result.PayloadID, pTracker)
		b.payloadParentRootToPayloadTracker.Add(update.HeadBlockHash, pTracker)

		go func() {
			_, span := tracer.Start(traceCtx, "wait_for_builder")
			defer span.End()

			now := time.Now()
			tm := time.NewTimer(1 * time.Second)

			for {
				// if the payload is delivered already we were late for syncing.
				select {
				case <-pTracker.deliveredCh:
					return
				default:
				}

				// with stream or polling if syncing.
				var result2 engine.ForkChoiceResponse

				if err := b.builder.CallContext(getCallTraceCtx(traceCtx), &result2, "engine_forkchoiceUpdatedV3", update, params); err != nil {
					log.Error("Failed to call 'builder' engine_forkchoiceUpdatedV3", "err", err)
				} else {
					status := result2.PayloadStatus.Status
					switch status {
					case engine.VALID:
						// The builder has accepted the payload, check if the payloadID matches
						if !bytes.Equal((*result2.PayloadID)[:], (*result.PayloadID)[:]) {
							panic("PayloadID mismatch")
						}
						log.Info("Builder accepted payload", "payloadID", result2.PayloadID, "duration", time.Since(now))

						// update the payload tracker to indicate the builder has the payload
						val, ok := b.payloadIdToPayloadTracker.Get(*result.PayloadID)
						if ok {
							val.builderHasPayload = true // TODO: data race
						}

						return

					case engine.INVALID:
						// The builder has rejected the payload
						log.Error("Builder rejected payload", "payloadID", result2.PayloadID)
					case engine.SYNCING:
						log.Debug("Builder is syncing", "payloadID", result2.PayloadID)
						// The builder is syncing, wait and try again on the next block
						select {
						case <-b.builderBlock:
							// TODO: There is a small race condition here, if multiple fcu with params get triggered
							// at the same time, this channel will only trigger once and only one of the routines
							// will continue. This is fine for now, since anyway most of the fcu are pretty much sequential.
						case <-tm.C:
							return
						}
					}
				}
			}
		}()
	} else if *boostSync {
		// TODO: As with the engine_newPayloadV3 call, this fails if the builder node is not synced with the chain.
		var result engine.ForkChoiceResponse
		if err := b.builder.Call(&result, "engine_forkchoiceUpdatedV3", update, params); err != nil {
			return nil, err
		}
	}

	return &result, nil
}

func (b *backend) GetPayloadV3(payloadID engine.PayloadID) (*engine.ExecutionPayloadEnvelope, error) {
	var opGethPayload engine.ExecutionPayloadEnvelope
	if err := b.clt.Call(&opGethPayload, "engine_getPayloadV3", payloadID); err != nil {
		return nil, err
	}

	// get the payload tracker instance
	payloadTracker, ok := b.payloadIdToPayloadTracker.Get(payloadID)
	if !ok {
		// This can happen if the op-node is building blocks with NoTxPool which are deterministic blocks
		// and we are not sending them to op-builder since the builder cannot compete with the op-geth node.
		log.Debug("Payload tracker not found", "payloadID", payloadID)
		return &opGethPayload, nil
	}

	_, span := tracer.Start(payloadTracker.traceCtx, "get_payload")
	defer span.End()

	log.Info("GetPayloadV3", "payloadID", payloadID, "builderHasPayload", payloadTracker.builderHasPayload)

	if !payloadTracker.builderHasPayload {
		// The builder did not sync up to deliver the block, return the op-geth payload
		close(payloadTracker.deliveredCh) // Close the channel so that the builder does not try to build this block.
		return &opGethPayload, nil
	}

	// TODO: We can query this in parallel with the op-geth node.
	var builderPayload engine.ExecutionPayloadEnvelope
	if err := b.builder.Call(&builderPayload, "engine_getPayloadV3", payloadID); err != nil {
		log.Error("Failed to retrieve 'builder' engine_getPayloadV3", "err", err)
		return &opGethPayload, nil
	}

	log.Info("builder payload", "hash", builderPayload.ExecutionPayload.BlockHash)

	{
		// Send the payload to the op-geth node with engine_newPayload to make sure it is valid for him too.
		// Otherwise, we do not want to risk the network to a halt since op-node will not be able to propose the block.
		// If we cannot validate it, return the one from op-geth since that one has already being validated.
		if err := b.clt.Call(nil, "engine_newPayloadV3", builderPayload.ExecutionPayload, []common.Hash{}, builderPayload.ParentBeaconBlockRoot); err != nil {
			log.Error("Failed to validate builder block on op-geth", "err", err)
			return &opGethPayload, nil
		}
	}

	// keep a reverse index to map the builder-payload timestamp to the payload tracker since we want to also
	// account for the span in newPayloadV3 but we do not have the payloadID there.
	b.payloadTimestampToPayloadTracker.Add(builderPayload.ExecutionPayload.Timestamp, payloadTracker)

	return &builderPayload, nil
}

func (b *backend) NewPayloadV3(params engine.ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash) (engine.PayloadStatusV1, error) {
	// trace the time it takes for new payload if there is a payload tracker for this payload (check the timestamp)
	payloadTracker, ok := b.payloadTimestampToPayloadTracker.Get(params.Timestamp)
	if ok {
		_, span := tracer.Start(payloadTracker.traceCtx, "new_payload")
		defer func() {
			span.End()
			// close also the payload tracker to signal the end of the payload lifecycle
			payloadTracker.Close()
		}()
	}

	if *boostSync {
		// TODO: This fails if the builder node is not synced with the chain.
		// We send both newPayload and fcu (withotu attributes) to advance the builder EL node
		// at the same time we advance the proposer node.
		var result1 engine.PayloadStatusV1
		if err := b.builder.Call(&result1, "engine_newPayloadV3", params, versionedHashes, beaconRoot); err != nil {
			log.Error("Failed to sync new payload with engine", "err", err)
		}
	}

	var result engine.PayloadStatusV1
	err := b.clt.Call(&result, "engine_newPayloadV3", params, versionedHashes, beaconRoot)
	return result, err
}

// The next methods are just wrappers to relay the engine calls from the proposer op-node to its op-geth.

func (b *backend) ChainId() (*big.Int, error) {
	return ethclient.NewClient(b.clt).ChainID(context.Background())
}

func (b *backend) GetBlockByNumber(number rpc.BlockNumber, full bool) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := b.clt.Call(&result, "eth_getBlockByNumber", number, full)
	return result, err
}

func (b *backend) GetBlockByHash(hash common.Hash, full bool) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := b.clt.Call(&result, "eth_getBlockByHash", hash, full)
	return result, err
}

func (b *backend) GetProof(address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	var result AccountResult
	err := b.clt.Call(&result, "eth_getProof", address, storageKeys, blockNrOrHash)
	return &result, err
}

type backendStub interface {
	ChainId() (*big.Int, error)
	GetBlockByNumber(number rpc.BlockNumber, full bool) (map[string]interface{}, error)
	GetBlockByHash(hash common.Hash, full bool) (map[string]interface{}, error)
	GetProof(address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error)
	ForkchoiceUpdatedV3(update engine.ForkchoiceStateV1, params *engine.PayloadAttributes) (*engine.ForkChoiceResponse, error)
	GetPayloadV3(payloadID engine.PayloadID) (*engine.ExecutionPayloadEnvelope, error)
	NewPayloadV3(params engine.ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash) (engine.PayloadStatusV1, error)
}

type engineBackend struct {
	stub backendStub
}

func (e *engineBackend) ForkchoiceUpdatedV3(update engine.ForkchoiceStateV1, params *engine.PayloadAttributes) (*engine.ForkChoiceResponse, error) {
	return e.stub.ForkchoiceUpdatedV3(update, params)
}

func (e *engineBackend) GetPayloadV3(payloadID engine.PayloadID) (*engine.ExecutionPayloadEnvelope, error) {
	return e.stub.GetPayloadV3(payloadID)
}

func (e *engineBackend) NewPayloadV3(params engine.ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash) (engine.PayloadStatusV1, error) {
	return e.stub.NewPayloadV3(params, versionedHashes, beaconRoot)
}

type ethBackend struct {
	stub backendStub
}

func (b *ethBackend) ChainId() *hexutil.Big {
	id, err := b.stub.ChainId()
	if err != nil {
		return nil
	}
	return (*hexutil.Big)(id)
}

func (b *ethBackend) GetBlockByNumber(number rpc.BlockNumber, full bool) (map[string]interface{}, error) {
	return b.stub.GetBlockByNumber(number, full)
}

func (b *ethBackend) GetBlockByHash(hash common.Hash, full bool) (map[string]interface{}, error) {
	return b.stub.GetBlockByHash(hash, full)
}

// Result structs for GetProof (It needs to be here because it is behind internal in geth)
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

func (b *ethBackend) GetProof(address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	return b.stub.GetProof(address, storageKeys, blockNrOrHash)
}
