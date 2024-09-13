package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	defaultJwtTokenStr = "688f5d737bad920bdfb2fc2f488d6b6209eebda1dae949a8de91398d932c517a"
	defaultOpgethURL   = "http://localhost:8551"
	defaultBuilderURL  = "http://localhost:8552"
)

func main() {
	jwtTokenStr := flag.String("jwt-token", defaultJwtTokenStr, "JWT token to authenticate with the RPC")
	opgethURL := flag.String("opgeth-url", defaultOpgethURL, "URL of the op-geth RPC")
	builderURL := flag.String("builder-url", defaultBuilderURL, "URL of the builder RPC")
	flag.Parse()

	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelDebug, true)))
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

	backend := &backend{clt: opGethRef, builder: builderRef, builderBlock: make(chan *header)}
	if err := srv.RegisterName("eth", &ethBackend{backend}); err != nil {
		log.Error("Failed to register 'eth' backend", "err", err)
		os.Exit(1)
	}
	if err := srv.RegisterName("engine", &engineBackend{backend}); err != nil {
		log.Error("Failed to register 'engine' backend", "err", err)
		os.Exit(1)
	}

	go backend.trackBuilderBlock()

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

// TODO: Not sure why types.Header was not working
type header struct {
	ParentHash common.Hash    `json:"parentHash"`
	Number     hexutil.Uint64 `json:"number"`
}

func (b *backend) trackBuilderBlock() error {
	var lastHead *header

	for {
		<-time.After(20 * time.Millisecond) // TODO: Use ws subscription instead of polling

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

	// notification for builder block
	builderBlock chan *header
}

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

func (b *backend) ForkchoiceUpdatedV3(update engine.ForkchoiceStateV1, params *engine.PayloadAttributes) (*engine.ForkChoiceResponse, error) {
	var result engine.ForkChoiceResponse
	if err := b.clt.Call(&result, "engine_forkchoiceUpdatedV3", update, params); err != nil {
		return nil, err
	}

	log.Info("ForkchoiceUpdatedV3", "payloadID", result.PayloadID)

	// if there are attributes, relay the info to the builder too
	if params != nil {
		go func() {
			tm := time.NewTimer(1 * time.Second)

			for {
				// with stream or polling if syncing.
				var result2 engine.ForkChoiceResponse
				if err := b.builder.Call(&result2, "engine_forkchoiceUpdatedV3", update, params); err != nil {
					log.Error("Failed to call 'builder' engine_forkchoiceUpdatedV3", "err", err)
				} else {
					status := result2.PayloadStatus.Status
					switch status {
					case engine.VALID:
						// The builder has accepted the payload, check if the payloadID matches
						if !bytes.Equal((*result2.PayloadID)[:], (*result.PayloadID)[:]) {
							panic("PayloadID mismatch")
						}
						log.Info("Builder accepted payload", "payloadID", result2.PayloadID)
						return

					case engine.INVALID:
						// The builder has rejected the payload
						log.Error("Builder rejected payload", "payloadID", result2.PayloadID)
					case engine.SYNCING:
						// The builder is syncing, wait and try again on the next block
						select {
						case <-b.builderBlock:
						case <-tm.C:
							return
						}
					}
				}
			}
		}()
	}

	return &result, nil
}

func (b *backend) GetPayloadV3(payloadID engine.PayloadID) (*engine.ExecutionPayloadEnvelope, error) {
	var result engine.ExecutionPayloadEnvelope
	if err := b.clt.Call(&result, "engine_getPayloadV3", payloadID); err != nil {
		return nil, err
	}

	// get the payload from builder
	var result2 engine.ExecutionPayloadEnvelope
	if err := b.builder.Call(&result2, "engine_getPayloadV3", payloadID); err != nil {
		fmt.Println("- err -", err)
		// panic(err) // handle this error, do not retunr error since we have to return at least one payload
		// if the op-geth returned one.
	} else {
		fmt.Println("- builder payload -")
		fmt.Println(result2)
		return &result2, nil
	}

	return &result, nil
}

func (b *backend) NewPayloadV3(params engine.ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash) (engine.PayloadStatusV1, error) {
	var result engine.PayloadStatusV1
	err := b.clt.Call(&result, "engine_newPayloadV3", params, versionedHashes, beaconRoot)
	return result, err
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
