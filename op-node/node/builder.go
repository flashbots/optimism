package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	builderTypes "github.com/ethereum-optimism/optimism/op-node/node/types"
	"github.com/ethereum-optimism/optimism/op-node/p2p"
	opservice "github.com/ethereum-optimism/optimism/op-service"
	"github.com/holiman/uint256"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-node/rollup/builder"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

const PathGetPayload = "/eth/v1/builder/payload"

type BuilderAPIConfig struct {
	Timeout  time.Duration
	Endpoint *url.URL
	Address  common.Address
}

type BuilderAPIClient struct {
	log           log.Logger
	config        *BuilderAPIConfig
	rollupCfg     *rollup.Config
	requestSigner *ecdsa.PrivateKey
}

type BuilderMetrics interface {
	RecordBuilderPayloadBytes(num int)
}

func BuilderSigningHash(cfg *rollup.Config, payloadBytes []byte) (common.Hash, error) {
	return p2p.SigningHash(builderTypes.SigningDomainBuilderV1, cfg.L2ChainID, payloadBytes)
}

func NewBuilderClient(log log.Logger, rollupCfg *rollup.Config, endpoint string, timeout time.Duration, signer *ecdsa.PrivateKey) (*BuilderAPIClient, error) {
	endpointURL, err := url.ParseRequestURI(endpoint)
	if err != nil {
		return nil, fmt.Errorf("builder endpoint is invalid url: %w", err)
	}

	builderAddress := common.Address{}
	if endpointURL.User.Username() == "" {
		log.Warn("builder endpoint is missing builder address")
	} else {
		builderAddress, err = opservice.ParseAddress(endpointURL.User.Username())
		if err != nil {
			log.Warn("builder endpoint is invalid address", "error", err)
		}
	}
	if builderAddress == (common.Address{}) {
		log.Warn("no builder address found, builder payloads will not be verified against known builders")
	}

	config := &BuilderAPIConfig{
		Timeout:  timeout,
		Endpoint: endpointURL,
		Address:  builderAddress,
	}

	return &BuilderAPIClient{
		config:        config,
		rollupCfg:     rollupCfg,
		log:           log,
		requestSigner: signer,
	}, nil
}

func (s *BuilderAPIClient) Enabled() bool {
	return true
}

func (s *BuilderAPIClient) Timeout() time.Duration {
	return s.config.Timeout
}

var _ builder.PayloadBuilder = &BuilderAPIClient{}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *BuilderAPIClient) GetPayload(ctx context.Context, ref eth.L2BlockRef, log log.Logger, metrics builder.BuilderMetrics) (*eth.ExecutionPayloadEnvelope, error) {
	blockResponse := new(builderTypes.VersionedBuilderPayloadResponse)
	slot := ref.Number + 1
	parentHash := ref.Hash

	msg := builderTypes.PayloadRequestV1{
		Slot:       slot,
		ParentHash: parentHash,
	}

	signature, err := s.signBuilderRequest(&msg)
	if err != nil {
		return nil, err
	}

	request := &builderTypes.BuilderPayloadRequest{
		Message:   msg,
		Signature: signature,
	}

	err = s.requestBuilder(ctx, request, blockResponse, metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to request builder: %w", err)
	}

	err = s.validateBlockResponse(blockResponse, ref)
	if err != nil {
		return nil, fmt.Errorf("failed to validate builder response: %w", err)
	}

	envelope, err := getExecutionPayloadEnvelope(blockResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution payload envelope: %w", err)
	}
	return envelope, nil
}

func (s *BuilderAPIClient) signBuilderRequest(request *builderTypes.PayloadRequestV1) ([]byte, error) {
	if s.requestSigner == nil {
		signature := make([]byte, 65)
		return signature, nil
	}

	requestBytes, err := rlp.EncodeToBytes(request)
	if err != nil {
		return nil, err
	}

	hash, err := BuilderSigningHash(s.rollupCfg, requestBytes)
	if err != nil {
		return nil, err
	}

	return crypto.Sign(hash[:], s.requestSigner)
}

func (s *BuilderAPIClient) requestBuilder(ctx context.Context, request *builderTypes.BuilderPayloadRequest, blockResponse *builderTypes.VersionedBuilderPayloadResponse, metrics builder.BuilderMetrics) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	path := s.config.Endpoint.String() + PathGetPayload
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		metrics.RecordBuilderPayloadBytes(len(bodyBytes))
		var errResp httpErrorResp
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			log.Warn("failed to unmarshal error response", "error", err, "response", string(bodyBytes))
			return fmt.Errorf("HTTP error response: %v", resp.Status)
		}
		return fmt.Errorf("HTTP error response: %v", errResp.Message)
	}

	if err := json.Unmarshal(bodyBytes, blockResponse); err != nil {
		return err
	}

	return nil
}

func getExecutionPayloadEnvelope(blockResponse *builderTypes.VersionedBuilderPayloadResponse) (*eth.ExecutionPayloadEnvelope, error) {
	withdrawals := make(types.Withdrawals, 0)
	for _, withdrawal := range blockResponse.ExecutionPayload.Withdrawals {
		withdrawals = append(withdrawals, withdrawal)
	}
	transactions := make([]hexutil.Bytes, 0)
	for _, tx := range blockResponse.ExecutionPayload.Transactions {
		transactions = append(transactions, hexutil.Bytes(tx))
	}
	baseFee, overflow := uint256.FromBig(blockResponse.ExecutionPayload.BaseFeePerGas)
	if overflow {
		return nil, fmt.Errorf("base fee overflow")
	}
	blockValue, overflow := uint256.FromBig(blockResponse.Message.Value)
	if overflow {
		return nil, fmt.Errorf("block value overflow")
	}

	return &eth.ExecutionPayloadEnvelope{
		ExecutionPayload: &eth.ExecutionPayload{
			ParentHash:    blockResponse.ExecutionPayload.ParentHash,
			FeeRecipient:  blockResponse.ExecutionPayload.FeeRecipient,
			StateRoot:     eth.Bytes32(blockResponse.ExecutionPayload.StateRoot),
			ReceiptsRoot:  eth.Bytes32(blockResponse.ExecutionPayload.ReceiptsRoot),
			LogsBloom:     eth.Bytes256(blockResponse.ExecutionPayload.LogsBloom),
			PrevRandao:    eth.Bytes32(blockResponse.ExecutionPayload.Random),
			BlockNumber:   eth.Uint64Quantity(blockResponse.ExecutionPayload.Number),
			GasLimit:      eth.Uint64Quantity(blockResponse.ExecutionPayload.GasLimit),
			GasUsed:       eth.Uint64Quantity(blockResponse.ExecutionPayload.GasUsed),
			Timestamp:     (hexutil.Uint64)(blockResponse.ExecutionPayload.Timestamp),
			ExtraData:     blockResponse.ExecutionPayload.ExtraData,
			BaseFeePerGas: eth.Uint256Quantity(*baseFee),
			BlockHash:     blockResponse.ExecutionPayload.BlockHash,
			Transactions:  transactions,
			Withdrawals:   &withdrawals,
			BlobGasUsed:   (*hexutil.Uint64)(blockResponse.ExecutionPayload.BlobGasUsed),
			ExcessBlobGas: (*hexutil.Uint64)(blockResponse.ExecutionPayload.ExcessBlobGas),
		},
		ParentBeaconBlockRoot: nil,
		BlockValue:            (*hexutil.U256)(blockValue),
	}, nil
}

func (s *BuilderAPIClient) validateBlockResponse(blockResponse *builderTypes.VersionedBuilderPayloadResponse, ref eth.L2BlockRef) error {
	// selects expected data version from the optimism version.
	var expectedVersion builderTypes.SpecVersion
	if s.rollupCfg.IsEcotone(ref.Time) {
		expectedVersion = builderTypes.SpecVersionBedrock
	} else if s.rollupCfg.IsCanyon(ref.Time) {
		expectedVersion = builderTypes.SpecVersionCanyon
	} else {
		expectedVersion = builderTypes.SpecVersionEcotone
	}
	if expectedVersion != blockResponse.Version {
		return fmt.Errorf("expected version %s, got %s", expectedVersion, blockResponse.Version)
	}

	err := s.verifyBuilderSignature(blockResponse.Message, blockResponse.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify builder signature: %w", err)
	}
	return nil
}

func (s *BuilderAPIClient) verifyBuilderSignature(bidTrace *builderTypes.BidTrace, signature []byte) error {
	if s.config.Address != (common.Address{}) && bidTrace.BuilderAddress != s.config.Address {
		return fmt.Errorf("block builder address does not match known builder address")
	}

	payloadBytes, err := rlp.EncodeToBytes(bidTrace)
	if err != nil {
		return fmt.Errorf("could not encode block bid message: %w", err)
	}
	signingHash, err := BuilderSigningHash(s.rollupCfg, payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to compute block signing hash: %w", err)
	}
	pub, err := crypto.SigToPub(signingHash[:], signature)
	if err != nil {
		return fmt.Errorf("invalid builder signature: %w", err)
	}

	addr := crypto.PubkeyToAddress(*pub)
	if addr != bidTrace.BuilderAddress {
		return fmt.Errorf("block bid signature address does not match builder address: %w", err)
	}

	return nil
}
