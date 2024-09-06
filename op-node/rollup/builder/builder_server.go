package builder

// IT is here because of circular import issues

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	builderTypes "github.com/ethereum-optimism/optimism/op-node/node/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gorilla/mux"
)

type BuilderServerImpl interface {
	GetPayload(request *builderTypes.BuilderPayloadRequest) (*builderTypes.VersionedBuilderPayloadResponse, error)
}

type BuilderService struct {
	srv             *http.Server
	builder         BuilderServerImpl
	proposerAddress common.Address
}

func NewService(listenAddr string, builder BuilderServerImpl, proposerAddress common.Address) *BuilderService {
	srv := &BuilderService{
		builder:         builder,
		proposerAddress: proposerAddress,
		srv: &http.Server{
			Addr: listenAddr,
		},
	}

	router := mux.NewRouter()
	router.HandleFunc("/eth/v1/builder/payload", srv.handleGetPayload).Methods(http.MethodPost)
	srv.srv.Handler = router

	return srv
}

func (s *BuilderService) Start() error {
	if s.srv != nil {
		log.Info("Service started")
		go s.srv.ListenAndServe()
	}
	return nil
}

func (s *BuilderService) Stop() error {
	if s.srv != nil {
		s.srv.Close()
	}
	return nil
}

func (s *BuilderService) verifyProposerSignature(payload *builderTypes.BuilderPayloadRequest) error {
	return nil

	// TODO: FIX

	/*
		msg, err := rlp.EncodeToBytes(payload.Message)
		if err != nil {
			return fmt.Errorf("could not encode message, %w", err)
		}
		signingHash, err := BuilderSigningHash(b.eth.Config(), msg)
		if err != nil {
			return fmt.Errorf("could not get signing hash, %w", err)
		}
		recoveredPubkey, err := crypto.SigToPub(signingHash[:], payload.Signature)
		if err != nil {
			return fmt.Errorf("could not recover pubkey, %w", err)
		}
		recoveredAddress := crypto.PubkeyToAddress(*recoveredPubkey)
		if recoveredAddress != s.proposerAddress {
			return fmt.Errorf("recovered address does not match proposer address, %s != %s", recoveredAddress, s.proposerAddress)
		}
		return nil
	*/
}

func (s *BuilderService) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	// start := time.Now()
	//success := false

	defer func() {
		// Collect metrics at end of request
		// updateServeTimeHistogram("getPayload", success, time.Since(start))
	}()

	// Read the body first, so we can decode it later
	body, err := io.ReadAll(req.Body)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			log.Error("getPayload request failed to decode (i/o timeout)", "err", err)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		log.Error("could not read body of request from the op node", "err", err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Decode payload
	payload := new(builderTypes.BuilderPayloadRequest)
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(payload); err != nil {
		log.Warn("failed to decode getPayload request", "err", err)
		respondError(w, http.StatusBadRequest, "failed to decode payload")
		return
	}

	log.Info("received handle get payload request", "slot", payload.Message.Slot, "parent", payload.Message.ParentHash.String())

	bestSubmission, err := s.builder.GetPayload(payload)
	if err != nil {
		handleError(w, err)
		// updateServeTimeHistogram("getPayload", false, time.Since(start))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(bestSubmission); err != nil {
		// updateServeTimeHistogram("getPayload", false, time.Since(start))
		log.Error("could not encode response", "err", err)
		respondError(w, http.StatusInternalServerError, "could not encode response")
		return
	}
	//updateServeTimeHistogram("getPayload", true, time.Since(start))
}

var (
	ErrIncorrectSlot         = errors.New("incorrect slot")
	ErrNoPayloads            = errors.New("no payloads")
	ErrSlotFromPayload       = errors.New("could not get slot from payload")
	ErrSlotMismatch          = errors.New("slot mismatch")
	ErrParentHashFromPayload = errors.New("could not get parent hash from payload")
	ErrParentHashMismatch    = errors.New("parent hash mismatch")
)

func handleError(w http.ResponseWriter, err error) {
	var errorMsg string
	var status int
	switch {
	case errors.Is(err, ErrIncorrectSlot):
		errorMsg = err.Error()
		status = http.StatusBadRequest
	case errors.Is(err, ErrNoPayloads):
		errorMsg = err.Error()
		status = http.StatusNotFound
	case errors.Is(err, ErrSlotFromPayload):
		errorMsg = err.Error()
		status = http.StatusInternalServerError
	case errors.Is(err, ErrSlotMismatch):
		errorMsg = err.Error()
		status = http.StatusBadRequest
	case errors.Is(err, ErrParentHashFromPayload):
		errorMsg = err.Error()
		status = http.StatusInternalServerError
	case errors.Is(err, ErrParentHashMismatch):
		errorMsg = err.Error()
		status = http.StatusBadRequest
	default:
		errorMsg = "error processing request"
		status = http.StatusInternalServerError
	}

	respondError(w, status, errorMsg)
}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(httpErrorResp{code, message}); err != nil {
		http.Error(w, message, code)
	}
}
