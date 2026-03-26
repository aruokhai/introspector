package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/sha256"

	"github.com/ArkLabsHQ/introspector-enclave/client"
	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

const defaultManifestURL = "https://github.com/aruokhai/introspector/releases/download/latest/deployment.json"

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: enclave-client [flags] <command>\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  info        Get introspector version and signer pubkey\n")
	fmt.Fprintf(os.Stderr, "  submit-tx   Submit an Ark transaction for signing\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage

	manifestURL := flag.String("manifest", defaultManifestURL, "deployment manifest URL")
	baseURL := flag.String("url", "", "override base URL (skips manifest, requires -pcr0)")
	pcr0 := flag.String("pcr0", "", "expected PCR0 hex (used with -url)")
	insecure := flag.Bool("insecure", false, "skip attestation/PCR0 verification (use plain HTTPS)")
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	ctx := context.Background()

	if *insecure {
		if *baseURL == "" {
			fmt.Fprintf(os.Stderr, "error: -url is required when using -insecure\n")
			os.Exit(1)
		}
		fmt.Println("WARNING: skipping attestation verification (insecure mode)")
		ic := newInsecureClient(*baseURL)
		switch flag.Arg(0) {
		case "info":
			if err := cmdInfoInsecure(ctx, ic); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		case "submit-tx":
			if err := cmdSubmitTxInsecure(ctx, ic, flag.Args()[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", flag.Arg(0))
			os.Exit(1)
		}
		return
	}

	c, err := createClient(ctx, *manifestURL, *baseURL, *pcr0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch flag.Arg(0) {
	case "info":
		if err := cmdInfo(ctx, c); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "submit-tx":
		if err := cmdSubmitTx(ctx, c, flag.Args()[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", flag.Arg(0))
		os.Exit(1)
	}
}

func createClient(ctx context.Context, manifestURL, baseURL, pcr0 string) (*client.Client, error) {
	if baseURL != "" {
		if pcr0 == "" {
			return nil, fmt.Errorf("-pcr0 is required when using -url")
		}
		return client.New(baseURL, client.Options{
			ExpectedPCR0: pcr0,
		})
	}

	fmt.Printf("Fetching manifest from %s ...\n", manifestURL)
	c, err := client.NewFromManifest(ctx, manifestURL, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("create client from manifest: %w", err)
	}
	fmt.Println("Manifest loaded, client created.")
	return c, nil
}

func cmdInfo(ctx context.Context, c *client.Client) error {
	fmt.Println("Calling GET /v1/info ...")
	resp, err := c.Get(ctx, "/v1/info")
	if err != nil {
		return err
	}

	fmt.Printf("\nStatus:             %d\n", resp.StatusCode)
	fmt.Printf("Signature Verified: %v\n", resp.SignatureVerified)

	var info struct {
		Version      string `json:"version"`
		SignerPubkey string `json:"signerPubkey"`
	}
	if err := json.Unmarshal(resp.Body, &info); err != nil {
		fmt.Printf("Raw body: %s\n", resp.Body)
		return nil
	}

	fmt.Printf("Version:            %s\n", info.Version)
	fmt.Printf("Signer Pubkey:      %s\n", info.SignerPubkey)
	return nil
}

// getSignerPubkey fetches the introspector's signer public key via /v1/info.
func getSignerPubkey(ctx context.Context, c *client.Client) (*btcec.PublicKey, error) {
	resp, err := c.Get(ctx, "/v1/info")
	if err != nil {
		return nil, fmt.Errorf("get info: %w", err)
	}

	var info struct {
		SignerPubkey string `json:"signerPubkey"`
	}
	if err := json.Unmarshal(resp.Body, &info); err != nil {
		return nil, fmt.Errorf("parse info: %w", err)
	}

	pubkeyBytes, err := hex.DecodeString(info.SignerPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode signer pubkey hex: %w", err)
	}

	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse signer pubkey: %w", err)
	}

	return pubkey, nil
}

// buildExampleTx builds a valid ark transaction + checkpoints, mirroring the e2e test flow.
// It creates an arkade script that checks output 0 goes to a known destination,
// constructs proper tapscripts with the introspector's tweaked key, and uses
// offchain.BuildTxs to produce correctly structured PSBTs.
func buildExampleTx(signerPubkey *btcec.PublicKey) (string, []string, error) {
	// Generate random keys for the example participants.
	bobPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate bob key: %w", err)
	}
	bobPubKey := bobPrivKey.PubKey()

	destPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate dest key: %w", err)
	}

	// Build the destination P2TR script.
	destPkScript, err := script.P2TRScript(destPrivKey.PubKey())
	if err != nil {
		return "", nil, fmt.Errorf("build dest script: %w", err)
	}

	// Build the arkade script: verify output 0 goes to the destination address.
	// This mirrors the e2e test pattern.
	arkadeScriptBytes, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(destPkScript[2:]). // witness program (x-only pubkey)
		AddOp(arkade.OP_EQUAL).
		Script()
	if err != nil {
		return "", nil, fmt.Errorf("build arkade script: %w", err)
	}

	// Compute the introspector's tweaked public key for this arkade script.
	tweakedPubKey := arkade.ComputeArkadeScriptPublicKey(
		signerPubkey, arkade.ArkadeScriptHash(arkadeScriptBytes),
	)

	// Build the VTXO tapscript: a MultisigClosure with bob + tweaked introspector key.
	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{bobPubKey, tweakedPubKey},
			},
		},
	}

	_, vtxoTapTree, err := vtxoScript.TapTree()
	if err != nil {
		return "", nil, fmt.Errorf("build vtxo tap tree: %w", err)
	}

	closure := vtxoScript.ForfeitClosures()[0]
	closureScript, err := closure.Script()
	if err != nil {
		return "", nil, fmt.Errorf("build closure script: %w", err)
	}

	// Get the merkle proof and control block for the closure.
	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(closureScript).TapHash(),
	)
	if err != nil {
		return "", nil, fmt.Errorf("get merkle proof: %w", err)
	}

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	if err != nil {
		return "", nil, fmt.Errorf("parse control block: %w", err)
	}

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	// Build the signer unroll script (CSVMultisigClosure) for checkpoints.
	unrollKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate unroll key: %w", err)
	}
	unrollClosure := &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{unrollKey.PubKey()},
		},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 10},
	}
	unrollScript, err := unrollClosure.Script()
	if err != nil {
		return "", nil, fmt.Errorf("build unroll script: %w", err)
	}

	// Build ark tx + checkpoint PSBTs using the same function as the e2e tests.
	const amount = int64(10000)
	fakeOutpoint := &wire.OutPoint{
		Hash:  chainhash.Hash{0x01}, // non-zero fake txid
		Index: 0,
	}

	arkTx, checkpointPsbts, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint:           fakeOutpoint,
				Tapscript:          tapscript,
				Amount:             amount,
				RevealedTapscripts: []string{hex.EncodeToString(closureScript)},
			},
		},
		[]*wire.TxOut{
			{Value: amount, PkScript: destPkScript},
		},
		unrollScript,
	)
	if err != nil {
		return "", nil, fmt.Errorf("build txs: %w", err)
	}

	// Set the arkade script field on the ark tx input (same as e2e test).
	if err := txutils.SetArkPsbtField(arkTx, 0, arkade.ArkadeScriptField, arkadeScriptBytes); err != nil {
		return "", nil, fmt.Errorf("set arkade script field: %w", err)
	}

	// Encode everything as base64.
	encodedArkTx, err := arkTx.B64Encode()
	if err != nil {
		return "", nil, fmt.Errorf("encode ark tx: %w", err)
	}

	encodedCheckpoints := make([]string, 0, len(checkpointPsbts))
	for _, cp := range checkpointPsbts {
		encoded, err := cp.B64Encode()
		if err != nil {
			return "", nil, fmt.Errorf("encode checkpoint: %w", err)
		}
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

	fmt.Printf("Arkade script:      %s\n", hex.EncodeToString(arkadeScriptBytes))
	fmt.Printf("Destination:        %s\n", hex.EncodeToString(destPkScript))
	fmt.Printf("Bob pubkey:         %s\n", hex.EncodeToString(schnorr.SerializePubKey(bobPubKey)))
	fmt.Printf("Tweaked signer key: %s\n", hex.EncodeToString(schnorr.SerializePubKey(tweakedPubKey)))

	return encodedArkTx, encodedCheckpoints, nil
}

func cmdSubmitTx(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("submit-tx", flag.ExitOnError)
	tx := fs.String("tx", "", "base64-encoded Ark transaction (PSBT)")
	checkpoints := fs.String("checkpoints", "", "comma-separated base64-encoded checkpoint PSBTs")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var arkTxB64 string
	var cpList []string

	if *tx == "" {
		// Build a proper example transaction using the introspector's signer key.
		fmt.Println("Fetching introspector signer pubkey ...")
		signerPubkey, err := getSignerPubkey(ctx, c)
		if err != nil {
			return err
		}
		fmt.Printf("Signer pubkey:      %s\n\n", hex.EncodeToString(signerPubkey.SerializeCompressed()))

		fmt.Println("Building example ark transaction ...")
		arkTxB64, cpList, err = buildExampleTx(signerPubkey)
		if err != nil {
			return fmt.Errorf("build example tx: %w", err)
		}
		fmt.Println()
	} else {
		arkTxB64 = *tx
		if *checkpoints != "" {
			cpList = strings.Split(*checkpoints, ",")
		}
	}

	payload := struct {
		ArkTx         string   `json:"ark_tx"`
		CheckpointTxs []string `json:"checkpoint_txs,omitempty"`
	}{
		ArkTx:         arkTxB64,
		CheckpointTxs: cpList,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	fmt.Println("Calling POST /v1/tx ...")
	resp, err := c.Post(ctx, "/v1/tx", bytes.NewReader(body))
	if err != nil {
		return err
	}

	fmt.Printf("\nStatus:             %d\n", resp.StatusCode)
	fmt.Printf("Signature Verified: %v\n", resp.SignatureVerified)
	fmt.Printf("Raw body:           %s\n", resp.Body)

	if resp.StatusCode != 200 {
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	var result struct {
		SignedArkTx         string   `json:"signed_ark_tx"`
		SignedCheckpointTxs []string `json:"signed_checkpoint_txs"`
	}
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil
	}

	if result.SignedArkTx != "" {
		fmt.Printf("Signed Ark Tx:      %s\n", result.SignedArkTx)
	}
	for i, cp := range result.SignedCheckpointTxs {
		fmt.Printf("Signed Checkpoint %d: %s\n", i, cp)
	}
	return nil
}

// insecureClient makes plain HTTPS requests without attestation verification
// but still verifies X-Attestation-Signature Schnorr signatures on responses.
type insecureClient struct {
	baseURL    string
	httpClient *http.Client
}

func newInsecureClient(baseURL string) *insecureClient {
	return &insecureClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// verifySignature checks the X-Attestation-Signature header against the
// X-Attestation-Pubkey header. Returns whether verification succeeded.
func verifySignature(resp *http.Response, body []byte) (bool, error) {
	sigHex := resp.Header.Get("X-Attestation-Signature")
	pubkeyHex := resp.Header.Get("X-Attestation-Pubkey")

	if sigHex == "" || pubkeyHex == "" {
		return false, nil
	}

	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return false, fmt.Errorf("decode pubkey: %w", err)
	}
	// Compressed pubkey (33 bytes) → x-only (32 bytes) for Schnorr.
	if len(pubkeyBytes) == 33 {
		pubkeyBytes = pubkeyBytes[1:]
	}
	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return false, fmt.Errorf("parse pubkey: %w", err)
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return false, fmt.Errorf("parse signature: %w", err)
	}

	msgHash := sha256.Sum256(body)
	return sig.Verify(msgHash[:], pubkey), nil
}

func (ic *insecureClient) get(ctx context.Context, path string) (int, []byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ic.baseURL+path, nil)
	if err != nil {
		return 0, nil, false, err
	}
	resp, err := ic.httpClient.Do(req)
	if err != nil {
		return 0, nil, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, false, err
	}
	verified, verr := verifySignature(resp, body)
	if verr != nil {
		fmt.Fprintf(os.Stderr, "  signature check error: %v\n", verr)
	}
	return resp.StatusCode, body, verified, nil
}

func (ic *insecureClient) post(ctx context.Context, path string, body io.Reader) (int, []byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ic.baseURL+path, body)
	if err != nil {
		return 0, nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ic.httpClient.Do(req)
	if err != nil {
		return 0, nil, false, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, false, err
	}
	verified, verr := verifySignature(resp, respBody)
	if verr != nil {
		fmt.Fprintf(os.Stderr, "  signature check error: %v\n", verr)
	}
	return resp.StatusCode, respBody, verified, nil
}

func cmdInfoInsecure(ctx context.Context, ic *insecureClient) error {
	fmt.Println("Calling GET /v1/info (insecure) ...")
	status, body, sigOK, err := ic.get(ctx, "/v1/info")
	if err != nil {
		return err
	}

	fmt.Printf("\nStatus:             %d\n", status)
	fmt.Printf("Signature Verified: %v\n", sigOK)

	var info struct {
		Version      string `json:"version"`
		SignerPubkey string `json:"signerPubkey"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		fmt.Printf("Raw body: %s\n", body)
		return nil
	}

	fmt.Printf("Version:            %s\n", info.Version)
	fmt.Printf("Signer Pubkey:      %s\n", info.SignerPubkey)
	return nil
}

func getSignerPubkeyInsecure(ctx context.Context, ic *insecureClient) (*btcec.PublicKey, error) {
	_, body, _, err := ic.get(ctx, "/v1/info")
	if err != nil {
		return nil, fmt.Errorf("get info: %w", err)
	}

	var info struct {
		SignerPubkey string `json:"signerPubkey"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse info: %w", err)
	}

	pubkeyBytes, err := hex.DecodeString(info.SignerPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode signer pubkey hex: %w", err)
	}

	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse signer pubkey: %w", err)
	}

	return pubkey, nil
}

func cmdSubmitTxInsecure(ctx context.Context, ic *insecureClient, args []string) error {
	fs := flag.NewFlagSet("submit-tx", flag.ExitOnError)
	tx := fs.String("tx", "", "base64-encoded Ark transaction (PSBT)")
	checkpoints := fs.String("checkpoints", "", "comma-separated base64-encoded checkpoint PSBTs")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var arkTxB64 string
	var cpList []string

	if *tx == "" {
		fmt.Println("Fetching introspector signer pubkey ...")
		signerPubkey, err := getSignerPubkeyInsecure(ctx, ic)
		if err != nil {
			return err
		}
		fmt.Printf("Signer pubkey:      %s\n\n", hex.EncodeToString(signerPubkey.SerializeCompressed()))

		fmt.Println("Building example ark transaction ...")
		arkTxB64, cpList, err = buildExampleTx(signerPubkey)
		if err != nil {
			return fmt.Errorf("build example tx: %w", err)
		}
		fmt.Println()
	} else {
		arkTxB64 = *tx
		if *checkpoints != "" {
			cpList = strings.Split(*checkpoints, ",")
		}
	}

	payload := struct {
		ArkTx         string   `json:"ark_tx"`
		CheckpointTxs []string `json:"checkpoint_txs,omitempty"`
	}{
		ArkTx:         arkTxB64,
		CheckpointTxs: cpList,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	fmt.Println("Calling POST /v1/tx (insecure) ...")
	status, body, sigOK, err := ic.post(ctx, "/v1/tx", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}

	fmt.Printf("\nStatus:             %d\n", status)
	fmt.Printf("Signature Verified: %v\n", sigOK)
	fmt.Printf("Raw body:           %s\n", body)

	if status != 200 {
		return fmt.Errorf("request failed with status %d", status)
	}

	var result struct {
		SignedArkTx         string   `json:"signed_ark_tx"`
		SignedCheckpointTxs []string `json:"signed_checkpoint_txs"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	if result.SignedArkTx != "" {
		fmt.Printf("Signed Ark Tx:      %s\n", result.SignedArkTx)
	}
	for i, cp := range result.SignedCheckpointTxs {
		fmt.Printf("Signed Checkpoint %d: %s\n", i, cp)
	}
	return nil
}
