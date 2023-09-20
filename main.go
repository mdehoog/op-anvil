package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum-optimism/optimism/op-chain-ops/genesis"
	opnodeflags "github.com/ethereum-optimism/optimism/op-node/flags"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"

	"github.com/mdehoog/op-anvil/config"
	l1genesis "github.com/mdehoog/op-anvil/genesis"
	"github.com/mdehoog/op-anvil/node"
	"github.com/mdehoog/op-anvil/util"
)

const version = "v0.0.0"

var (
	//L1ForkUrl = &cli.StringFlag{
	//	Name:  "l1.fork-url",
	//	Usage: "Address of L1 JSON-RPC endpoint to fork",
	//	Value: "https://nodes-proxy-development.cbhq.net/geth/testnet-archive-goerli-lighthouse",
	//}
	//L2ForkURL = &cli.StringFlag{
	//	Name:  "l2.fork-url",
	//	Usage: "Address of L2 JSON-RPC endpoint to fork",
	//	Value: "https://goerli.base.org",
	//}
	L1Port = &cli.IntFlag{
		Name:  "l1.port",
		Usage: "Port to use for L1 Anvil",
		Value: 7545,
	}
	L2Port = &cli.IntFlag{
		Name:  "l2.port",
		Usage: "Port to use for L2 Anvil",
		Value: 8545,
	}
	DeployConfig = &cli.StringFlag{
		Name:  "deploy-config",
		Usage: "Path to op-stack deploy config file",
	}
)
var flags = []cli.Flag{
	//L1ForkUrl,
	//L2ForkURL,
	L1Port,
	L2Port,
	DeployConfig,
}

func main() {
	log.Root().SetHandler(
		log.LvlFilterHandler(
			log.LvlInfo,
			log.StreamHandler(os.Stdout, log.TerminalFormat(true)),
		),
	)

	app := cli.NewApp()
	app.Version = version
	app.Flags = flags
	app.Name = "op-anvil"
	app.Usage = "Anvil wrapper for op-stack"
	app.Description = "Coordinates two anvil process (one each for L1 and L2) for forking op-stack chains"
	app.Action = action

	err := app.Run(os.Args)
	if err != nil {
		log.Crit("Application failed", "message", err)
	}
}

func action(cliCtx *cli.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//l1ForkUrl := cliCtx.String(L1ForkUrl.Name)
	//l2ForkURL := cliCtx.String(L2ForkURL.Name)
	l1Port := cliCtx.Int(L1Port.Name)
	l2Port := cliCtx.Int(L2Port.Name)

	deployConfigPath := cliCtx.String(DeployConfig.Name)
	var deployConfig *genesis.DeployConfig
	var err error
	if deployConfigPath != "" {
		deployConfig, err = genesis.NewDeployConfig(deployConfigPath)
	} else {
		deployConfig, err = config.DefaultDeployConfig()
	}
	if err != nil {
		return err
	}

	dump, l1Deployments, err := l1genesis.L1Alloc()
	if err != nil {
		return err
	}
	deployConfig.SetDeployments(l1Deployments)

	handler := log.Root().GetHandler()
	ignoreHandler := log.FuncHandler(func(r *log.Record) error { return nil })
	log.Root().SetHandler(ignoreHandler)
	l1Genesis, err := genesis.BuildL1DeveloperGenesis(deployConfig, dump, l1Deployments, false)
	log.Root().SetHandler(handler)
	if err != nil {
		return err
	}
	l1GenesisFile, err := os.CreateTemp("", "l1-genesis-*.json")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(l1GenesisFile.Name())
	}()
	enc := json.NewEncoder(l1GenesisFile)
	if err = enc.Encode(l1Genesis); err != nil {
		return err
	}
	_ = l1GenesisFile.Close()

	a1, c1, err := anvil(ctx, l1Port, l1GenesisFile.Name(), color.YellowString("L1: "), 12)
	if err != nil {
		log.Crit("Failed to start L1 anvil", "message", err)
	}
	defer func() {
		_ = a1.Process.Signal(syscall.SIGINT)
		_ = a1.Wait()
	}()

	l1GenesisBlock, err := c1.BlockByNumber(ctx, big.NewInt(0))
	if err != nil {
		return err
	}
	log.Root().SetHandler(ignoreHandler)
	l2Genesis, err := genesis.BuildL2Genesis(deployConfig, l1GenesisBlock)
	log.Root().SetHandler(handler)
	if err != nil {
		return err
	}
	l2GenesisFile, err := os.CreateTemp("", "l2-genesis-*.json")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(l2GenesisFile.Name())
	}()
	enc = json.NewEncoder(l2GenesisFile)
	if err = enc.Encode(l2Genesis); err != nil {
		return err
	}
	_ = l2GenesisFile.Close()

	l2AnvilPort, err := freePort()
	if err != nil {
		return err
	}
	a2, c2, err := anvil(ctx, l2AnvilPort, l2GenesisFile.Name(), color.CyanString("L2: "), 0)
	if err != nil {
		log.Crit("Failed to start L2 anvil", "message", err)
	}
	defer func() {
		_ = a2.Process.Signal(syscall.SIGINT)
		_ = a2.Wait()
	}()

	l2GenesisBlock, err := c2.BlockByNumber(ctx, big.NewInt(0))
	if err != nil {
		return err
	}
	rollupConfig, err := deployConfig.RollupConfig(l1GenesisBlock, l2GenesisBlock.Hash(), l2GenesisBlock.Number().Uint64())
	if err != nil {
		return err
	}
	if err := rollupConfig.Check(); err != nil {
		return fmt.Errorf("generated rollup config does not pass validation: %w", err)
	}
	l2RollupFile, err := os.CreateTemp("", "l2-rollup-*.json")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(l2RollupFile.Name())
	}()
	enc = json.NewEncoder(l2RollupFile)
	if err = enc.Encode(rollupConfig); err != nil {
		return err
	}
	_ = l2RollupFile.Close()
	signer := types.LatestSignerForChainID(rollupConfig.L2ChainID)

	eng := NewAnvilEngine(c2, signer)

	go func() {
		u, _ := url.Parse(fmt.Sprintf("http://localhost:%d", l2AnvilPort))
		proxy := &httputil.ReverseProxy{}
		proxy.Rewrite = func(r *httputil.ProxyRequest) {
			body, err := io.ReadAll(r.Out.Body)
			if err != nil {
				return
			}
			body = eng.ModifyRequest(body)
			r.Out.Body = io.NopCloser(bytes.NewBuffer(body))
			r.Out.URL = u
		}
		proxy.ModifyResponse = func(r *http.Response) error {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return err
			}
			body = eng.ModifyResponse(body)
			r.Body = io.NopCloser(bytes.NewBuffer(body))
			return nil
		}
		err = http.ListenAndServe(fmt.Sprintf(":%d", l2Port), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(body))
			if err != nil {
				proxy.ServeHTTP(rw, r)
				return
			}
			var req util.RPCReq
			if err = json.Unmarshal(body, &req); err != nil {
				proxy.ServeHTTP(rw, r)
				return
			}
			log.Info("L2 API request", "method", req.Method)
			if strings.HasPrefix(req.Method, "engine_") {
				log.Info("Engine API request", "method", req.Method, "params", string(req.Params))
				res := util.RPCRes{
					ID:      req.ID,
					JSONRPC: req.JSONRPC,
				}
				switch req.Method {
				case "engine_forkchoiceUpdatedV1":
					var heads engine.ForkchoiceStateV1
					var payloadAttributes engine.PayloadAttributes
					if err = json.Unmarshal(req.Params, &[]interface{}{&heads, &payloadAttributes}); err != nil {
						log.Error("Failed to unmarshal engine_forkchoiceUpdatedV1 params", "message", err)
						res.Error = &util.RPCErr{
							Code:          -32000,
							Message:       err.Error(),
							HTTPErrorCode: http.StatusBadRequest,
						}
					} else {
						payloadAttributesPtr := &payloadAttributes
						if payloadAttributes.Timestamp == 0 {
							payloadAttributesPtr = nil
						}
						fcr, err := eng.ForkchoiceUpdatedV1(heads, payloadAttributesPtr)
						if err != nil {
							log.Error("Failed to call ForkchoiceUpdatedV1", "message", err)
							res.Error = &util.RPCErr{
								Code:          -32000,
								Message:       err.Error(),
								HTTPErrorCode: http.StatusBadRequest,
							}
						} else {
							res.Result = fcr
						}
					}
				case "engine_getPayloadV1":
					var payloadID engine.PayloadID
					if err = json.Unmarshal(req.Params, &[]interface{}{&payloadID}); err != nil {
						log.Error("Failed to unmarshal engine_getPayloadV1 params", "message", err)
						res.Error = &util.RPCErr{
							Code:          -32000,
							Message:       err.Error(),
							HTTPErrorCode: http.StatusBadRequest,
						}
					} else {
						payload, err := eng.GetPayloadV1(payloadID)
						if err != nil {
							log.Error("Failed to call GetPayloadV1", "message", err)
							res.Error = &util.RPCErr{
								Code:          -32000,
								Message:       err.Error(),
								HTTPErrorCode: http.StatusBadRequest,
							}
						} else {
							res.Result = payload
						}
					}
				case "engine_newPayloadV1":
					var payload engine.ExecutableData
					if err = json.Unmarshal(req.Params, &[]interface{}{&payload}); err != nil {
						log.Error("Failed to unmarshal engine_newPayloadV1 params", "message", err)
						res.Error = &util.RPCErr{
							Code:          -32000,
							Message:       err.Error(),
							HTTPErrorCode: http.StatusBadRequest,
						}
					} else {
						status, err := eng.NewPayloadV1(payload)
						if err != nil {
							log.Error("Failed to call NewPayloadV1", "message", err)
							res.Error = &util.RPCErr{
								Code:          -32000,
								Message:       err.Error(),
								HTTPErrorCode: http.StatusBadRequest,
							}
						} else {
							res.Result = status
						}
					}
				}
				resBytes, err := json.Marshal(res)
				if err != nil {
					proxy.ServeHTTP(rw, r)
					return
				}
				rw.WriteHeader(http.StatusOK)
				_, _ = rw.Write(resBytes)
				return
			}
			// TODO: record the response from the following proxy call
			// and replace any deposit txs / hashes with the ones from the deposit txs in the payload
			proxy.ServeHTTP(rw, r)

		}))
		if err != nil {
			log.Crit("Failed to start Engine API", "message", err)
		}
	}()

	jwtFile, err := os.CreateTemp("", "jwt-*.json")
	defer func() {
		_ = os.Remove(jwtFile.Name())
	}()
	if err != nil {
		return err
	}
	var secret [32]byte
	if _, err := io.ReadFull(rand.Reader, secret[:]); err != nil {
		return err
	}
	_, _ = jwtFile.Write([]byte(hexutil.Encode(secret[:])))
	_ = jwtFile.Close()

	nodeArgs := []string{
		"op-node",
		"--l1",
		fmt.Sprintf("http://localhost:%d", l1Port),
		"--l2",
		fmt.Sprintf("http://localhost:%d", l2Port),
		"--rollup.config",
		l2RollupFile.Name(),
		"--l2.jwt-secret",
		jwtFile.Name(),
		"--l1.trustrpc",
		"--p2p.disable",
		"--sequencer.enabled",
		"--log.level",
		"info",
	}
	log.Info("Running op-node", "args", nodeArgs)
	app := cli.NewApp()
	app.Flags = opnodeflags.Flags
	app.Action = node.RollupNodeMain(version)
	return app.Run(nodeArgs)
}

func anvil(ctx context.Context, port int, genesis, linePrefix string, blockTime int) (*exec.Cmd, *ethclient.Client, error) {
	args := []string{"--port", strconv.Itoa(port), "--init", genesis}
	if blockTime > 0 {
		args = append(args, "--block-time", strconv.Itoa(blockTime))
	} else {
		args = append(args, "--no-mining")
	}
	log.Info("Running anvil", "args", args)
	cmd := exec.Command("anvil", args...)
	cmd.Stdout = util.NewLinePrefixWriter([]byte(linePrefix), os.Stdout)
	cmd.Stderr = util.NewLinePrefixWriter([]byte(linePrefix), os.Stderr)
	err := cmd.Start()
	if err != nil {
		return nil, nil, err
	}
	waitCtx, waitCancel := context.WithCancel(ctx)
	go func() {
		_ = cmd.Wait()
		waitCancel()
	}()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		select {
		case <-waitCtx.Done():
			return nil, nil, fmt.Errorf("anvil exited unexpectedly")
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("timed out waiting for anvil to start")
		default:
		}
		time.Sleep(100 * time.Millisecond)
		c, err := ethclient.DialContext(ctx, fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			continue
		}
		_, err = c.ChainID(ctx)
		if err != nil {
			continue
		}
		return cmd, c, nil
	}
}

func freePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = l.Close()
	}()
	return l.Addr().(*net.TCPAddr).Port, nil
}

type anvilEngine struct {
	client   *ethclient.Client
	signer   types.Signer
	payloads map[engine.PayloadID]engine.ExecutableData
	txs      map[common.Hash]types.Transaction
	deposits map[common.Hash]common.Hash
}

func NewAnvilEngine(client *ethclient.Client, signer types.Signer) *anvilEngine {
	return &anvilEngine{
		client:   client,
		signer:   signer,
		payloads: make(map[engine.PayloadID]engine.ExecutableData),
		txs:      make(map[common.Hash]types.Transaction),
		deposits: make(map[common.Hash]common.Hash),
	}
}

func (e *anvilEngine) ForkchoiceUpdatedV1(update engine.ForkchoiceStateV1, payloadAttributes *engine.PayloadAttributes) (engine.ForkChoiceResponse, error) {
	ctx := context.Background()

	result := engine.ForkChoiceResponse{
		PayloadStatus: engine.PayloadStatusV1{Status: engine.VALID, LatestValidHash: &update.HeadBlockHash},
	}
	if payloadAttributes == nil {
		return result, nil
	}

	var payloadID engine.PayloadID
	_, _ = io.ReadFull(rand.Reader, payloadID[:])
	result.PayloadID = &payloadID

	transactions := make(types.Transactions, 0, len(payloadAttributes.Transactions))
	for i, otx := range payloadAttributes.Transactions {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(otx); err != nil {
			log.Error("Failed to unmarshal transaction", "message", err, "index", i)
			return result, err
		}
		transactions = append(transactions, &tx)
	}

	var r interface{}
	err := e.client.Client().CallContext(ctx, &r, "anvil_setNextBlockBaseFeePerGas", "0x0")
	if err != nil {
		return result, err
	}

	for _, tx := range transactions {
		if tx.IsDepositTx() {
			sender, err := e.signer.Sender(tx)
			if err != nil {
				return result, err
			}
			if tx.Mint() != nil && tx.Mint().Cmp(big.NewInt(0)) != 0 {
				balance, err := e.client.PendingBalanceAt(ctx, sender)
				if err != nil {
					return result, err
				}
				newBalance := hexutil.EncodeBig(balance.Add(balance, tx.Mint()))
				err = e.client.Client().CallContext(ctx, &r, "anvil_setBalance", sender.String(), newBalance)
				if err != nil {
					return result, err
				}
			}
			err = e.client.Client().CallContext(ctx, &r, "anvil_impersonateAccount", sender.String())
			if err != nil {
				return result, err
			}
			var hash common.Hash
			tx2 := make(map[string]string)
			tx2["from"] = sender.String()
			tx2["to"] = tx.To().String()
			tx2["gas"] = hexutil.EncodeUint64(tx.Gas())
			tx2["gasPrice"] = hexutil.EncodeBig(tx.GasPrice())
			tx2["value"] = hexutil.EncodeBig(tx.Value())
			tx2["data"] = hexutil.Encode(tx.Data())
			err = e.client.Client().CallContext(ctx, &hash, "eth_sendTransaction", tx2)
			if err != nil {
				return result, err
			}
			log.Info("Sent deposit transaction", "hash", hash)
			e.txs[hash] = *tx
			e.deposits[tx.Hash()] = hash
		}
	}

	// parameters: number of blocks, time between blocks
	err = e.client.Client().CallContext(ctx, &r, "anvil_mine", "0x1", "0x2")
	if err != nil {
		return result, err
	}

	block, err := e.client.BlockByNumber(ctx, nil)
	if err != nil {
		return result, err
	}

	//transactionsBinary := make([][]byte, block.Transactions().Len())
	//for i, tx := range block.Transactions() {
	//	transactionsBinary[i], err = tx.MarshalBinary()
	//	if err != nil {
	//		return result, err
	//	}
	//}

	data := engine.ExecutableData{
		ParentHash:    block.ParentHash(),
		FeeRecipient:  common.HexToAddress("0x4200000000000000000000000000000000000011"),
		StateRoot:     block.Root(),
		ReceiptsRoot:  block.ReceiptHash(),
		LogsBloom:     block.Bloom().Bytes(),
		Random:        common.Hash{},
		Number:        block.NumberU64(),
		GasLimit:      block.GasLimit(),
		GasUsed:       block.GasUsed(),
		Timestamp:     block.Time(),
		ExtraData:     block.Extra(),
		BaseFeePerGas: block.BaseFee(),
		BlockHash:     block.Hash(),
		Transactions:  payloadAttributes.Transactions, // TODO add any extra txs in block.Transactions
		Withdrawals:   block.Withdrawals(),
	}
	e.payloads[payloadID] = data

	return result, nil
}

func (e *anvilEngine) GetPayloadV1(payloadID engine.PayloadID) (*engine.ExecutableData, error) {
	if data, ok := e.payloads[payloadID]; ok {
		return &data, nil
	}
	return nil, errors.New("payload not found")
}

func (e *anvilEngine) NewPayloadV1(params engine.ExecutableData) (engine.PayloadStatusV1, error) {
	return engine.PayloadStatusV1{
		Status:          engine.VALID,
		LatestValidHash: &params.BlockHash,
	}, nil
}

func (e *anvilEngine) ModifyRequest(r []byte) []byte {
	fmt.Printf("Request: %s\n", string(r))
	return r
}

func (e *anvilEngine) ModifyResponse(r []byte) []byte {
	fmt.Printf("Response before: %s\n", string(r))
	var res interface{}
	_ = json.Unmarshal(r, &res)
	res = e.replaceTxs(res)
	r, _ = json.Marshal(res)
	fmt.Printf("Response after: %s\n", string(r))
	return r
}

func (e *anvilEngine) replaceTxs(j interface{}) interface{} {
	switch j.(type) {
	case []interface{}:
		a := j.([]interface{})
		for i, v := range a {
			a[i] = e.replaceTxs(v)
		}
	case map[string]interface{}:
		m := j.(map[string]interface{})
		if m["hash"] != nil {
			if hash, ok := m["hash"].(string); ok {
				h := common.HexToHash(hash)
				if deposit, ok := e.txs[h]; ok {
					js, _ := deposit.MarshalJSON()
					var n interface{}
					_ = json.Unmarshal(js, &n)
					return n
				}
			}
		}
		for k, v := range m {
			m[k] = e.replaceTxs(v)
		}
	}
	return j
}

// steps:
// 1. insert transactions into L2 anvil (must support deposit tx type)
// 2. create a engine.ExecutableData associated with the payloadID
// 3. return it from engine_getPayloadV1
// 4. accept it from engine_newPayloadV1 and return the new block hash

// if payloadAttributes is not null, a payload (engine.ExecutableData)
// should be created and associated with a payloadID
// otherwise if payloadAttributes is null, payloadID should be null

// proxy the L2 anvil, returning a deposit tx with correct mint value
// for any L2 deposit tx hashes
// - for any requests: replace the deposit tx hash with the actual L2 tx hash
// - for any responses, replace the actual L2 tx hash with the deposit tx hash

//req:
/*
	[{
		"headBlockHash":"0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f",
		"safeBlockHash":"0x850ad1947be0cdcd885b90788d0d1578d1dc915e097c69cc42a7d1213a4a50f7",
		"finalizedBlockHash":"0x2c7c5d40c938a984666b0fed9ab24c46118a2dabde3b8330a91d877e3cdbaa90"
	},
	{
		"timestamp":"0x64eea0f3",
		"prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000",
		"suggestedFeeRecipient":"0x4200000000000000000000000000000000000011",
		"transactions":[
			"0x7ef90159a0cd3f7984cf5065672e8fb22fa9907e7b33763bcf9f32c3ea77b557f8e8cf7cf194deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b90104015d8eb9000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000064eea0ef0000000000000000000000000000000000000000000000000000000000009b17a56027408b7b4d474f39475b337aa2a982b5c4a9b2c0842341fbe32857db304900000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240"
		],
		"gasLimit":"0x1c9c380"
	}]
*/
//res:
/*
	{
		"payloadStatus":{
			"status":"VALID",
			"latestValidHash":"0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f"
		},
		"payloadId":"0xa5e118b4ac83af38"
	}
*/
//payload:
/*
	{
		"parentHash":"0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f",
		"feeRecipient":"0x4200000000000000000000000000000000000011",
		"stateRoot":"0x28bb0f5807d3ef4dcb30c5290b8acd822733e42c561d6dfd629cff742bd30327",
		"receiptsRoot":"0xa6fc4e1426e904b9509352f12c54f69a9feec3bdeb26c797fca33a61cd582bb9",
		"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000",
		"blockNumber":"0x76",
		"gasLimit":"0x1c9c380",
		"gasUsed":"0xc4fd",
		"timestamp":"0x64eea0f3",
		"extraData":"0x",
		"baseFeePerGas":"0x1",
		"blockHash":"0x0547f7c092e3db0dbf1e9bf55667871064b80d53a446f3d7d7643df2cd898b70",
		"transactions":[
			"0x7ef90159a0cd3f7984cf5065672e8fb22fa9907e7b33763bcf9f32c3ea77b557f8e8cf7cf194deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b90104015d8eb9000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000064eea0ef0000000000000000000000000000000000000000000000000000000000009b17a56027408b7b4d474f39475b337aa2a982b5c4a9b2c0842341fbe32857db304900000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240"
		]
	}
*/

/*
	Method:
	eth_getBlockByNumber

	Request:
	["0x4c",false]

	Response:
	{"parentHash":"0x9cf79cb869fa629012e681765af08c4d02821dd508e04c18955f97f375608f98","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x29f85f90b137ea2e9c9aa3930c49ddbcf2bb395e8de485073e2304ee40167144","transactionsRoot":"0xab5c0f0e738292b5e486f0bb5d9c01d0f3067a5aa8327cdc11f4892995be0e89","receiptsRoot":"0xbcbc7177fdd5ea3c6dab1bbf7683a21b2907584cbf03414b674366425db05485","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x2","number":"0x4c","gasLimit":"0x1c9c380","gasUsed":"0x6e68","timestamp":"0x64eea0ef","extraData":"0xd883010c02846765746888676f312e32302e37856c696e757800000000000000503b8e9b188ae7568eb884ed9abf827d43ffdee80fa69d67993327e0290d821654729134e88124917269a79dbfcd8e10e703a61a81921507396a9b2ecb71c2a901","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x9b17","withdrawalsRoot":null,"hash":"0xa56027408b7b4d474f39475b337aa2a982b5c4a9b2c0842341fbe32857db3049"}

	t=2023-09-01T06:08:21+0000 lvl=info msg="creating new block"                     parent=0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f:117 l1Origin=0xa56027408b7b4d474f39475b337aa2a982b5c4a9b2c0842341fbe32857db3049:76
	Method:
	engine_forkchoiceUpdatedV1

	Request:
	[{"headBlockHash":"0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f","safeBlockHash":"0x850ad1947be0cdcd885b90788d0d1578d1dc915e097c69cc42a7d1213a4a50f7","finalizedBlockHash":"0x2c7c5d40c938a984666b0fed9ab24c46118a2dabde3b8330a91d877e3cdbaa90"},{"timestamp":"0x64eea0f3","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","suggestedFeeRecipient":"0x4200000000000000000000000000000000000011","transactions":["0x7ef90159a0cd3f7984cf5065672e8fb22fa9907e7b33763bcf9f32c3ea77b557f8e8cf7cf194deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b90104015d8eb9000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000064eea0ef0000000000000000000000000000000000000000000000000000000000009b17a56027408b7b4d474f39475b337aa2a982b5c4a9b2c0842341fbe32857db304900000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240"],"gasLimit":"0x1c9c380"}]

	Response:
	{"payloadStatus":{"status":"VALID","latestValidHash":"0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f"},"payloadId":"0xa5e118b4ac83af38"}

	t=2023-09-01T06:08:21+0000 lvl=info msg="sequencer started building new block"   payload_id=0xa5e118b4ac83af38 l2_parent_block=0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f:117 l2_parent_block_time=1,693,360,369
	Method:
	engine_getPayloadV1

	Request:
	["0xa5e118b4ac83af38"]

	Response:
	{"parentHash":"0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f","feeRecipient":"0x4200000000000000000000000000000000000011","stateRoot":"0x28bb0f5807d3ef4dcb30c5290b8acd822733e42c561d6dfd629cff742bd30327","receiptsRoot":"0xa6fc4e1426e904b9509352f12c54f69a9feec3bdeb26c797fca33a61cd582bb9","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x76","gasLimit":"0x1c9c380","gasUsed":"0xc4fd","timestamp":"0x64eea0f3","extraData":"0x","baseFeePerGas":"0x1","blockHash":"0x0547f7c092e3db0dbf1e9bf55667871064b80d53a446f3d7d7643df2cd898b70","transactions":["0x7ef90159a0cd3f7984cf5065672e8fb22fa9907e7b33763bcf9f32c3ea77b557f8e8cf7cf194deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b90104015d8eb9000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000064eea0ef0000000000000000000000000000000000000000000000000000000000009b17a56027408b7b4d474f39475b337aa2a982b5c4a9b2c0842341fbe32857db304900000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240"]}

	Method:
	engine_newPayloadV1

	Request:
	[{"parentHash":"0xbf2a6c03e0d04e8437c4f81bf90d96dd0b0ea61c70a9bf9547da7574be9ace4f","feeRecipient":"0x4200000000000000000000000000000000000011","stateRoot":"0x28bb0f5807d3ef4dcb30c5290b8acd822733e42c561d6dfd629cff742bd30327","receiptsRoot":"0xa6fc4e1426e904b9509352f12c54f69a9feec3bdeb26c797fca33a61cd582bb9","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","prevRandao":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x76","gasLimit":"0x1c9c380","gasUsed":"0xc4fd","timestamp":"0x64eea0f3","extraData":"0x","baseFeePerGas":"0x1","blockHash":"0x0547f7c092e3db0dbf1e9bf55667871064b80d53a446f3d7d7643df2cd898b70","transactions":["0x7ef90159a0cd3f7984cf5065672e8fb22fa9907e7b33763bcf9f32c3ea77b557f8e8cf7cf194deaddeaddeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b90104015d8eb9000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000064eea0ef0000000000000000000000000000000000000000000000000000000000009b17a56027408b7b4d474f39475b337aa2a982b5c4a9b2c0842341fbe32857db304900000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240"]}]

	Response:
	{"status":"VALID","latestValidHash":"0x0547f7c092e3db0dbf1e9bf55667871064b80d53a446f3d7d7643df2cd898b70"}

	Method:
	engine_forkchoiceUpdatedV1

	Request:
	[{"headBlockHash":"0x0547f7c092e3db0dbf1e9bf55667871064b80d53a446f3d7d7643df2cd898b70","safeBlockHash":"0x850ad1947be0cdcd885b90788d0d1578d1dc915e097c69cc42a7d1213a4a50f7","finalizedBlockHash":"0x2c7c5d40c938a984666b0fed9ab24c46118a2dabde3b8330a91d877e3cdbaa90"},null]

	Response:
	{"payloadStatus":{"status":"VALID","latestValidHash":"0x0547f7c092e3db0dbf1e9bf55667871064b80d53a446f3d7d7643df2cd898b70"},"payloadId":null}
*/
