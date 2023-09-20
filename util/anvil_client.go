package util

import (
	"context"
	"math/big"

	"github.com/ethereum-optimism/optimism/op-node/client"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

type anvilClient struct {
	client     client.RPC
	blockCache map[common.Hash]*big.Int
}

func NewAnvilClient(rpcClient client.RPC) client.RPC {
	return &anvilClient{
		client:     rpcClient,
		blockCache: make(map[common.Hash]*big.Int),
	}
}

func (c *anvilClient) Close() {
	c.client.Close()
}

func (c *anvilClient) CallContext(ctx context.Context, result any, method string, args ...any) error {
	// Anvil's eth_getStorageAt doesn't support block hashes, so retrieve block number
	if method == "eth_getStorageAt" && len(args) == 3 {
		if hashStr, ok := args[2].(string); ok && len(hashStr) == 66 {
			hash := common.HexToHash(hashStr)
			cached, ok := c.blockCache[hash]
			if !ok {
				var header types.Header
				err := c.CallContext(ctx, &header, "eth_getBlockByHash", hash, false)
				if err != nil {
					return err
				}
				c.blockCache[hash] = header.Number
				cached = header.Number
			}
			args[2] = hexutil.EncodeBig(cached)
		}
	}
	return c.client.CallContext(ctx, result, method, args...)
}

func (c *anvilClient) BatchCallContext(ctx context.Context, b []rpc.BatchElem) error {
	return c.client.BatchCallContext(ctx, b)
}

func (c *anvilClient) EthSubscribe(ctx context.Context, channel any, args ...any) (ethereum.Subscription, error) {
	return c.client.EthSubscribe(ctx, channel, args...)
}
