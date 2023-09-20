package util

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

type EthClient struct {
	Client *rpc.Client
}

func (s *EthClient) GetStorageAt(ctx context.Context, address common.Address, storageSlot common.Hash, blockTag string) (common.Hash, error) {
	var out common.Hash
	err := s.Client.CallContext(ctx, &out, "eth_getStorageAt", address, storageSlot, blockTag)
	return out, err
}

func (s *EthClient) ReadStorageAt(ctx context.Context, address common.Address, storageSlot common.Hash, blockHash common.Hash) (common.Hash, error) {
	return s.GetStorageAt(ctx, address, storageSlot, blockHash.String())
}
