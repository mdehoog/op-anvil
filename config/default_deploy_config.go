package config

import (
	"bytes"
	"encoding/json"

	"github.com/ethereum-optimism/optimism/op-chain-ops/genesis"
)

const defaultDeployConfig = `
{
  "l1ChainID": 900,
  "l2ChainID": 901,
  "l2BlockTime": 2,
  "maxSequencerDrift": 300,
  "sequencerWindowSize": 200,
  "channelTimeout": 120,
  "p2pSequencerAddress": "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
  "batchInboxAddress": "0xff00000000000000000000000000000000000901",
  "batchSenderAddress": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  "cliqueSignerAddress": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "l1UseClique": false,
  "l1StartingBlockTag": "earliest",
  "l2OutputOracleSubmissionInterval": 6,
  "l2OutputOracleStartingTimestamp": 0,
  "l2OutputOracleStartingBlockNumber": 0,
  "l2OutputOracleProposer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "l2OutputOracleChallenger": "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
  "l2GenesisBlockGasLimit": "0x1c9c380",
  "l1BlockTime": 12,
  "baseFeeVaultRecipient": "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
  "l1FeeVaultRecipient": "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
  "sequencerFeeVaultRecipient": "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
  "baseFeeVaultMinimumWithdrawalAmount": "0x8ac7230489e80000",
  "l1FeeVaultMinimumWithdrawalAmount": "0x8ac7230489e80000",
  "sequencerFeeVaultMinimumWithdrawalAmount": "0x8ac7230489e80000",
  "baseFeeVaultWithdrawalNetwork": "remote",
  "l1FeeVaultWithdrawalNetwork": "remote",
  "sequencerFeeVaultWithdrawalNetwork": "remote",
  "proxyAdminOwner": "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
  "finalSystemOwner": "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
  "portalGuardian": "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
  "finalizationPeriodSeconds": 2,
  "fundDevAccounts": true,
  "l2GenesisBlockBaseFeePerGas": "0x1",
  "gasPriceOracleOverhead": 2100,
  "gasPriceOracleScalar": 1000000,
  "enableGovernance": true,
  "governanceTokenSymbol": "OP",
  "governanceTokenName": "Optimism",
  "governanceTokenOwner": "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
  "eip1559Denominator": 50,
  "eip1559Elasticity": 6,
  "l1GenesisBlockTimestamp": "0x0",
  "l2GenesisRegolithTimeOffset": "0x0",
  "faultGameAbsolutePrestate": "0x41c7ae758795765c6664a5d39bf63841c71ff191e9189522bad8ebff5d4eca98",
  "faultGameMaxDepth": 30,
  "faultGameMaxDuration": 300,
  "systemConfigStartBlock": 0
}
`

func DefaultDeployConfig() (*genesis.DeployConfig, error) {
	dec := json.NewDecoder(bytes.NewBufferString(defaultDeployConfig))
	dec.DisallowUnknownFields()
	var config genesis.DeployConfig
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}