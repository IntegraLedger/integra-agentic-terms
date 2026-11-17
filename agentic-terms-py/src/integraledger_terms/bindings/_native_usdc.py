"""The native USDC token contract Circle publishes for each EVM chain, by chain id: the token a usdc EVM challenge's
request.currency must be for its methodDetails.evm.chainId. "Servers MUST verify that request.currency is the native
USDC token contract published by Circle for methodDetails.evm.chainId" (draft-usdc-charge-00 at tempoxyz/mpp-specs
1f0574a, lines 300-301), the publication being Circle's page USDC Contract Addresses,
https://developers.circle.com/stablecoins/usdc-contract-addresses (the draft's CIRCLE-USDC-ADDRESSES, lines 81-83), read
on 2026-11-17, every EVM row of its mainnet and testnet tables, the address lower-case, as @integraledger/lcp holds it.
The page names each chain; the chain id is the one viem 2.57.4's chain of that name defines (viem/chains, the export
named beside each row). Five rows of the page name a chain viem 2.57.4 defines no id for, and are not here: EDGE, EDGE
Testnet, Pharos, Pharos Testnet and Morph Hoodi Testnet; a challenge on such a chain is refused as one on a chain
Circle publishes no native USDC for, since its currency cannot be verified."""

from collections.abc import Mapping

NATIVE_USDC: Mapping[int, str] = {
    42161: "0xaf88d065e77c8cc2239327c5edb3a432268e5831",  # Arbitrum (viem `arbitrum`)
    5042: "0x3600000000000000000000000000000000000000",  # Arc (viem `arc`)
    43114: "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",  # Avalanche C-Chain (viem `avalanche`)
    8453: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # Base (viem `base`)
    81224: "0xd996633a415985dbd7d6d12f4a4343e31f5037cf",  # Codex (viem `codex`)
    42220: "0xceba9300f2b948710d2653dd7b07f33a8b32118c",  # Celo (viem `celo`)
    25: "0x3d7f2c478aafdb65542bcb44bceec05849999d2d",  # Cronos (viem `cronos`)
    1: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # Ethereum (viem `mainnet`)
    999: "0xb88339cb7199b77e23db6e890353e22632ba630f",  # HyperEVM (viem `hyperEvm`)
    1776: "0xa00c59ff5a080d2b954d0c75e46e22a0c371235a",  # Injective (viem `injective`)
    57073: "0x2d270e6886d130d724215a266106e6832161eaed",  # Ink (viem `ink`)
    59144: "0x176211869ca2b568f2a7d4ee941e073a821ee1ff",  # Linea (viem `linea`)
    143: "0x754704bc059f8c67012fed69bc8a327a5aafb603",  # Monad (viem `monad`)
    2818: "0xcfb1186f4e93d60e60a8bdd997427d1f33bc372b",  # Morph (viem `morph`)
    10: "0x0b2c639c533813f4aa9d7837caf62653d097ff85",  # OP Mainnet (viem `optimism`)
    9745: "0x2d661c89d812261039af9764eceaaee884f5f67f",  # Plasma (viem `plasma`)
    98866: "0x222365ef19f7947e5484218551b56bb3965aa7af",  # Plume (viem `plumeMainnet`)
    137: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",  # Polygon PoS (viem `polygon`)
    1329: "0xe15fc38f6d8c56af07bbcbe3baf5708a2bf42392",  # Sei (viem `sei`)
    146: "0x29219dd400f2bf60e5a23d13be72b486d4038894",  # Sonic (viem `sonic`)
    130: "0x078d782b760474a361dda0af3839290b0ef57ad6",  # Unichain (viem `unichain`)
    480: "0x79a02482a880bce3f13e09da970dc34db4cd24d1",  # World Chain (viem `worldchain`)
    196: "0xb6ceceab302e2e4948951ee7843fc24e92933061",  # X Layer (viem `xLayer`)
    50: "0xfa2958cb79b0491cc627c1557f441ef849ca8eb1",  # XDC (viem `xdc`)
    324: "0x1d17cbcf0d6d143135ae902365d2e5e2a16538d4",  # ZKsync Era (viem `zksync`)
    421614: "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d",  # Arbitrum Sepolia (viem `arbitrumSepolia`)
    5042002: "0x3600000000000000000000000000000000000000",  # Arc Testnet (viem `arcTestnet`)
    43113: "0x5425890298aed601595a70ab815c96711a31bc65",  # Avalanche Fuji (viem `avalancheFuji`)
    84532: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",  # Base Sepolia (viem `baseSepolia`)
    11142220: "0x01c5c0122039549ad1493b8220cabedd739bc44e",  # Celo Sepolia (viem `celoSepolia`)
    812242: "0x6d7f141b6819c2c9cc2f818e6ad549e7ca090f8f",  # Codex Testnet (viem `codexTestnet`)
    338: "0xeb33dc5fac03833e132593659e1de7256ab59794",  # Cronos Testnet (viem `cronosTestnet`)
    11155111: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",  # Ethereum Sepolia (viem `sepolia`)
    998: "0x2b3370ee501b4a559b57d449569354196457d8ab",  # HyperEVM Testnet (viem `hyperliquidEvmTestnet`)
    1439: "0x0c382e685bbeefe5d3d9c29e29e341fee8e84c5d",  # Injective Testnet (viem `injectiveTestnet`)
    763373: "0xfabab97dce620294d2b0b0e46c68964e326300ac",  # Ink Testnet (viem `inkSepolia`)
    59141: "0xfece4462d57bd51a6a552365a011b95f0e16d9b7",  # Linea Sepolia (viem `lineaSepolia`)
    10143: "0x534b2f3a21130d7a60830c2df862319e593943a3",  # Monad Testnet (viem `monadTestnet`)
    11155420: "0x5fd84259d66cd46123540766be93dfe6d43130d7",  # OP Sepolia (viem `optimismSepolia`)
    9746: "0xe67fb267022cba8064dd388cc2fed724f3120d9d",  # Plasma Testnet (viem `plasmaTestnet`)
    98867: "0xcb5f30e335672893c7eb944b374c196392c19d18",  # Plume Testnet (viem `plumeSepolia`)
    80002: "0x41e94eb019c0762f9bfcf9fb1e58725bfb0e7582",  # Polygon PoS Amoy (viem `polygonAmoy`)
    1328: "0x4fcf1784b31630811181f670aea7a7bef803eaed",  # Sei Testnet (viem `seiTestnet`)
    64165: "0x0ba304580ee7c9a980cf72e55f5ed2e9fd30bc51",  # Sonic Testnet (viem `sonicTestnet`)
    57054: "0xa4879fed32ecbef99399e5cbc247e533421c4ec6",  # Sonic Blaze Testnet (viem `sonicBlazeTestnet`)
    1301: "0x31d0220469e10c4e71834a79b1f276d740d3768f",  # Unichain Sepolia (viem `unichainSepolia`)
    4801: "0x66145f38cbac35ca6f1dfb4914df98f1614aea88",  # World Chain Sepolia (viem `worldchainSepolia`)
    1952: "0xdec90b78111ba2fc6fc6d84d8b9ec159a2d4b9b3",  # X Layer Testnet (viem `xLayerTestnet`)
    51: "0xb5ab69f7bbada22b28e79c8ffaece55ef1c771d4",  # XDC Apothem (viem `xdcTestnet`)
    300: "0xae045de5638162fa134807cb558e15a3f5a7f853",  # ZKsync Era Testnet (viem `zksyncSepoliaTestnet`)
}
