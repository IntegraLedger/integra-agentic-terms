/**
 * `eip712` requests signing Circle Gateway's batched payment: an EIP-3009 `TransferWithAuthorization` in the Gateway
 * Wallet's `GatewayWalletBatched` domain (profile `buyer-gate.md`, rule 13; lcp profile
 * `x402-exact-eip155-gateway-batched.md`, rules 4, 5 and 7). The verifying contract is the Gateway Wallet, not the
 * token: at version `"2"` the domain's `salt` names the token, its address left-padded to 32 bytes; at version `"1"`
 * the domain names none, and Circle's client signs it only for the network's USDC. The summary reads only what the
 * typed data signs, under the types the request names.
 */
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { address, decimal, isObject, sameAddress, typeIs } from "./evm-fields.js";

const MAINNET_WALLET = "0x77777777dcc4d5a8b6e418fd04d8997ef11000ee";
const TESTNET_WALLET = "0x0077777d7eba4688bdef3e311b846f25870a19b9";

/**
 * The Gateway Wallet and USDC on each network, by chain id, as `@circle-fin/x402-batching` 4.0.0 configures them
 * (`src/config.ts:110-116`, `:121-360`), lowercase.
 */
const NETWORKS: ReadonlyMap<string, { readonly wallet: string; readonly usdc: string }> = new Map(
  (
    [
      ["1", MAINNET_WALLET, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"],
      ["10", MAINNET_WALLET, "0x0b2c639c533813f4aa9d7837caf62653d097ff85"],
      ["130", MAINNET_WALLET, "0x078d782b760474a361dda0af3839290b0ef57ad6"],
      ["137", MAINNET_WALLET, "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"],
      ["146", MAINNET_WALLET, "0x29219dd400f2bf60e5a23d13be72b486d4038894"],
      ["480", MAINNET_WALLET, "0x79a02482a880bce3f13e09da970dc34db4cd24d1"],
      ["999", MAINNET_WALLET, "0xb88339cb7199b77e23db6e890353e22632ba630f"],
      ["1329", MAINNET_WALLET, "0xe15fc38f6d8c56af07bbcbe3baf5708a2bf42392"],
      ["5042", MAINNET_WALLET, "0x3600000000000000000000000000000000000000"],
      ["8453", MAINNET_WALLET, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"],
      ["42161", MAINNET_WALLET, "0xaf88d065e77c8cc2239327c5edb3a432268e5831"],
      ["43114", MAINNET_WALLET, "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"],
      ["998", TESTNET_WALLET, "0x2b3370ee501b4a559b57d449569354196457d8ab"],
      ["1301", TESTNET_WALLET, "0x31d0220469e10c4e71834a79b1f276d740d3768f"],
      ["1328", TESTNET_WALLET, "0x4fcf1784b31630811181f670aea7a7bef803eaed"],
      ["4801", TESTNET_WALLET, "0x66145f38cbac35ca6f1dfb4914df98f1614aea88"],
      ["14601", TESTNET_WALLET, "0x0ba304580ee7c9a980cf72e55f5ed2e9fd30bc51"],
      ["43113", TESTNET_WALLET, "0x5425890298aed601595a70ab815c96711a31bc65"],
      ["80002", TESTNET_WALLET, "0x41e94eb019c0762f9bfcf9fb1e58725bfb0e7582"],
      ["84532", TESTNET_WALLET, "0x036cbd53842c5426634e7929541ec2318f3dcf7e"],
      ["421614", TESTNET_WALLET, "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d"],
      ["5042002", TESTNET_WALLET, "0x3600000000000000000000000000000000000000"],
      ["11155111", TESTNET_WALLET, "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"],
      ["11155420", TESTNET_WALLET, "0x5fd84259d66cd46123540766be93dfe6d43130d7"],
    ] as const
  ).map(([id, wallet, usdc]) => [id, { wallet, usdc }] as const),
);

const DOMAIN = [
  ["name", "string"],
  ["version", "string"],
  ["chainId", "uint256"],
  ["verifyingContract", "address"],
] as const;
const DOMAIN_WITH_SALT = [...DOMAIN, ["salt", "bytes32"]] as const;
const TRANSFER_WITH_AUTHORIZATION = [
  ["from", "address"],
  ["to", "address"],
  ["value", "uint256"],
  ["validAfter", "uint256"],
  ["validBefore", "uint256"],
  ["nonce", "bytes32"],
] as const;

/** A version `"2"` domain's salt, an address left-padded to 32 bytes: that address; else undefined. */
const SALTED = /^0x0{24}([0-9a-fA-F]{40})$/;

/**
 * `TransferWithAuthorization` in the `GatewayWalletBatched` domain whose `verifyingContract` is the Gateway Wallet on
 * `d.chainId`'s network: the amount and the one payee's part are `m.value`, the payee `m.to`, the asset the token
 * `d.salt` names at version `"2"` or the network's USDC at version `"1"`, the network `eip155:` and `d.chainId`, and
 * the validity `m.validAfter` to `m.validBefore`, in seconds. Another domain, version or verifying contract, a salt that
 * is not a padded address, or types other than these gives no summary.
 */
export function gatewayBatched(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData)) return undefined;
  const { primaryType, types, domain: d, message: m } = r.typedData;
  if (primaryType !== "TransferWithAuthorization" || !isObject(types) || !isObject(d) || !isObject(m)) return undefined;
  if (d["name"] !== "GatewayWalletBatched" || !typeIs(types["TransferWithAuthorization"], TRANSFER_WITH_AUTHORIZATION)) return undefined;
  const chain = decimal(d["chainId"]);
  const network = chain === undefined ? undefined : NETWORKS.get(chain);
  const wallet = address(d["verifyingContract"]);
  if (network === undefined || wallet === undefined || !sameAddress(wallet, network.wallet)) return undefined;
  let asset: string | undefined;
  if (d["version"] === "1" && typeIs(types["EIP712Domain"], DOMAIN) && d["salt"] === undefined) asset = network.usdc;
  else if (d["version"] === "2" && typeIs(types["EIP712Domain"], DOMAIN_WITH_SALT) && typeof d["salt"] === "string") {
    const salted = SALTED.exec(d["salt"]);
    asset = salted === null ? undefined : `0x${salted[1]!}`;
  }
  const value = decimal(m["value"]);
  const after = decimal(m["validAfter"]);
  const before = decimal(m["validBefore"]);
  const to = address(m["to"]);
  if (asset === undefined || value === undefined || after === undefined || before === undefined || to === undefined) return undefined;
  return {
    amount: value,
    payees: [{ account: to, amount: value }],
    asset,
    network: `eip155:${chain!}`,
    validity: { notBefore: after, notAfter: before, unit: "seconds" },
  };
}
