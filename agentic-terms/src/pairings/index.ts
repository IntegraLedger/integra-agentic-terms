import type { BuyerPiece } from "../types.js";
import { mppChargeLightning, mppSessionLightning } from "./lightning.js";
import { x402ExactCasper } from "./x402-exact-casper.js";
import { x402ExactCcd } from "./x402-exact-ccd.js";
import { ackPaymentRequest } from "./ack-payment-request.js";
import { acpCheckoutDelegated } from "./acp-checkout-delegated.js";
import { acpCheckoutUndelegated } from "./acp-checkout-undelegated.js";
import { ap2CheckoutMandate } from "./ap2-checkout-mandate.js";
import { ap2CheckoutMandateX402 } from "./ap2-checkout-mandate-x402.js";
import { cardMastercardViAutonomous } from "./card-mastercard-vi-autonomous.js";
import { cardMastercardViImmediate } from "./card-mastercard-vi-immediate.js";
import { cardSellerReference } from "./card-seller-reference.js";
import { cardVisaTap } from "./card-visa-tap.js";
import { cardVisaVic } from "./card-visa-vic.js";
import { cardMastercardAgentPay } from "./card-mastercard-agent-pay.js";
import { mppChargeEvmAuthorization } from "./mpp-charge-evm-authorization.js";
import { mppChargeEvmHash } from "./mpp-charge-evm-hash.js";
import { mppChargeEvmPermit2 } from "./mpp-charge-evm-permit2.js";
import { mppChargeEvmTransaction } from "./mpp-charge-evm-transaction.js";
import { mppChargeLcpHedera } from "./mpp-charge-lcp.js";
import { mppChargeCard } from "./mpp-charge-card.js";
import { mppChargeNearIntents } from "./mpp-charge-nearintents.js";
import { mppChargeStripe } from "./mpp-charge-stripe.js";
import { mppChargeUsdcEvm } from "./mpp-charge-usdc-evm.js";
import { mppChargeUsdcGateway } from "./mpp-charge-usdc-gateway.js";
import { mppChargeUsdcSolana } from "./mpp-charge-usdc-solana.js";
import { mppChargeUsdcStacks } from "./mpp-charge-usdc-stacks.js";
import { mppSubscriptionStripe } from "./mpp-subscription-stripe.js";
import { mppChargeSolana } from "./mpp-charge-solana.js";
import { mppChargeSolanaUnsponsored } from "./mpp-charge-solana-unsponsored.js";
import { mppSubscriptionSolana } from "./mpp-subscription-solana.js";
import { mppChargeXrpl } from "./mpp-charge-xrpl.js";
import { mppSessionXrpl } from "./mpp-session-xrpl.js";
import { mppSessionXrplStock } from "./mpp-session-xrpl-stock.js";
import { mppSessionHederaStock } from "./mpp-session-hedera-stock.js";
import { ucpBookingAp2Mandate } from "./ucp-booking-ap2-mandate.js";
import { ucpBookingUnsigned } from "./ucp-booking-unsigned.js";
import { ucpCheckoutAp2Mandate } from "./ucp-checkout-ap2-mandate.js";
import { ucpCheckoutAgentSigned } from "./ucp-checkout-agent-signed.js";
import { ucpCheckoutUnsigned } from "./ucp-checkout-unsigned.js";
import { x402AuthCaptureEip155Eip3009 } from "./x402-auth-capture-eip155-eip3009.js";
import { x402AuthCaptureEip155Permit2 } from "./x402-auth-capture-eip155-permit2.js";
import { x402ExactAlgorand } from "./x402-exact-algorand.js";
import { mppSessionEvm } from "./mpp-session-evm.js";
import { mppSessionTempo } from "./mpp-session-tempo.js";
import { mppSubscriptionTempo } from "./mpp-subscription-tempo.js";
import { x402BatchSettlementCloudflare } from "./x402-batch-settlement-cloudflare.js";
import { x402BatchSettlementEip155 } from "./x402-batch-settlement-eip155.js";
import { x402BatchSettlementSolana } from "./x402-batch-settlement-solana.js";
import { x402ExactEip155Eip3009 } from "./x402-exact-eip155-eip3009.js";
import { x402ExactEip155Erc7710 } from "./x402-exact-eip155-erc7710.js";
import { x402ExactEip155Erc7710Salt } from "./x402-exact-eip155-erc7710-salt.js";
import { x402ExactEip155Permit2 } from "./x402-exact-eip155-permit2.js";
import { x402ExactHedera } from "./x402-exact-hedera.js";
import { x402ExactHederaTransferExecutor } from "./x402-exact-hedera-transfer-executor.js";
import { x402ExactSolana } from "./x402-exact-solana.js";
import { x402ExactStellarPrecondition } from "./x402-exact-stellar-precondition.js";
import { x402ExactXrpl } from "./x402-exact-xrpl.js";
import { x402UptoEip155Permit2 } from "./x402-upto-eip155-permit2.js";
import { x402UptoSolana } from "./x402-upto-solana.js";
import { x402UptoXrpl } from "./x402-upto-xrpl.js";
import { x402ExactAptos } from "./x402-exact-aptos.js";
import { x402ExactCardano } from "./x402-exact-cardano.js";
import { x402ExactCardanoLock } from "./x402-exact-cardano-lock.js";
import { x402ExactNear } from "./x402-exact-near.js";
import { x402ExactPolkadotLcpAssetsRemark } from "./x402-exact-polkadot-lcp-assets-remark.js";
import { x402ExactStarknet } from "./x402-exact-starknet.js";
import { x402ExactSui } from "./x402-exact-sui.js";
import { x402ExactTronLcpTrc20Memo } from "./x402-exact-tron-lcp-trc20-memo.js";
import { x402ExactTvm } from "./x402-exact-tvm.js";
import { spendPermissionsEip155Piece } from "./spend-permissions-eip155.js";

/** The buyer piece for each pairing the gate pays, by pairing id. */
export const PIECES: ReadonlyMap<string, BuyerPiece> = new Map<string, BuyerPiece>([
  ["x402/exact/eip155/eip3009", x402ExactEip155Eip3009],
  ["x402/exact/eip155/permit2", x402ExactEip155Permit2],
  ["x402/exact/eip155/erc7710", x402ExactEip155Erc7710],
  ["x402/exact/eip155/erc7710-salt", x402ExactEip155Erc7710Salt],
  ["x402/upto/eip155/permit2", x402UptoEip155Permit2],
  ["x402/auth-capture/eip155/eip3009", x402AuthCaptureEip155Eip3009],
  ["x402/auth-capture/eip155/permit2", x402AuthCaptureEip155Permit2],
  ["x402/exact/solana", x402ExactSolana],
  ["x402/upto/solana", x402UptoSolana],
  ["x402/exact/xrpl", x402ExactXrpl],
  ["x402/exact/hedera", x402ExactHedera],
  ["x402/exact/hedera/transfer-executor", x402ExactHederaTransferExecutor],
  ["x402/exact/algorand", x402ExactAlgorand],
  ["x402/exact/stellar/precondition", x402ExactStellarPrecondition],
  ["mpp/charge/evm/authorization", mppChargeEvmAuthorization],
  ["mpp/charge/evm/permit2", mppChargeEvmPermit2],
  ["mpp/charge/evm/transaction", mppChargeEvmTransaction],
  ["mpp/charge/evm/hash", mppChargeEvmHash],
  ["mpp/charge/solana", mppChargeSolana],
  ["mpp/charge/xrpl", mppChargeXrpl],
  ["mpp/charge/nearintents", mppChargeNearIntents],
  ["mpp/session/xrpl", mppSessionXrpl],
  ["x402/exact/near", x402ExactNear],
  ["x402/exact/tron/lcp-trc20-memo", x402ExactTronLcpTrc20Memo],
  ["x402/exact/tvm", x402ExactTvm],
  ["x402/exact/starknet", x402ExactStarknet],
  ["x402/exact/polkadot/lcp-assets-remark", x402ExactPolkadotLcpAssetsRemark],
  ["x402/exact/sui", x402ExactSui],
  ["x402/exact/aptos", x402ExactAptos],
  ["x402/exact/cardano", x402ExactCardano],
  ["x402/exact/cardano/lock", x402ExactCardanoLock],
  ["x402/exact/casper", x402ExactCasper],
  ["x402/exact/ccd", x402ExactCcd],
  ["mpp/charge/lightning", mppChargeLightning],
  ["mpp/session/lightning", mppSessionLightning],
  ["card/visa-tap", cardVisaTap],
  ["card/mastercard-vi/immediate", cardMastercardViImmediate],
  ["card/mastercard-vi/autonomous", cardMastercardViAutonomous],
  ["card/seller-reference", cardSellerReference],
  ["ap2/checkout-mandate", ap2CheckoutMandate],
  ["ucp/checkout/ap2-mandate", ucpCheckoutAp2Mandate],
  ["ucp/checkout/unsigned", ucpCheckoutUnsigned],
  ["ucp/booking/ap2-mandate", ucpBookingAp2Mandate],
  ["ucp/booking/unsigned", ucpBookingUnsigned],
  ["acp/checkout/delegated", acpCheckoutDelegated],
  ["acp/checkout/undelegated", acpCheckoutUndelegated],
  ["ack/payment-request", ackPaymentRequest],
  ["x402/batch-settlement/eip155", x402BatchSettlementEip155],
  ["x402/batch-settlement/solana", x402BatchSettlementSolana],
  ["x402/batch-settlement/cloudflare", x402BatchSettlementCloudflare],
  ["mpp/session/evm", mppSessionEvm],
  ["mpp/session/tempo", mppSessionTempo],
  ["mpp/subscription/tempo", mppSubscriptionTempo],
  ["mpp/charge/card", mppChargeCard],
  ["mpp/charge/stripe", mppChargeStripe],
  ["mpp/subscription/stripe", mppSubscriptionStripe],
  ["mpp/charge/usdc/evm", mppChargeUsdcEvm],
  ["mpp/charge/usdc/solana", mppChargeUsdcSolana],
  ["mpp/charge/usdc/stacks", mppChargeUsdcStacks],
  ["mpp/charge/usdc/gateway", mppChargeUsdcGateway],
  ["mpp/session/hedera/stock", mppSessionHederaStock],
  ["mpp/session/xrpl/stock", mppSessionXrplStock],
  ["x402/upto/xrpl", x402UptoXrpl],
  ["mpp/charge/lcp/hedera", mppChargeLcpHedera],
  ["mpp/charge/solana/unsponsored", mppChargeSolanaUnsponsored],
  ["mpp/subscription/solana", mppSubscriptionSolana],
  ["ap2/checkout-mandate/x402", ap2CheckoutMandateX402],
  ["ucp/checkout/agent-signed", ucpCheckoutAgentSigned],
  ["card/visa-vic", cardVisaVic],
  ["card/mastercard-agent-pay", cardMastercardAgentPay],
  ["spend-permissions/eip155", spendPermissionsEip155Piece],
]);
