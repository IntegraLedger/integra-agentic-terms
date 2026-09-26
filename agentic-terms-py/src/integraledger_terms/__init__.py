"""The Python buyer gate: before a buyer signs, confirm that the advertised ATR hash is the SHA-256 of the bytes the
seller's link serves, build the payment with that hash, and confirm the hash inside what was signed."""

from ._agreement import agree
from ._channels import ChannelHold, Within, open_channel, record_charge, within
from ._core import MAX_ATR_BYTES, AtrHash, atr_hash, hash_equals
from ._gate import check, confirm, finish, transact
from ._types import (
    Advertised,
    Agreed,
    AgreementReceipt,
    Binding,
    Checked,
    Chosen,
    Confirmed,
    DeclineCode,
    Declined,
    Finished,
    Inputs,
    Json,
    Next,
    Refusal,
    Signature,
    Signer,
    Step,
    Transacted,
    Unsigned,
)
from .bindings.mpp_card_stripe import charge_card, charge_stripe, subscription_stripe
from .bindings.mpp_charge_evm import (
    MppChargeEvmAuthorization,
    MppChargeEvmHash,
    MppChargeEvmPermit2,
    MppChargeEvmTransaction,
)
from .bindings.mpp_charge_nearintents import MppChargeNearIntents
from .bindings.mpp_charge_tempo import MppChargeTempoMemo, MppChargeTempoPush
from .bindings.mpp_charge_usdc import MppChargeUsdcEvm, MppChargeUsdcGateway
from .bindings.mpp_session import MppSessionEvm, MppSessionTempo, MppSubscriptionTempo
from .bindings._channel import BatchUnsigned, ChannelRef
from .bindings.ack_payment_request import AckPaymentRequest
from .bindings.acp_checkout import AcpCheckoutDelegated, AcpCheckoutUndelegated
from .bindings.ap2_checkout_mandate import Ap2CheckoutMandate
from .bindings.card import CardMastercardViAutonomous, CardMastercardViImmediate, CardSellerReference, CardVisaTap
from .bindings.lightning import (
    MPP_CHARGE,
    MppLightning,
    MppLightningSession,
    X402ExactLnbtc,
    X402ExactLnbtcInvoiceNamed,
)
from .bindings.ucp import (
    BOOKING_AP2_MANDATE,
    BOOKING_UNSIGNED,
    CHECKOUT_AP2_MANDATE,
    CHECKOUT_UNSIGNED,
    UcpAp2Mandate,
    UcpUnsignedPairing,
)
from .bindings.x402_batch_settlement_cloudflare import X402BatchSettlementCloudflare
from .bindings.x402_batch_settlement_eip155 import X402BatchSettlementEip155
from .bindings.x402_evm import (
    X402_AUTH_CAPTURE_EIP155_EIP3009,
    X402_AUTH_CAPTURE_EIP155_PERMIT2,
    X402_EXACT_EIP155_ERC7710,
    X402_EXACT_EIP155_ERC7710_SALT,
    X402_EXACT_EIP155_PERMIT2,
    X402_UPTO_EIP155_PERMIT2,
)
from .bindings.x402_exact_eip155_eip3009 import X402ExactEip155Eip3009
from .bindings.mpp_charge_solana import MPP_CHARGE_SOLANA, MPP_CHARGE_USDC_SOLANA
from .bindings.mpp_session_solana import MPP_SESSION_SOLANA
from .bindings.x402_batch_settlement_solana import X402BatchSettlementSolana
from .bindings.x402_exact_solana import X402ExactSolana
from .bindings.x402_upto_solana import X402UptoSolana
from .bindings.mpp_charge_hedera import MppChargeHedera
from .bindings.mpp_session_hedera import MppSessionHedera
from .bindings.x402_exact_hedera import X402ExactHedera, X402ExactHederaExecutor
from .bindings.x402_exact_near import X402ExactNear
from .bindings.x402_exact_tron_lcp_trc20_memo import X402ExactTronLcpTrc20Memo
from .bindings.x402_exact_tvm import X402ExactTvm
from .bindings.x402_exact_starknet import X402ExactStarknet
from .bindings.x402_exact_casper import X402ExactCasper
from .bindings.x402_exact_aptos import X402ExactAptos
from .bindings.x402_exact_polkadot_lcp_assets_remark import X402ExactPolkadotLcpAssetsRemark
from .bindings.x402_exact_ccd import X402ExactCcd
from .bindings.x402_exact_cardano import X402ExactCardano
from .bindings.x402_exact_sui import X402ExactSui
from .bindings.mpp_charge_stellar import MppChargeStellar
from .bindings.mpp_charge_usdc_stacks import MppChargeUsdcStacks
from .bindings.mpp_charge_xrpl import MppChargeXrpl
from .bindings.mpp_session_xrpl import MppSessionXrpl
from .bindings.x402_exact_algorand import X402ExactAlgorand
from .bindings.x402_exact_stellar import X402ExactStellar
from .bindings.x402_exact_xrpl import X402ExactXrpl

X402_EXACT_EIP155_EIP3009: Binding = X402ExactEip155Eip3009()
X402_EXACT_HEDERA: Binding = X402ExactHedera()
MPP_CHARGE_HEDERA: Binding = MppChargeHedera()
MPP_SESSION_HEDERA: Binding = MppSessionHedera()
X402_EXACT_HEDERA_TRANSFER_EXECUTOR: Binding = X402ExactHederaExecutor()
X402_EXACT_NEAR: Binding = X402ExactNear()
X402_EXACT_TRON_LCP_TRC20_MEMO: Binding = X402ExactTronLcpTrc20Memo()
X402_EXACT_TVM: Binding = X402ExactTvm()
ACK_PAYMENT_REQUEST: Binding = AckPaymentRequest()
ACP_CHECKOUT_DELEGATED: Binding = AcpCheckoutDelegated()
ACP_CHECKOUT_UNDELEGATED: Binding = AcpCheckoutUndelegated()
CARD_VISA_TAP: Binding = CardVisaTap()
AP2_CHECKOUT_MANDATE: Binding = Ap2CheckoutMandate()
UCP_CHECKOUT_AP2_MANDATE: Binding = UcpAp2Mandate(CHECKOUT_AP2_MANDATE)
UCP_CHECKOUT_UNSIGNED: Binding = UcpUnsignedPairing(CHECKOUT_UNSIGNED)
UCP_BOOKING_AP2_MANDATE: Binding = UcpAp2Mandate(BOOKING_AP2_MANDATE)
UCP_BOOKING_UNSIGNED: Binding = UcpUnsignedPairing(BOOKING_UNSIGNED)
X402_EXACT_LNBTC: Binding = X402ExactLnbtc()
X402_EXACT_LNBTC_INVOICE_NAMED: Binding = X402ExactLnbtcInvoiceNamed()
MPP_CHARGE_LIGHTNING: Binding = MppLightning(MPP_CHARGE)
MPP_SESSION_LIGHTNING: Binding = MppLightningSession()
CARD_MASTERCARD_VI_IMMEDIATE: Binding = CardMastercardViImmediate()
CARD_MASTERCARD_VI_AUTONOMOUS: Binding = CardMastercardViAutonomous()
CARD_SELLER_REFERENCE: Binding = CardSellerReference()
X402_BATCH_SETTLEMENT_EIP155 = X402BatchSettlementEip155()
X402_BATCH_SETTLEMENT_CLOUDFLARE = X402BatchSettlementCloudflare()
X402_EXACT_SOLANA: Binding = X402ExactSolana()
X402_BATCH_SETTLEMENT_SOLANA: Binding = X402BatchSettlementSolana()
X402_UPTO_SOLANA: Binding = X402UptoSolana()

MPP_CHARGE_EVM_AUTHORIZATION: Binding = MppChargeEvmAuthorization()
MPP_CHARGE_EVM_PERMIT2: Binding = MppChargeEvmPermit2()
MPP_CHARGE_EVM_TRANSACTION: Binding = MppChargeEvmTransaction()
MPP_CHARGE_EVM_HASH: Binding = MppChargeEvmHash()
MPP_CHARGE_CARD: Binding = charge_card()
MPP_CHARGE_STRIPE: Binding = charge_stripe()
MPP_SUBSCRIPTION_STRIPE: Binding = subscription_stripe()
MPP_CHARGE_NEARINTENTS: Binding = MppChargeNearIntents()
MPP_CHARGE_TEMPO_MEMO: Binding = MppChargeTempoMemo()
MPP_CHARGE_TEMPO_PUSH: Binding = MppChargeTempoPush()
MPP_CHARGE_USDC_EVM: Binding = MppChargeUsdcEvm()
MPP_CHARGE_USDC_GATEWAY: Binding = MppChargeUsdcGateway()
MPP_SESSION_EVM: Binding = MppSessionEvm()
MPP_SESSION_TEMPO: Binding = MppSessionTempo()
MPP_SUBSCRIPTION_TEMPO: Binding = MppSubscriptionTempo()
X402_EXACT_STARKNET: Binding = X402ExactStarknet()
X402_EXACT_CASPER: Binding = X402ExactCasper()
X402_EXACT_APTOS: Binding = X402ExactAptos()
X402_EXACT_POLKADOT_LCP_ASSETS_REMARK: Binding = X402ExactPolkadotLcpAssetsRemark()
X402_EXACT_CCD: Binding = X402ExactCcd()
X402_EXACT_CARDANO: Binding = X402ExactCardano()
X402_EXACT_SUI: Binding = X402ExactSui()

X402_EXACT_XRPL: Binding = X402ExactXrpl()
X402_EXACT_ALGORAND: Binding = X402ExactAlgorand()
X402_EXACT_STELLAR: Binding = X402ExactStellar()
MPP_CHARGE_XRPL: Binding = MppChargeXrpl()
MPP_CHARGE_STELLAR: Binding = MppChargeStellar()
MPP_CHARGE_USDC_STACKS: Binding = MppChargeUsdcStacks()
MPP_SESSION_XRPL: Binding = MppSessionXrpl()

__all__ = [
    "ACK_PAYMENT_REQUEST",
    "ACP_CHECKOUT_DELEGATED",
    "ACP_CHECKOUT_UNDELEGATED",
    "AP2_CHECKOUT_MANDATE",
    "CARD_MASTERCARD_VI_AUTONOMOUS",
    "CARD_MASTERCARD_VI_IMMEDIATE",
    "CARD_SELLER_REFERENCE",
    "CARD_VISA_TAP",
    "MAX_ATR_BYTES",
    "MPP_CHARGE_CARD",
    "MPP_CHARGE_EVM_AUTHORIZATION",
    "MPP_CHARGE_EVM_HASH",
    "MPP_CHARGE_EVM_PERMIT2",
    "MPP_CHARGE_EVM_TRANSACTION",
    "MPP_CHARGE_HEDERA",
    "MPP_CHARGE_LIGHTNING",
    "MPP_CHARGE_NEARINTENTS",
    "MPP_CHARGE_SOLANA",
    "MPP_CHARGE_STRIPE",
    "MPP_CHARGE_TEMPO_MEMO",
    "MPP_CHARGE_TEMPO_PUSH",
    "MPP_CHARGE_USDC_EVM",
    "MPP_CHARGE_USDC_GATEWAY",
    "MPP_CHARGE_USDC_SOLANA",
    "MPP_SESSION_EVM",
    "MPP_SESSION_HEDERA",
    "MPP_SESSION_LIGHTNING",
    "MPP_SESSION_SOLANA",
    "MPP_SESSION_TEMPO",
    "MPP_SUBSCRIPTION_STRIPE",
    "MPP_SUBSCRIPTION_TEMPO",
    "UCP_BOOKING_AP2_MANDATE",
    "UCP_BOOKING_UNSIGNED",
    "UCP_CHECKOUT_AP2_MANDATE",
    "UCP_CHECKOUT_UNSIGNED",
    "X402_AUTH_CAPTURE_EIP155_EIP3009",
    "X402_AUTH_CAPTURE_EIP155_PERMIT2",
    "X402_BATCH_SETTLEMENT_CLOUDFLARE",
    "X402_BATCH_SETTLEMENT_EIP155",
    "X402_BATCH_SETTLEMENT_SOLANA",
    "X402_EXACT_APTOS",
    "X402_EXACT_CARDANO",
    "X402_EXACT_CASPER",
    "X402_EXACT_CCD",
    "X402_EXACT_EIP155_EIP3009",
    "X402_EXACT_EIP155_ERC7710",
    "X402_EXACT_EIP155_ERC7710_SALT",
    "X402_EXACT_EIP155_PERMIT2",
    "X402_EXACT_HEDERA",
    "X402_EXACT_HEDERA_TRANSFER_EXECUTOR",
    "X402_EXACT_LNBTC",
    "X402_EXACT_LNBTC_INVOICE_NAMED",
    "X402_EXACT_NEAR",
    "X402_EXACT_POLKADOT_LCP_ASSETS_REMARK",
    "X402_EXACT_SOLANA",
    "X402_EXACT_STARKNET",
    "X402_EXACT_SUI",
    "X402_EXACT_TRON_LCP_TRC20_MEMO",
    "X402_EXACT_TVM",
    "X402_UPTO_EIP155_PERMIT2",
    "X402_UPTO_SOLANA",
    "X402_EXACT_XRPL",
    "X402_EXACT_ALGORAND",
    "X402_EXACT_STELLAR",
    "MPP_CHARGE_XRPL",
    "MPP_CHARGE_STELLAR",
    "MPP_CHARGE_USDC_STACKS",
    "MPP_SESSION_XRPL",
    "Advertised",
    "Agreed",
    "AgreementReceipt",
    "AtrHash",
    "BatchUnsigned",
    "Binding",
    "ChannelHold",
    "ChannelRef",
    "Checked",
    "Chosen",
    "Confirmed",
    "DeclineCode",
    "Declined",
    "Finished",
    "Inputs",
    "Json",
    "Next",
    "Refusal",
    "Signature",
    "Signer",
    "Step",
    "Transacted",
    "Unsigned",
    "Within",
    "agree",
    "atr_hash",
    "check",
    "confirm",
    "finish",
    "hash_equals",
    "open_channel",
    "record_charge",
    "transact",
    "within",
]
