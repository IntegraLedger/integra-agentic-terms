"""The buyer half of the pairing mpp/session/solana: read, build with complete, bound, and the channel members
(channel_kind, channel_ref, bound_within, build_within).

The ATR hash rides as the channel's salt, H's first 8 bytes read as a little-endian u64, which the payer signs in the
channel program's open instruction; H itself is in the challenge the opening answers. Nothing here fetches, hashes an
ATR or signs.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._channel import BatchUnsigned, ChannelKind, ChannelRef
from ._codec import b58_decode, canonical_json
from ._lcp import is_object, is_well_formed
from ._mpp import (
    Echoed,
    EchoedChallenge,
    MppUnsigned,
    chosen_for,
    credential_of,
    echoed_for,
    fetched_of,
    measured,
    measuring,
    read,
    session_broadcaster,
)
from ._mpp_checks import solana_network_of
from ._session_within import action_kind, echoed_details, within_checks
from ._svm import (
    SvmTx,
    channel_voucher_message,
    decode_svm_tx,
    key_bytes,
    key_string,
    loaded_keys,
    static_nonce,
    wire_of,
)

ID = "mpp/session/solana"
OPEN_DISCRIMINATOR = 1
OPEN_MIN_DATA = 33
OPEN_MIN_ACCOUNTS = 6
OPEN_CHANNEL_ACCOUNT = 5
# The open instruction's authorizedSigner account.
OPEN_SIGNER_ACCOUNT = 4
WITHIN_ACTIONS = ("voucher", "topUp", "use")
U64_LIMIT = 1 << 64


def session_salt(h: AtrHash) -> int:
    """H's first 8 bytes read as a little-endian u64, so the salt's encoded bytes are exactly those 8 bytes."""
    return int.from_bytes(bytes.fromhex(h[2:18]), "little")


def session_proof(channel_id: str, payer: str, challenge_id: str) -> bytes:
    """The UTF-8 of the RFC 8785 JSON of {channelId, domain: "mpp-session-auth-v1", payer, sessionChallengeId}. Raises
    TypeError when channel_id, payer or challenge_id is not a string with a UTF-8 form: one holding a lone surrogate
    has none, so no message is made that the caller did not write."""
    if not is_well_formed(channel_id) or not is_well_formed(payer) or not is_well_formed(challenge_id):
        raise TypeError("session_proof: channel_id, payer and challenge_id must be strings with a UTF-8 form")
    text = canonical_json(
        {"channelId": channel_id, "domain": "mpp-session-auth-v1", "payer": payer, "sessionChallengeId": challenge_id}
    )
    return text.encode("utf-8")


@dataclass(frozen=True, slots=True)
class Open:
    """The open instruction: its salt and its account indexes."""

    salt: int
    accounts: tuple[int, ...]


def open_of(tx: SvmTx, program: object, key_count: int) -> Open | Refusal:
    """The one top-level instruction of program whose data starts with the open discriminator, with at least 33 bytes
    of data and 6 accounts, and its salt (data bytes 1-8, little-endian). svm/open-not-found when there is none, or
    more than one, or when its channel (account 5) is past key_count, the count of every key the message names: its
    static keys and each address its address table lookups load."""
    program_key = key_bytes(program)
    if program_key is None:
        return Refusal("svm/open-not-found")
    opens = [
        ix
        for ix in tx.instructions
        if ix.program < len(tx.keys)
        and tx.keys[ix.program] == program_key
        and len(ix.data) >= OPEN_MIN_DATA
        and ix.data[0] == OPEN_DISCRIMINATOR
        and len(ix.accounts) >= OPEN_MIN_ACCOUNTS
    ]
    if len(opens) != 1:
        return Refusal("svm/open-not-found")
    ix = opens[0]
    if ix.accounts[OPEN_CHANNEL_ACCOUNT] >= key_count:
        return Refusal("svm/open-not-found")
    return Open(int.from_bytes(ix.data[1:9], "little"), ix.accounts)


@dataclass(frozen=True, slots=True)
class OpenAccounts:
    signer: str | None
    channel: str


def open_accounts(o: Open, keys: Sequence[bytes]) -> OpenAccounts | Refusal:
    """The open's authorizedSigner (account 4; None for an index past keys) and channel (account 5; an index past keys
    is svm/open-not-found), each read from keys: the message's static keys, or every key its instructions may index
    once its address table lookups are resolved (loaded_keys)."""
    position, signer = o.accounts[OPEN_CHANNEL_ACCOUNT], o.accounts[OPEN_SIGNER_ACCOUNT]
    if position >= len(keys):
        return Refusal("svm/open-not-found")
    return OpenAccounts(key_string(keys[signer]) if signer < len(keys) else None, key_string(keys[position]))


@dataclass(frozen=True, slots=True)
class Opening:
    """A checked opening: its H, its echoed challenge, its payload, its signed transaction, and its open's
    authorizedSigner."""

    h: AtrHash
    checked: EchoedChallenge
    payload: Mapping[str, Any]
    tx: SvmTx
    signer: str | None


@dataclass(frozen=True, slots=True)
class _Static:
    tx: SvmTx
    open: Open
    channel_id: str
    operator: str | None


def _static(presented: Mapping[str, Any], e: Echoed) -> _Static | Refusal:
    """The opening's checks that read no account, in order: the program, methodDetails.channelProgram, a key, else
    svm/input-malformed; the transaction; a durable nonce account named through an address lookup table,
    svm/nonce-account-not-static; the one open of the program, svm/open-not-found when there is none, or more than one,
    or when its channel (account 5) is past every key the message names; its salt H's first 8 bytes, else
    mpp/carrier-not-challenge; the payload's channelId a key, else svm/channel-mismatch; then authentication, which
    draft-solana-session-00's open action requires for an operator voucher signer and forbids for client, the default:
    missing for operator, or present for client, is mpp/credential-malformed; present, it names the echoed challenge's
    id, else svm/proof-not-challenge; and for operator, the challenge's operator a key, else svm/signer-not-operator.
    Each comes before any address lookup table is read, so an opening that fails one gets its code whatever its
    lookups hold."""
    program = e.checked.details.get("channelProgram")
    if not isinstance(program, str) or key_bytes(program) is None:
        return Refusal("svm/input-malformed")
    wire = wire_of(e.payload.get("transaction"))
    if isinstance(wire, Refusal):
        return wire
    tx = decode_svm_tx(wire)
    if isinstance(tx, Refusal):
        return tx
    from_table = static_nonce(tx)
    if from_table is not None:
        return from_table
    loaded = sum(len(lookup.writable) + len(lookup.readonly) for lookup in tx.lookups)
    opened = open_of(tx, program, len(tx.keys) + loaded)
    if isinstance(opened, Refusal):
        return opened
    if opened.salt != session_salt(e.h):
        return Refusal("mpp/carrier-not-challenge")
    declared = key_bytes(e.payload.get("channelId"))
    if declared is None:
        return Refusal("svm/channel-mismatch")
    authenticated = "authentication" in e.payload
    operator_mode = e.checked.details.get("voucherSigner") == "operator"
    if operator_mode != authenticated:
        return Refusal("mpp/credential-malformed")
    if authenticated:
        auth = e.payload["authentication"]
        if not is_object(auth) or auth.get("challengeId") != presented["challenge"].get("id"):
            return Refusal("svm/proof-not-challenge")
    operator = key_bytes(e.checked.details.get("operator")) if operator_mode else None
    if operator_mode and operator is None:
        return Refusal("svm/signer-not-operator")
    return _Static(tx, opened, key_string(declared), None if operator is None else key_string(operator))


def _opening(presented: Mapping[str, Any]) -> Opening | Refusal:
    """The opening's checks: first those that read no account (_static). Then the open's accounts: its channel the
    payload's channelId, else svm/channel-mismatch, and, for operator, its authorizedSigner (account 4) the challenged
    operator, as draft-solana-session-00 requires, else svm/signer-not-operator; for client, the client chooses that
    signer. The draft has the server validate the complete compiled message, resolving any version-0 address lookup
    table entries (Settlement Procedure, Open, step 9), and a table can supply account 4 or account 5. So the accounts
    are read from the static keys and, for a message with address table lookups, from the tables read for the opening
    and held in Held, as @integraledger/lcp holds them under the payment's own FETCHED member (fetched_of), in the
    runtime's order (loaded_keys): such an opening without them, or whose tables are not one entry per lookup naming
    its table with as many keys as it names indexes, is svm/read-first, and
    one whose loaded keys repeat a static key or each other is svm/table-unusable. A tables member of the opening's own
    is not read: an opening carrying one gives the answer the same opening without it gives. A message without lookups
    is read from its static keys, whatever the opening carries."""
    e = echoed_for(presented, ID)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("action") != "open":
        return Refusal("mpp/session-action")
    s = _static(presented, e)
    if isinstance(s, Refusal):
        return s
    keys: Sequence[bytes] = s.tx.keys
    if s.tx.lookups:
        read = fetched_of(presented)
        loaded = loaded_keys(s.tx, read.get("tables") if is_object(read) else None)
        if isinstance(loaded, Refusal):
            return loaded
        keys = loaded
    accounts = open_accounts(s.open, keys)
    if isinstance(accounts, Refusal):
        return accounts
    if accounts.channel != s.channel_id:
        return Refusal("svm/channel-mismatch")
    if s.operator is not None and accounts.signer != s.operator:
        return Refusal("svm/signer-not-operator")
    return Opening(e.h, e.checked, e.payload, s.tx, accounts.signer)


def _kind(presented: object) -> ChannelKind | Refusal:
    """The kind of a Solana session payment by its action, read against the echoed challenge's voucherSigner (client
    when absent), as draft-solana-session-00 says: a voucher authorizes service only for client, and in operator mode
    does not authenticate the caller; a use is valid only for operator; a close carries voucher and no authentication
    for client, and authentication and no voucher for operator. A voucher whose challenge names operator, or a use
    whose challenge names client or no voucherSigner, is mpp/session-action; a close that lacks the member its mode
    requires, or carries the one its mode forbids, is mpp/credential-malformed."""
    k = action_kind(presented, WITHIN_ACTIONS)
    if isinstance(k, Refusal):
        return k
    assert is_object(presented)
    payload = presented["payload"]
    action = payload.get("action")
    if action not in ("voucher", "use", "close"):
        return k
    details = echoed_details(presented, "solana")
    if isinstance(details, Refusal):
        return details
    operator = details.get("voucherSigner") == "operator"
    if action == "close":
        voucher, authenticated = "voucher" in payload, "authentication" in payload
        return k if voucher != operator and authenticated == operator else Refusal("mpp/credential-malformed")
    return k if operator == (action == "use") else Refusal("mpp/session-action")


def is_base58_signature(value: object) -> bool:
    """A base58 string of 64 to 88 characters that decodes to a 64-byte Ed25519 signature."""
    if not isinstance(value, str) or not 64 <= len(value) <= 88:
        return False
    decoded = b58_decode(value)
    return decoded is not None and len(decoded) == 64


@dataclass(frozen=True, slots=True)
class MppSessionSolana:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash) -> MppUnsigned | Refusal:
        """The values the buyer's channel client composes the open from: the salt (H's first 8 bytes), the program,
        the network and the request's blockhash and slot. complete checks the composed open as bound does before
        returning the credential: it carries authentication when the challenge's voucherSigner is operator, and none
        otherwise. complete reads no address lookup table, so an open whose message has lookups is svm/read-first."""
        if not is_object(choice):
            return Refusal("svm/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        network = solana_network_of(checked.details, True)
        if network is None:
            return Refusal("svm/network-undeclared")
        if isinstance(network, Refusal):
            return network
        challenge = dict(checked.challenge)
        d = checked.details

        def complete(open_payload: Any) -> dict[str, Any] | Refusal:
            """The opening credential, {challenge, payload: open_payload}, once bound's read of it (_opening) takes
            it, else that read's refusal: a payload that is not an object, or a credential over the credential size
            bound, is mpp/credential-malformed, and another action mpp/session-action."""
            credential = {"challenge": challenge, "payload": open_payload}
            o = _opening(credential)
            return o if isinstance(o, Refusal) else credential

        request = {
            "kind": "solana-session-open",
            "salt": session_salt(h),
            "channelProgram": d["channelProgram"],
            "network": network,
            "recentBlockhash": d["recentBlockhash"],
            "recentSlot": int(d["recentSlot"]),
        }
        return MppUnsigned(request, complete)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """H from the echoed challenge, once the signed open's salt is H's first 8 bytes and its channel the
        payload's, its accounts read as the opening's checks read them: through the tables held in Held, as
        @integraledger/lcp holds them under the payment's own FETCHED member, for an opening whose message has address
        table lookups. No signature is verified here."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        o = _opening(credential)
        return o if isinstance(o, Refusal) else o.h

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts every payment the session takes, for the actions channel_kind takes, as
        draft-solana-session-00 has it: the seller's server co-signs and broadcasts the opening and a top-up, each a
        transaction the payer signed, redeems vouchers and the operator's use metering when it settles, and broadcasts
        the close. Any other action, a voucher where the challenge's voucherSigner is operator and a use where it is not
        among them, gets mpp/session-action, as bound refuses it. bound reads the opening alone, so channel_kind reads
        the rest: a close that lacks the member its mode requires, or carries the one its mode forbids, gets
        mpp/credential-malformed, as channel_kind refuses it. Where channel_kind refuses the echoed challenge itself
        (another intent or method, or a request that does not decode or whose methodDetails is not an object), the
        challenge decides, and broadcaster answers."""
        return session_broadcaster(
            presented, _kind, lambda c: "payee", "mpp/session-action", lambda c: echoed_details(c, "solana")
        )

    @measuring
    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """open; close, carrying voucher under a client voucher signer and authentication under an operator one; or
        within for a topUp, a voucher under a client voucher signer, or a use under an operator one."""
        return _kind(presented)

    @measuring
    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The network and the payload's channelId, re-encoded from its 32 bytes; on a within or close payment, read
        from the payment itself. A voucher whose challenge's voucherSigner is operator, a use whose challenge's is not,
        and a close whose voucher and authentication are not its mode's, are refused as channel_kind refuses them."""
        kind = _kind(presented)
        if isinstance(kind, Refusal):
            return kind
        details: Mapping[str, Any]
        if kind == "open":
            e = echoed_for(presented, ID)
            if isinstance(e, Refusal):
                return e
            details = e.checked.details
        else:
            d = echoed_details(presented, "solana")
            if isinstance(d, Refusal):
                return d
            details = d
        network = solana_network_of(details, True)
        if network is None:
            return Refusal("svm/network-undeclared")
        if isinstance(network, Refusal):
            return network
        assert is_object(presented)
        channel = key_bytes(presented["payload"].get("channelId"))
        return Refusal("mpp/credential-malformed") if channel is None else ChannelRef(network, key_string(channel))

    @measuring
    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A use credential echoing the opening challenge, whose bearer proof names that challenge's id, gives its H.
        A voucher or topUp signs no value holding H. A voucher whose challenge's voucherSigner is operator, a use whose
        challenge's is not, and a close whose voucher and authentication are not its mode's, are refused as
        channel_kind refuses them."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        kind = _kind(credential)
        if isinstance(kind, Refusal):
            return kind
        if credential["payload"].get("action") != "use":
            return Refusal("mpp/not-bound-within")
        e = echoed_for(credential, ID)
        if isinstance(e, Refusal):
            return e
        auth = e.payload.get("authentication")
        if not is_object(auth) or auth.get("challengeId") != credential["challenge"].get("id"):
            return Refusal("svm/proof-not-challenge")
        return e.h

    def build_within(self, w: Mapping[str, Any], h: AtrHash) -> BatchUnsigned | Refusal:
        """A voucher, or a close's voucher, on the channel the held opening opened, for its client voucher signer: one
        ed25519-raw request over the channel voucher message (channel id, cumulative amount, no expiry), for the
        authorizedSigner of the opening's one open instruction, the key vouchers "MUST verify under"
        (draft-solana-session-00). The opening is read as bound reads it: for a message with address table lookups,
        through the tables held for it in Held, else svm/read-first, so the opening is the one held with its tables
        for the life of the channel. An operator channel's vouchers are the operator's, and are not built, nor are a
        topUp or a use; an action draft-solana-session-00 does not define, such as bearer, is mpp/session-action."""
        o = within_checks(w, h, "session/solana", _opening, U64_LIMIT, ("topUp", "use"))
        if isinstance(o, Refusal):
            return o
        if o.checked.details.get("voucherSigner") == "operator":
            return Refusal("mpp/within-action-not-built")
        signer = o.signer
        if signer is None:
            return Refusal("svm/open-not-found")
        channel = key_bytes(w["opening"]["payload"].get("channelId"))
        if channel is None:
            return Refusal("mpp/credential-malformed")
        channel_id = key_string(channel)
        message = channel_voucher_message(channel_id, w["cumulativeAmount"], 0)
        if message is None:
            return Refusal("svm/input-malformed")
        challenge = dict(w["challenge"])
        action = w["action"]
        amount = str(w["cumulativeAmount"])

        def complete(signatures: Any) -> dict[str, Any] | Refusal:
            signature = signatures[0] if isinstance(signatures, (list, tuple)) and len(signatures) == 1 else None
            if not is_base58_signature(signature):
                return Refusal("mpp/credential-malformed")
            voucher = {"voucher": {"channelId": channel_id, "cumulativeAmount": amount}, "signer": signer, "signature": signature, "signatureType": "ed25519"}
            payload = {"action": action, "channelId": channel_id, "voucher": voucher}
            return measured({"challenge": challenge, "payload": payload})

        return BatchUnsigned(requests=[{"kind": "ed25519-raw", "message": message, "signer": signer}], complete=complete)


MPP_SESSION_SOLANA = MppSessionSolana()
