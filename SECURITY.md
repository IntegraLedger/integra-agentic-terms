# Security policy

The packages in this repository check, before a buyer signs, that a payment carries the hash of the record the seller
serves and is held to what that record's binding slot commits to; and, in `transact`, that each
signing is shown to the buyer's approver and bounded in time. A flaw that defeats any of these is a vulnerability. We
want to hear about it privately. The [security model](./docs/security-model.md) states what the packages guarantee,
what they trust and what they leave to the caller.

## Reporting a vulnerability

Report it through GitHub's
[private vulnerability reporting](https://github.com/IntegraLedger/integra-agentic-terms/security/advisories/new) on this
repository: the **Report a vulnerability** button under the **Security** tab. Only the maintainers can read the report.

Do not open a public issue, discussion or pull request for a vulnerability.

Include what you can:

- the package and version, or the commit;
- the pairing, if the problem is specific to one;
- what happens, and what should happen instead;
- the smallest input that shows it: a seller document, the bytes served, a signer's answer;
- whether both the TypeScript and the Python gate are affected.

We confirm that we received the report, keep you informed while we work on it, and credit you in the advisory if you
wish.

## Supported versions

Security fixes are released for the latest published version of each package.

## What counts

- `@integraledger/terms`, `@integraledger/terms-mcp` and `integraledger-terms`, as published from this repository.
- The skill in `agentic-terms-mcp/skills/`, where its instructions would lead an agent to sign or send a payment the
  tools declined.

Examples of what we treat as vulnerabilities:

- the signer is called before the served bytes are compared with the advertised hash, or after they fail to match;
- `finish`, `transact` or a tool returns a payment from which the pairing reads a hash other than that of the compared
  bytes, or reads none where the proof is not the agreement payment;
- the ATR fetch exceeds its bounds (one `https` request, no redirect, 10 seconds, 1 MiB);
- the TypeScript and Python gates accept different payments for the same inputs;
- `transact` calls the signer without the approver's `true`, or a summary omits or misstates an authority the signed
  request grants;
- `transact` signs, or `confirm` or `finish` returns to be signed, a payment that stays payable past its pairing's
  ceiling;
- an option outside the ATR's `x402` `accepts` or `mpp` `challenges`, or a request other than the `x402` slot's request
  commitment, is paid;
- bytes that are not one JSON text both gates read alike are accepted.

## What does not

- What the ATR's terms say. The gate parses the ATR and reads only its binding slot's options and request commitment;
  it does not judge terms, amounts or payees.
- Vulnerabilities in a seller's server, a facilitator, a wallet, or a chain. Report those to their maintainers.
- Vulnerabilities in a dependency with no effect on these packages. Report those upstream.

## Bugs that are not vulnerabilities

Open a public [issue](https://github.com/IntegraLedger/integra-agentic-terms/issues).
