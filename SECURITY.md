# Security

The packages in this repository check, before a buyer signs, that a payment carries the hash of the record the seller
serves. A flaw that lets a payment be signed without that match, or returned with a hash other than the one compared,
is a vulnerability. We want to hear about it privately.

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

## What is in scope

- `@integraledger/terms`, `@integraledger/terms-mcp` and `integraledger-terms`, as published from this repository.
- The skill in `agentic-terms-mcp/skills/`, where its instructions would lead an agent to sign or send a payment the
  tools declined.

Examples of what we treat as vulnerabilities:

- the signer is called before the served bytes are compared with the advertised hash, or after they fail to match;
- `finish`, `transact` or a tool returns a payment whose signed contents do not carry the hash of the compared bytes;
- the ATR fetch exceeds its bounds (one `https` request, no redirect, 10 seconds, 1 MiB);
- the TypeScript and Python gates accept different payments for the same inputs.

## What is not in scope

- Anything that depends on the content of the ATR. The gate compares hashes; it does not judge terms, amounts or payees.
- Vulnerabilities in a seller's server, a facilitator, a wallet, or a chain. Report those to their maintainers.
- Vulnerabilities in a dependency with no effect on these packages. Report those upstream.

## Bugs that are not vulnerabilities

Open a public [issue](https://github.com/IntegraLedger/integra-agentic-terms/issues).
