"""The Unicode 17.0.0 tables the URL host parser reads, bindings/_idna_data.py, are the integra-protocol repository's
scripts/idna/_idna_data.py byte for byte: its scripts/idna/idna-data.mjs writes them from Unicode's files, whose
addresses and SHA-256 the module's docstring names, and @integraledger/lcp's host parser reads the same tables. The
expected SHA-256 is that file's."""

import hashlib
from pathlib import Path

from integraledger_terms.bindings import _idna_data

TABLES_SHA256 = "55f0feb88c1ca76744e8457b583049ead56f79ac7b2330bd7e6fadc1ccd96ea6"


def test_the_tables_are_the_protocol_repositorys_file_byte_for_byte() -> None:
    assert hashlib.sha256(Path(_idna_data.__file__).read_bytes()).hexdigest() == TABLES_SHA256
    assert _idna_data.UNICODE_VERSION == "17.0.0"
