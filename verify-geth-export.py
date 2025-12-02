import json
import base64

import rlp

from hash_table import HashTableClient
from verify_proof import verify_eth_trie_proof
from decode import *

state_root = bytes.fromhex(
    "7481b1a92483682b38601554b8c65c2ecf52cecac8d91bd8729e0d31ea76d446"
)

with open("./demodata/hash-table.metadata.json", "r") as f:
    ht_md = json.load(f)

with open("./demodata/accounts.metadata.json", "r") as f:
    data_md = json.load(f)

with open("./demodata/debug.jsonl", "r") as f:
    debug = []
    for line in f:
        debug.append(json.loads(line))

n_account_records = data_md["n_records"]
record_size = data_md["record_size"]
with open("./demodata/accounts.bin", "rb") as f:
    account_db = []
    for i in range(n_account_records):
        account_db.append(f.read(record_size))


with open("./demodata/treeTop.metadata.json", "r") as f:
    tree_top_md = json.load(f)
    size_of_proof_record = tree_top_md["record_size"]

with open("./demodata/treeTop.bin", "rb") as f:
    tree_top_db = []
    for i in range(tree_top_md["n_records"]):
        tree_top_db.append(f.read(tree_top_md["record_size"]))

proof_dbs = []
for i in range(64):
    with open(f"./demodata/account-proofs-{i}.metadata.json", "r") as f:
        proof_db_md = json.load(f)
        assert proof_db_md["record_size"] == size_of_proof_record
        n_records = proof_db_md["n_records"]

    with open(f"./demodata/account-proofs-{i}.bin", "rb") as f:
        db = []
        for i in range(n_records):
            db.append(f.read(size_of_proof_record))
    proof_dbs.append(db)

htc = HashTableClient(ht_md["hash_seeds"], ht_md["capacity"])

print(ht_md, data_md)
for n, d in enumerate(debug):
    found = False
    want_value = d["value"]
    want_record = base64.b64decode(want_value)
    key = base64.b64decode(d["address_hash_bytes"])

    got = None
    for i in htc.indicies_for(key):
        got = account_db[i]
        got = unpad(got, record_size)
        if got == want_record:
            found = True
            break

    if not found:
        print(f"{n}: OOPS")
        print(want_value)
        exit()

    got_key = extract_account_hash(got)
    assert got_key == key

    got_proof_idxs = extract_proof_indexes(got)
    proof_nodes = []
    for pidx in got_proof_idxs:
        bucket_id = pidx["bucket_id"]
        row_id = pidx["row_id"]

        if bucket_id == 255:
            proof_bytes = tree_top_db[row_id]
        else:
            bucket = proof_dbs[bucket_id]
            proof_bytes = bucket[row_id]

        proof_bytes = unpad(proof_bytes, tree_top_md["record_size"])
        proof_nodes.append(proof_bytes)

    got_account = extract_account(got)
    account = verify_eth_trie_proof(state_root, got_key, proof_nodes)
    assert rlp.decode(got_account, strict=False) == rlp.decode(account)

print("DANG")
