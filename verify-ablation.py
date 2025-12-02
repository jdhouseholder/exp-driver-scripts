import json
import base64
import time

import numpy as np
import rlp

from hash_table import HashTableClient
from simple_pirate import serde
from simple_pirate.parameters import solve_system_parameters
from simple_pirate import simplepir
from verify_proof import verify_eth_trie_proof

from simple_flotilla.load_cfg import load_cfg
from simple_flotilla.flotilla import FlotillaClient
from simple_pirate.serde import mmap_to_uint64

from decode import *

def main():
    root = "./final-demodata"

    state_root = bytes.fromhex(
        "7481b1a92483682b38601554b8c65c2ecf52cecac8d91bd8729e0d31ea76d446"
    )

    def fetch(client, server, index) -> bytes:
        state, query = client.query(index)
        answer = server.answer([query])
        got = client.recover_large_record(state, answer[0])
        got = serde.uint64_list_to_bytes(got)
        return got

    with open(f"{root}/hash-table.metadata.json", "r") as f:
        ht_md = json.load(f)

    with open(f"{root}/accounts.metadata.json", "r") as f:
        data_md = json.load(f)

    print(data_md)

    with open(f"{root}/debug.jsonl", "r") as f:
        debug = []
        for line in f:
            debug.append(json.loads(line))

    account_n_records = data_md["n_records"]
    account_record_size = data_md["record_size"]
    bits_per_account_entry = account_record_size * 8

    account_db = mmap_to_uint64(f"{root}/accounts.bin")
    account_parameters = solve_system_parameters(
        entries=account_n_records,
        bits_per_entry=bits_per_account_entry,
    )

    account_server = simplepir.SimplePirServer(account_parameters, account_db)
    account_client = simplepir.SimplePirClient(
        account_parameters,
        account_server.get_offline_data(),
    )


    with open(f"{root}/ablation.metadata.json", "r") as f:
        ablation_md = json.load(f)

    proof_n_records = ablation_md["n_records"]
    proof_record_size = ablation_md["record_size"]

    db = mmap_to_uint64(f"{root}/ablation.bin")

    parameters = solve_system_parameters(
        entries=proof_n_records,
        bits_per_entry=proof_record_size * 8,
    )

    proof_server = simplepir.SimplePirServer(parameters, db)

    proof_client = simplepir.SimplePirClient(
        parameters,
        proof_server.get_offline_data(),
    )


    htc = HashTableClient(ht_md["hash_seeds"], ht_md["capacity"])
    
    account_durs_ms = []
    top_proof_durs_ms = []
    proof_durs_ms = []
    total_durs_ms = []

    for n, d in enumerate(debug[:10]):
        found = False
        want_value = d["value"]
        want = base64.b64decode(want_value)
        key = base64.b64decode(d["address_hash_bytes"])

        start = time.perf_counter_ns()

        for i in htc.indicies_for(key):
            account_start = time.perf_counter_ns()
            got = fetch(account_client, account_server, i)
            got = unpad(got, account_record_size)
            got_key = extract_account_hash(got)

            account_stop = time.perf_counter_ns()
            account_elapsed_ms = (account_stop - account_start) / 1e6
            account_durs_ms.append(account_elapsed_ms)

            if got_key == key:
                print(f"{n}: found")
                found = True
                break

        if not found:
            print(f"{n}: OOPS")
            exit()

        got_proof_idxs = extract_proof_indexes(got)
        proof_nodes = []
        for pidx in got_proof_idxs:
            proof_start = time.perf_counter_ns()

            row_id = pidx["row_id"]

            # This should be parallel but this is okay for now.
            proof_bytes = fetch(proof_client, proof_server, row_id)
            proof_stop = time.perf_counter_ns()

            proof_elapsed_ms = (proof_stop - proof_start) / 1e6
            proof_durs_ms.append(proof_elapsed_ms)

            proof_bytes = unpad(proof_bytes, proof_record_size)
            proof_nodes.append(proof_bytes)

        got_account = extract_account(got)
        account = verify_eth_trie_proof(state_root, got_key, proof_nodes)
        assert rlp.decode(got_account, strict=False) == rlp.decode(account)
        stop = time.perf_counter_ns()

        elapsed_ms = (stop - start) / 1e6
        total_durs_ms.append(elapsed_ms)

    def summarize(a, b, c, durs):
        total_durs_ms = np.asarray(durs)
        p98 = np.percentile(total_durs_ms, 98, method='linear') 
        print(f"\t\t{a} & {b} & {c} & {total_durs_ms.mean():.2f}ms & {p98:.2f}ms\\\\")

    summarize("Accounts", "17Gib", "", account_durs_ms)
    summarize("TreeTop", "16Kib", "", top_proof_durs_ms)
    summarize("Proof Shard", "330Mib", "", proof_durs_ms)
    print(f"\t\t\\hline")
    summarize("Total", "", "", total_durs_ms)

if __name__ == "__main__":
    main()
