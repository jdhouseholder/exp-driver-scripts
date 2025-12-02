import asyncio
import json
import base64

import numpy as np
import rlp

from hash_table import HashTableClient
from simple_pirate import serde
from simple_pirate.parameters import solve_system_parameters
from simple_pirate import simplepir
from verify_proof import verify_eth_trie_proof

from simple_flotilla.load_cfg import load_cfg
from simple_flotilla.flotilla import FlotillaClient

from decode import *

async def load_flotilla():
    cfg_path = "/home/j/privacy/simple-flotilla/cfg/flotilla.toml"
    cfg = load_cfg(cfg_path)
    flotilla_cfg = cfg["flotilla"]
    key = flotilla_cfg["key"].encode("utf8")

    parameters = solve_system_parameters(
        entries=flotilla_cfg["entries"],
        bits_per_entry=flotilla_cfg["bits_per_entry"],
    )

    flotilla = FlotillaClient(flotilla_cfg)

    o = await flotilla.get_offline_info()
    hint = o["hint"]

    client = simplepir.SimplePirClient(parameters, simplepir.OfflineData(
        A_key=key,
        hint=hint,
    ))

    return client, flotilla 



async def main():
    state_root = bytes.fromhex(
        "7481b1a92483682b38601554b8c65c2ecf52cecac8d91bd8729e0d31ea76d446"
    )


    def fetch(client, server, index) -> bytes:
        state, query = client.query(index)
        answer = server.answer([query])
        got = client.recover_large_record(state, answer[0])
        got = serde.uint64_list_to_bytes(got)
        return got

    async def afetch(client, flotilla, index) -> bytes:
        state, query = client.query(index)
        answer = await flotilla.answer(query)
        got = client.recover_large_record(state, answer)
        got = serde.uint64_list_to_bytes(got)
        return got


    with open("./sharded-demodata/hash-table.metadata.json", "r") as f:
        ht_md = json.load(f)

    with open("./sharded-demodata/accounts.metadata.json", "r") as f:
        data_md = json.load(f)

    print(ht_md, data_md)

    with open("./sharded-demodata/debug.jsonl", "r") as f:
        debug = []
        for line in f:
            debug.append(json.loads(line))

    n_records = data_md["n_records"]
    account_record_size = data_md["record_size"]
    bits_per_account_entry = account_record_size * 8

    account_client, account_flotilla_server = await load_flotilla()


    with open("./sharded-demodata/treeTop.metadata.json", "r") as f:
        tree_top_md = json.load(f)

    tree_top_n_records = tree_top_md["n_records"]
    proof_record_size = tree_top_md["record_size"]
    bits_per_proof_entry = proof_record_size * 8

    with open("./sharded-demodata/treeTop.bin", "rb") as f:
        tree_top_db = []
        for i in range(tree_top_n_records):
            tree_top_db.extend(serde.bytes_to_uint64_list_no_pad(f.read(proof_record_size)))
        tree_top_db = np.asarray(tree_top_db)

    tree_top_parameters = solve_system_parameters(
        entries=tree_top_n_records,
        bits_per_entry=bits_per_proof_entry,
    )

    tree_top_server = simplepir.SimplePirServer(tree_top_parameters, tree_top_db)
    tree_top_client = simplepir.SimplePirClient(
        tree_top_parameters,
        tree_top_server.get_offline_data(),
    )


    proof_dbs = []
    for i in range(64):
        with open(f"./sharded-demodata/account-proofs-{i}.metadata.json", "r") as f:
            proof_db_md = json.load(f)
            assert proof_db_md["record_size"] == proof_record_size
            n_records = proof_db_md["n_records"]

        with open(f"./sharded-demodata/account-proofs-{i}.bin", "rb") as f:
            db = []
            for i in range(n_records):
                db.extend(serde.bytes_to_uint64_list_no_pad(f.read(proof_record_size)))
            db = np.asarray(db)

        parameters = solve_system_parameters(
            entries=n_records,
            bits_per_entry=bits_per_proof_entry,
        )

        server = simplepir.SimplePirServer(parameters, db)

        client = simplepir.SimplePirClient(
            parameters,
            server.get_offline_data(),
        )

        proof_dbs.append(
            {
                "db": db,
                "client": client,
                "server": server,
            }
        )


    htc = HashTableClient(ht_md["hash_seeds"], ht_md["capacity"])

    for n, d in enumerate(debug):
        found = False
        want_value = d["value"]
        want = base64.b64decode(want_value)
        want_key = base64.b64decode(d["address_hash_bytes"])

        for i in htc.indicies_for(want_key):
            got = await afetch(account_client, account_flotilla_server, i)
            got = unpad(got, account_record_size)
            got_key = extract_account_hash(got)

            if got_key == want_key:
                assert got == want
                print(f"{n}: found")
                found = True
                break

        if not found:
            print(f"{n}: ERROR not found")
            print(f"want={want_value}")
            exit()

        got_proof_idxs = extract_proof_indexes(got)
        proof_nodes = []
        for pidx in got_proof_idxs:
            bucket_id = pidx["bucket_id"]
            row_id = pidx["row_id"]

            if bucket_id == 255:
                proof_bytes = fetch(tree_top_client, tree_top_server, row_id)
            else:
                pdb = proof_dbs[bucket_id]
                proof_bytes = fetch(pdb["client"], pdb["server"], row_id)

            proof_bytes = unpad(proof_bytes, proof_record_size)
            proof_nodes.append(proof_bytes)

        got_account = extract_account(got)
        account = verify_eth_trie_proof(state_root, got_key, proof_nodes)
        assert rlp.decode(got_account, strict=False) == rlp.decode(account)
    print("DANG")

if __name__ == "__main__":
    asyncio.run(main())
