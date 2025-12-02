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
    root = "/home/ec2-user/3.2M-data" 
 
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
    print("account hint size: ", len(account_server.get_offline_data().hint.tobytes())) 
    
    with open(f"{root}/treeTop.metadata.json", "r") as f: 
        tree_top_md = json.load(f) 
    
    tree_top_n_records = tree_top_md["n_records"] 
    proof_record_size = tree_top_md["record_size"] 
    bits_per_proof_entry = proof_record_size * 8 
 
    tree_top_db = mmap_to_uint64(f"{root}/treeTop.bin") 
 
    tree_top_parameters = solve_system_parameters( 
        entries=tree_top_n_records, 
        bits_per_entry=bits_per_proof_entry, 
    ) 
 
    tree_top_server = simplepir.SimplePirServer(tree_top_parameters, tree_top_db) 
    tree_top_client = simplepir.SimplePirClient( 
        tree_top_parameters, 
        tree_top_server.get_offline_data(), 
    ) 
    print("tree top hint size: ", len(tree_top_server.get_offline_data().hint.tobytes())) 
 
    proof_dbs = [] 
    for i in range(64): 
        with open(f"{root}/account-proofs-{i}.metadata.json", "r") as f: 
            proof_db_md = json.load(f) 
            assert proof_db_md["record_size"] == proof_record_size 
            n_records = proof_db_md["n_records"] 
    
        db = mmap_to_uint64(f"{root}/account-proofs-{i}.bin") 
 
        parameters = solve_system_parameters( 
            entries=n_records, 
            bits_per_entry=bits_per_proof_entry, 
        ) 
    
        server = simplepir.SimplePirServer(parameters, db) 
 
        client = simplepir.SimplePirClient( 
            parameters, 
            server.get_offline_data(), 
        ) 
 
        print(f"proof {i} hint size: ", len(server.get_offline_data().hint.tobytes())) 
 
        proof_dbs.append( 
            { 
                "db": db, 
                "client": client, 
                "server": server, 
            } 
        ) 
 
 
    htc = HashTableClient(ht_md["hash_seeds"], ht_md["capacity"]) 
     
    account_durs_ms = [] 
    top_proof_durs_ms = [] 
    proof_durs_ms = [] 
    parallel_durs_ms = [] 
    total_durs_ms = [] 
 
    for n, d in enumerate(debug[:100]): 
        found = False 
        want_value = d["value"] 
        want = base64.b64decode(want_value) 
        key = base64.b64decode(d["address_hash_bytes"]) 
 
        this_round_account_ms = [] 
        start = time.perf_counter_ns() 
 
        for i in htc.indicies_for(key): 
            account_start = time.perf_counter_ns() 
            got = fetch(account_client, account_server, i) 
            got = unpad(got, account_record_size) 
            got_key = extract_account_hash(got) 
 
            account_stop = time.perf_counter_ns() 
            account_elapsed_ms = (account_stop - account_start) / 1e6 
            account_durs_ms.append(account_elapsed_ms) 
            this_round_account_ms.append(account_elapsed_ms) 
 
            if got_key == key: 
                print(f"{n}: found") 
                found = True 
                break 
 
        if not found: 
            print(f"{n}: OOPS") 
            exit() 
 
        got_proof_idxs = extract_proof_indexes(got) 
        proof_nodes = [] 
        this_round_proof_ms = [] 
        for pidx in got_proof_idxs: 
            proof_start = time.perf_counter_ns() 
 
            bucket_id = pidx["bucket_id"] 
            row_id = pidx["row_id"] 
 
            # This should be parallel but this is okay for now. 
            if bucket_id == 255: 
                proof_bytes = fetch(tree_top_client, tree_top_server, row_id) 
                proof_stop = time.perf_counter_ns() 
                proof_elapsed_ms = (proof_stop - proof_start) / 1e6 
                top_proof_durs_ms.append(proof_elapsed_ms) 
                this_round_proof_ms.append(proof_elapsed_ms) 
            else: 
                pdb = proof_dbs[bucket_id] 
                proof_bytes = fetch(pdb["client"], pdb["server"], row_id) 
                proof_stop = time.perf_counter_ns() 
 
                proof_elapsed_ms = (proof_stop - proof_start) / 1e6 
                proof_durs_ms.append(proof_elapsed_ms) 
                this_round_proof_ms.append(proof_elapsed_ms) 
    
            proof_bytes = unpad(proof_bytes, proof_record_size) 
            proof_nodes.append(proof_bytes) 
    
        parallel_durs_ms.append(max(this_round_account_ms) + max(this_round_proof_ms)) 
 
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
    summarize("Parallel", "", "", parallel_durs_ms) 
 
if __name__ == "__main__": 
    main() 

