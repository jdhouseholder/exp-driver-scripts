def unpad(b, record_size):
    padding = int.from_bytes(b[:2], "little")
    return b[2 : record_size - padding]


def extract_account_hash(b):
    return b[:32]


def extract_account(b):
    return b[32 : 32 + 83]


def extract_proof_indexes(b):
    proof_index_list = b[32 + 83 :]
    size_of_proof_index = 1 + 4
    out = []
    for i in range(64):
        bidx = proof_index_list[i * size_of_proof_index : (i + 1) * size_of_proof_index]
        bucket_id = bidx[0]
        row_id = int.from_bytes(bidx[1:], "little")
        out.append({"bucket_id": bucket_id, "row_id": row_id})

    print(len(out))

    used = set()
    deduped = []
    for m in out:
        if m["bucket_id"] in used and m["bucket_id"] != 255:
            break
        used.add(m["bucket_id"])
        deduped.append(m)

    want = set(range(64))
    fill = want - used
    for f in fill:
        deduped.append({"bucket_id": f, "row_id": 0})

    return deduped
