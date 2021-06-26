import hashlib

BUF_SIZE = 65536
sha256_hash = hashlib.sha256()

def gen_hash_from_file(filepath):
    with open(filepath, "rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256_hash.update(data)
    print(f"sha256: {sha256_hash.hexdigest()}")
