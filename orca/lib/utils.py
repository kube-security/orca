import hashlib
def calculate_sha256(file_path):
    try:
        # Open the file in binary mode
        with open(file_path, 'rb') as file:
            # Initialize the SHA-256 hash object
            sha256_hash = hashlib.sha256()
            # Read the file in chunks to efficiently handle large files
            for chunk in iter(lambda: file.read(4096), b''):
                # Update the hash object with the current chunk
                sha256_hash.update(chunk)
            # Get the hexadecimal representation of the digest (hash value)
            hash_value = sha256_hash.digest()
            return hash_value
    except FileNotFoundError:
        return None

def map_container_id(container_id: str):
    return container_id.replace(":", "twodots").replace("/", "slash")
