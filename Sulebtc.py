import hashlib
import base58
import ecdsa


def compress_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    compressed_vk = vk.to_string("compressed").hex()
    return compressed_vk


def generate_bitcoin_address(private_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    compressed_public_key = vk.to_string("compressed").hex()
    sha256_hash = hashlib.sha256(bytes.fromhex(compressed_public_key)).digest()
    ripemd160_hash = hashlib.new("ripemd160")
    ripemd160_hash.update(sha256_hash)
    hashed_public_key = ripemd160_hash.digest()
    versioned_hashed_public_key = b"\x00" + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(versioned_hashed_public_key).digest()).dig>
    binary_address = versioned_hashed_public_key + checksum
    bitcoin_address = base58.b58encode(binary_address).decode()
    return bitcoin_address


def generate_private_key_range(start, end, given_address):
    for i in range(start, end + 1):
        private_key = hex(i)[2:].zfill(64)
        compressed_public_key = compress_public_key(private_key)
        address = generate_bitcoin_address(private_key)

        print(f"Private Key: {private_key}")
        print(f"Compressed Public Key: {compressed_public_key}")
        print(f"Address: {address}")
        print()

        if address == given_address:
            print("Private Key Found:")
            print(private_key)
            return


given_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
start_range = 0x20000000009999999
end_range = 0x3FFFFFFFFFFFFFFFF

generate_private_key_range(start_range, end_range, given_address)
