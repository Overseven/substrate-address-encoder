import hashlib
import base58


def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


# return first two bytes from hash of 'SS58PRE' + address prefix + address
def blake2(data):
    hash = hashlib.blake2b(digest_size=64)
    hash.update(bytes.fromhex('53533538505245') + data)
    return hash.digest()[:2]


# encode hex public key
def encode_public_key(key, prefix):
    if prefix < 64:
        encoded = bytes([prefix])
    else:
        encoded = bytes([(prefix & 0b0000000011111100) >> 2 | 0b01000000, prefix >> 8 | (prefix & 0b0000000000000011) << 6])
    encoded += key
    checksum = blake2(encoded)
    encoded += checksum
    encoded_str = base58.b58encode(encoded).decode("utf-8")
    return encoded, encoded_str


# main function to encode hex and base58 addresses with new prefix
def reencode_address(address, prefix):
    try:
        add_bytes = base58.b58decode(address)
    except:
        try:
            encoded, encoded_str = encode_public_key(bytes.fromhex(remove_prefix(address, '0x')), prefix)
            print("Encoded hex: ", encoded.hex())
            print("Encoded base58: ", encoded_str)
            print("")
            return encoded_str
        except:
            print("reencode_address error: incorrect address:", address)
            return

    print("Input address: ", address)
    print("Input address hex: ", add_bytes.hex())
    checksum = blake2(add_bytes[:-2])
    print("Checksum: ", checksum.hex())
    if add_bytes[-2:] != checksum:
        print("Incorrect checksum: ", checksum.hex(), " vs ", add_bytes[-2:].hex())
        return

    if add_bytes[0] < 64:
        decoded = add_bytes[1:-2]
    else:
        decoded = add_bytes[2:-2]

    encoded, encoded_str = encode_public_key(decoded, prefix)

    print("Encoded hex: ", encoded.hex())
    print("Encoded base58: ", encoded_str)
    print("")
    return encoded_str


# examples of usage
reencode_address('5ERTCNpBJe6tKGBA1ZWXi6CkFRFdHX4mogf2rFQhiVRUtXgT', 67)  # Genshiro: cZh5bjGbjxm7QQE3FFA8XiYhBMbMsYP2ZFyRh6u27nnJtqrfa
reencode_address('cZh5bjGbjxm7QQE3FFA8XiYhBMbMsYP2ZFyRh6u27nnJtqrfa', 2)  # Kusama: Ew4rhA3w17p4uzbnGKac3ZkQ1Xs6BsxG4VnEugfCHdydYf4
reencode_address('13MkLi5FARNMkoBfyCZXrF2u73FGypcutBPX1YQ4GaT14vbm', 67)  # Genshiro: cZh5bjGbjxm7QQE3FFA8XiYhBMbMsYP2ZFyRh6u27nnJtqrfa
reencode_address('cZh5bjGbjxm7QQE3FFA8XiYhBMbMsYP2ZFyRh6u27nnJtqrfa', 0)  # Polkadot: 13MkLi5FARNMkoBfyCZXrF2u73FGypcutBPX1YQ4GaT14vbm
# public key
reencode_address('0x684b450e6973bb0ccee706b51c4ee4e4e29488d3c067c8586ca4b60457dd3e57', 67)  # Genshiro: cZh5bjGbjxm7QQE3FFA8XiYhBMbMsYP2ZFyRh6u27nnJtqrfa
