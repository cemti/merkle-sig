from merkle_signature import sign_message, recover_root_public_key
from lamport import LamportSignature

n_leaves = int(input('Nr. de frunze: '))
pair_index = int(input('Indice din cheie publica: '))
message = input('Mesajul: ')

root_public_key, signature = sign_message(message, n_leaves, pair_index)

assert LamportSignature.verify(message, signature['signed_message'], signature['public_key'])

recovered_root_public_key = recover_root_public_key(signature, n_leaves, pair_index)
assert recovered_root_public_key == root_public_key