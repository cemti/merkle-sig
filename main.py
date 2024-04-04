from lamport import LamportSignature
from merkle import MerkleTree

n_leaves = int(input('Nr. de frunze: '))
pair_index = int(input('Indice din cheie publica: '))
message = input('Mesajul: ')

def verification(root_public_key, message, signature):
    if not LamportSignature.verify(message, signature['signed_message'], signature['public_key']):
        return False
    
    tree = MerkleTree(n_leaves)
    tree.add_node(signature['public_key'], (0, pair_index))
    
    auth_path = tree.get_authentification_path(pair_index)

    for path_hash, pos in zip(signature['path_hashes'], auth_path):
        tree.add_node(path_hash, pos, True)
            
    tree.generate_tree()
    return tree.get_root() == root_public_key
        
def generate(message):
    key_pairs = [LamportSignature() for _ in range(n_leaves)]
    public_keys = [pair.get_key(True) for pair in key_pairs]

    tree = MerkleTree(n_leaves)
    
    for i, public_key in enumerate(public_keys):
        tree.add_node(public_key, (0, i))

    tree.generate_tree()
    
    signature = {
        'signed_message': key_pairs[pair_index].sign(message),
        'public_key': public_keys[pair_index], 
        'path_hashes': tree.get_authentification_path_hashes(pair_index)
    }
    
    return tree.get_root(), signature

root_public_key, signature = generate(message)
print('Cheia publica (radacina):', root_public_key.hex())
assert verification(root_public_key, message, signature)