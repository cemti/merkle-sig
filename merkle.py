import hashlib

class MerkleTree:
    def __init__(self, n_leaves):
        if (n_leaves & (n_leaves - 1)) != 0:
            raise ValueError('Nr. de frunze trebuie sa fie o putere a lui 2.')
        
        self.tree = {}
        self.n_leaves = n_leaves
        self.n_levels = (n_leaves - 1).bit_count() + 1

    def add_node(self, data, position, hashed=False):
        self.tree[position] = None if data is None else data if hashed else self.hash(data)

    def generate_tree(self):
        for level in range(1, self.n_levels):
            for pos in range(int(self.n_leaves >> level)):
                left_pos = (level - 1, 2 * pos)
                right_pos = (level - 1, 2 * pos + 1)
                
                if left_pos in self.tree and right_pos in self.tree:
                    self.tree[(level, pos)] = self.hash(self.tree[left_pos] + self.tree[right_pos])

    def get_root(self):
        return self.tree[(self.n_levels - 1, 0)]

    def get_authentification_path_hashes(self, index):
        return [self.tree[i] for i in self.get_authentification_path(index)]

    def get_authentification_path(self, index):
        levels = ((i, index >> i) for i in range(self.n_levels - 1))
        return [(x, y + (1 if y % 2 == 0 else -1)) for x, y in levels]    

    @staticmethod
    def hash(data):
        if type(data) is not bytearray:
            data = data.encode('utf-8')

        return bytearray(hashlib.sha256(data).digest())