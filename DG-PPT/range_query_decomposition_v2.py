import math

def binary(num, MAX):
    # 直接利用 Python 格式化產生固定長度的二進位字串
    return format(num, '0{}b'.format(MAX))

class RangeTreeNode:
    def __init__(self, x, depth):
        self.range = x
        self.code = ""
        self.depth = depth
        self.parent = None
        self.left = None
        self.right = None

    def get_leaf_nodes(self, node):
        if not node:
            return []
        if not node.left and not node.right:
            return [node]
        leaf_nodes = self.get_leaf_nodes(node.left) + self.get_leaf_nodes(node.right)
        return leaf_nodes

def build_tree(depth, max_tree_depth, min, max):
    node = RangeTreeNode((min, max), depth)
    node.code = binary(min,max_tree_depth)[0:depth]+"*" * (max_tree_depth-depth)
    if depth < max_tree_depth:
        mid = math.floor((min + max) / 2)
        if max - min != 1:
            node.left = build_tree(depth+1, max_tree_depth, min, mid)
            node.right = build_tree(depth+1, max_tree_depth, mid+1, max)

        else:
            node.left = build_tree(depth+1, max_tree_depth, min, min)
            node.right = build_tree(depth + 1, max_tree_depth, max, max)
        node.left.parent = node
        node.right.parent = node

    return node


def range_in_query(r,q):
    if r is None or q is None:
        return False
    else:
        return (q[0] <= r[0]) and (r[1] <= q[1])

def check_parent(l, q, child_node):
    query = list(q)
    if range_in_query(l.range,q):
        if l.parent is None:
            return l.code, None
        else:
            return check_parent(l.parent, q, l)
    else:
        token = child_node.code
        query[0] = child_node.range[1]+1
        if query[0]>query[1]:
            return token, None
        else:
            return token, tuple(query)



import functools

@functools.lru_cache(maxsize=None)
def gettoken(q, m):
    token_list = []
    tree = build_tree(0, m, 0, 2 ** m - 1)
    leaf_nodes = tree.get_leaf_nodes(tree)

    for leaf in leaf_nodes:
        if range_in_query(leaf.range,q):
            token, update_q = check_parent(leaf, q, None)
            token_list.append(token)
            q = update_q

    return token_list



def BT_generate(binary_string,m):
    # Initialize a (2(m+1) − 1)-bit binary string array
    # BTi = [1, 0, · · · , 0];
    BT = [1]
    for _ in range((2 ** (m+1)) - 2):
        BT.append(0)

    # //Map di to a (2(m+1) − 1)-bit binary string array
    count = 1
    for o in binary_string:
        if o == "0":
            count = 2 * count
            BT[count - 1] = 1
        else:
            count = 2 * count + 1
            BT[count - 1] = 1
    return BT

def get_BT(num, bits, x):
    # Convert num into BT
    # BT_size = x * (2 ** (s + 1) - 1)
    s = bits // x  # s bit binary
    binary_num = binary(num, bits)
    BT = []

    for i in range(x):
        sub_binary = binary_num[s * i:s * (i + 1)]
        BT = BT + BT_generate(sub_binary, s)
    return BT


def BTQ_generate(binary_string,m):
    # Initialize a (2(m+1) − 1)-bit binary string array
    # BTi = [1, 0, · · · , 0];
    BTQ = ['1']
    for _ in range((2 ** (m+1)) - 2):
        BTQ.append("*")

    # //Map di to a (2(m+1) − 1)-bit binary string array
    count = 1
    for o in binary_string:
        if o != "*":
            if o == "0":
                count = 2 * count
                BTQ[count - 1] = "1"
            elif o == "1":
                count = 2 * count + 1
                BTQ[count - 1] = "1"
    return BTQ


def get_BTQ_list(q, bits, x):
    BTQ_list = []
    tokens = gettoken(q, bits)
    s = bits//x  # s bit binary
    for t in tokens:
        BTQ = []
        for i in range(x):
            sub_token = t[s*i:s*(i+1)]
            BTQ = BTQ + BTQ_generate(sub_token, s)
        BTQ_list.append(BTQ)
    return BTQ_list

'''
bits = 4


tokens = gettoken((0,2), bits)

BTQ_list = []
for t in tokens:
    BTQ_list.append(BTQ_generate(t, bits))

print(BTQ_list)

'''





