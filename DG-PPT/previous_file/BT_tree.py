import math
from AES import aes
from range_query_decomposition_v2 import get_BT
# ---------------------------
# Tree 節點與二元樹建立
# ---------------------------
class TreeNode:
    def __init__(self, x):
        self.val = x
        self.left = None
        self.right = None


def binary(num, MAX):
    # 直接利用 Python 格式化產生固定長度的二進位字串
    return format(num, '0{}b'.format(MAX))

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

def bt_or_operation(bt1, bt2):
    return [bt1[i] or bt2[i] for i in range(len(bt1))]

def bt_xor_operation(bt1, bt2):
    return [bt1[i] ^ bt2[i] for i in range(len(bt1))]


def bottom_up_merge(node_list):
    if len(node_list) == 1:
        return node_list[0]
    else:
        merge_node_list = []
        for i in range(len(node_list)//2):
            internal_node = TreeNode(str(node_list[2*i].val)+"&"+str(node_list[2*i + 1].val))
            internal_node.left = node_list[2*i]
            internal_node.right = node_list[2*i + 1]
            # NOTE: EPRQ+ Algorithm 4 specifies BT = XOR of children,
            # but with a different encryption formula for non-leaf nodes:
            # c_ij = F(msk, BT[j]||j) XOR F(msk, id_l) XOR F(msk, id_r)
            # Since our AES simulation does not support the id_l/id_r parameters,
            # we use OR here so that non-leaf nodes can still match when any
            # child node falls in the query range (conservative but functional).
            internal_node.BT = bt_or_operation(internal_node.left.BT, internal_node.right.BT)
            # Ciphertext c（使用 aes 模擬加密運算）
            size = len(internal_node.BT)
            c = [0] * size
            for i in range(size):
                if internal_node.BT[i] == 0:
                    c[i] = aes(0 + i)
                else:
                    c[i] = aes(1 + i)

            internal_node.c = c
            merge_node_list.append(internal_node)
        return bottom_up_merge(merge_node_list)


def buildTree(data_num, max_bits, t, x):
    leaf_node_list = []

    for num in range(data_num):
        leaf_node = TreeNode(num)
        leaf_node.BT = get_BT(num, max_bits, x)

        # Convert to a function
        # ASHVE.Enc extends ⃗x to get ⃗x′ = (x1, · · · , xm,H(1),H(2), · · · ,H(t))
        for i in range(0, t):
            leaf_node.BT.append(i % 2)

        # Ciphertext c（使用 aes 模擬加密運算）
        size = len(leaf_node.BT)
        c = [0] * size
        for i in range(size):
            if leaf_node.BT[i] == 0:
                c[i] = aes(0 + i)
            else:
                c[i] = aes(1 + i)

        leaf_node.c = c
        leaf_node_list.append(leaf_node)

    node = bottom_up_merge(leaf_node_list)
    return node


if __name__ == "__main__":
    root = buildTree(8, 4, 2, 2)
    print("Root BT:", root.BT)
    print("Root Ciphertext:", root.c)