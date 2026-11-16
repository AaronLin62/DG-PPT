import random
import math
from AES import aes
from range_query_decomposition_v2 import get_BTQ_list
from BT_tree import buildTree


# ------------------------------
# TokenGen
# trapdoor_F 函式（回傳更新後的 S 及 d0, d1）
# ------------------------------

def TokenGen(q, MAX, key_trap, t, x):

    BTQ_list = get_BTQ_list(q, MAX, x)

    T_list = []

    for BTQ in BTQ_list:
        num_encryt = 0
        S = []

        # Phase 1: accumulate S1 = positions where BTQ[i] == '1'
        for i in range(len(BTQ)):
            if BTQ[i] == '1':
                num_encryt += aes(1 + i)
                S.append(i)

        # Phase 2: add one random trap position S2 to make |S1 ∪ S2| even
        # (ASHVE.KeyGen: randomly choose from [1,t] to construct S2)
        loc = random.randint(0, t - 1)
        last = loc % 2
        S.append(loc + len(BTQ))

        # d0 = d'0 XOR d''0,  d1 = Sym.Enc(K, 0)
        num_encryt += aes(last + loc + len(BTQ))
        d0 = num_encryt + key_trap
        d1 = aes(0, key_trap)
        T_list.append((d0, d1, S))

    return T_list



# ------------------------------
# query_F 函式：根據 trapdoor 與 index_p 計算結果
# ------------------------------

def query(t_list, ciphertext):
    res = "noc"
    for token in t_list:
        num_encryt = 0
        (d0, d1, S) = token
        for i in range(len(S)):
            n = S[i]
            num_encryt += ciphertext[n]
        key_not = d0 - num_encryt
        key_0 = aes(0, key_not)
        if key_0 == d1:
            res = "c"
            break

    return res

def preOrderTraversal(root, MAX,t_list, m1):
    if root is None:
        return
    # print(root.val)  # Debug output - commented out for benchmarking
    res = query(t_list, root.c)
    # print(res)  # Debug output - commented out for benchmarking
    if res == "c":
        preOrderTraversal(root.left, MAX,t_list, m1)
        preOrderTraversal(root.right, MAX, t_list, m1)
# ------------------------------
# 主程式
# ------------------------------

def main():
    MAX = 4            # 字串長度
    DB_num = 8 # di 0~14
    t = 2 # Parameter t from ASHVE.KeyGen
    x = 2  # Split token and cipher
    q = (3,6) # Query range 查詢範圍
    random.seed()  # 以目前時間作為種子

    root = buildTree(DB_num, MAX, t, x)

    key_trap = 20
    token_list = TokenGen(q, MAX, key_trap, t, x)
    preOrderTraversal(root, MAX, token_list, t)


if __name__ == "__main__":
    main()

