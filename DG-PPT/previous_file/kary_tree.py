import math
from AES import aes
from BT_DAG import dag_get_BT

# ---------------------------
# k-ary Tree 節點
# ---------------------------
class KaryTreeNode:
    """
    k-ary Tree 節點

    每個節點最多有 k 個子節點（而非 Binary Tree 的 2 個）
    """
    def __init__(self, val=None, k=4):
        self.val = val              # 節點值（leaf 為資料 ID，internal 為組合標識）
        self.children = []          # 子節點列表（最多 k 個）
        self.BT = []               # Binary Tree bitmap
        self.c = []                # Ciphertext
        self.is_leaf = False       # 是否為葉節點
        self.k = k                 # 分叉數


# ---------------------------
# k-ary OR 運算
# ---------------------------
def bt_or_operation_kary(bt_list):
    """
    對 k 個 BT 進行 OR 運算

    Args:
        bt_list: list of BT vectors

    Returns:
        OR 運算結果
    """
    if not bt_list:
        return []

    # 取最大長度
    max_len = max(len(bt) for bt in bt_list)
    result = [0] * max_len

    # 對每個 BT 做 OR
    for bt in bt_list:
        for i in range(len(bt)):
            result[i] |= bt[i]

    return result


# ---------------------------
# k-ary Bottom-up Merge（固定 k 版本）
# ---------------------------
def bottom_up_merge_kary(node_list, k=4):
    """
    k-ary tree 的 bottom-up merge

    每次合併 k 個節點成為一個 parent

    Args:
        node_list: 當前層的節點列表
        k: 分叉數（每個 parent 有 k 個 children）

    Returns:
        Root node
    """
    if len(node_list) == 1:
        return node_list[0]

    merge_node_list = []

    # 每次取 k 個節點合併
    for i in range(0, len(node_list), k):
        # 取出 k 個子節點（最後一組可能不足 k 個）
        children = node_list[i:i+k]

        # 建立 internal node
        child_vals = [str(child.val) for child in children]
        internal_node = KaryTreeNode(val="&".join(child_vals), k=k)
        internal_node.children = children
        internal_node.is_leaf = False

        # OR 運算所有子節點的 BT
        bt_list = [child.BT for child in children]
        internal_node.BT = bt_or_operation_kary(bt_list)

        # 生成 Ciphertext
        size = len(internal_node.BT)
        c = [0] * size
        for j in range(size):
            if internal_node.BT[j] == 0:
                c[j] = aes(0 + j)
            else:
                c[j] = aes(1 + j)

        internal_node.c = c
        merge_node_list.append(internal_node)

    # 遞迴合併
    return bottom_up_merge_kary(merge_node_list, k)


# ---------------------------
# Build k-ary Tree（固定 k 版本）
# ---------------------------
def buildKaryTree(data_num, max_bits, t, x, k=4):
    """
    建立固定 k-ary tree

    Args:
        data_num: 資料數量
        max_bits: 位元數
        t: ASHVE 參數
        x: Split 參數
        k: 分叉數（預設 4）

    Returns:
        Root node of k-ary tree
    """
    # 延遲導入以避免循環導入
    leaf_node_list = []

    # Step 1: 建立所有 leaf nodes
    for num in range(data_num):
        leaf_node = KaryTreeNode(val=num, k=k)
        leaf_node.is_leaf = True

        # 生成 BT（使用 DAG 編碼）
        leaf_node.BT = dag_get_BT(num, max_bits, x)

        # ASHVE.Enc 擴展
        for i in range(t):
            leaf_node.BT.append(i % 2)

        # 生成 Ciphertext
        size = len(leaf_node.BT)
        c = [0] * size
        for i in range(size):
            if leaf_node.BT[i] == 0:
                c[i] = aes(0 + i)
            else:
                c[i] = aes(1 + i)

        leaf_node.c = c
        leaf_node_list.append(leaf_node)

    # Step 2: Bottom-up merge 建立 k-ary tree
    root = bottom_up_merge_kary(leaf_node_list, k)

    return root


# ---------------------------
# Top-down 自適應 k-ary Tree（預先建立 Leaf 版本）
# ---------------------------
def split_nodes_by_count(node_list, ratios):
    """
    按節點數量比例分割

    Args:
        node_list: [node1, node2, ...] 節點列表
        ratios: [0.15, 0.70, 0.15] 分組比例

    Returns:
        list of groups: [group1, group2, group3]
    """
    total = len(node_list)
    groups = []
    start = 0

    for i, ratio in enumerate(ratios):
        if i == len(ratios) - 1:
            # 最後一組：剩下全部
            count = total - start
        else:
            # 按比例計算，至少 1 個
            count = max(1, int(total * ratio))

        end = min(start + count, total)
        if end > start:
            groups.append(node_list[start:end])
        start = end

    return groups


def get_unique_values_from_nodes(node_list):
    """從節點列表中提取唯一值"""
    return set(node.data_value for node in node_list)


def buildAdaptiveKaryTree(data_list, max_bits, t, x, ratios=[0.15, 0.70, 0.15]):
    """
    建立 Top-down 自適應 k-ary tree（預先建立 Leaf 版本）

    核心思想：
    1. 先建立所有 Leaf Nodes（完整的 BT 和 ciphertext）
    2. Top-down 分組合併這些 Leaf Nodes
    3. 終止條件：組內只有單一唯一值

    Args:
        data_list: 已排序的資料列表 [value1, value2, ...]
        max_bits: 位元數
        t: ASHVE 參數
        x: Split 參數
        ratios: 分組比例（預設 [0.15, 0.70, 0.15]）

    Returns:
        Root node
    """

    # ===== Step 1: 預先建立所有 Leaf Nodes =====
    leaf_nodes = []
    for idx, val in enumerate(data_list):
        leaf_node = KaryTreeNode(val=(idx, val), k=len(ratios))
        leaf_node.is_leaf = True
        leaf_node.record_id = idx
        leaf_node.data_value = val

        # 生成 BT
        leaf_node.BT = dag_get_BT(val, max_bits, x)

        # ASHVE.Enc 擴展
        for i in range(t):
            leaf_node.BT.append(i % 2)

        # 生成 Ciphertext
        size = len(leaf_node.BT)
        c = [0] * size
        for i in range(size):
            if leaf_node.BT[i] == 0:
                c[i] = aes(0 + i)
            else:
                c[i] = aes(1 + i)

        leaf_node.c = c
        leaf_nodes.append(leaf_node)

    # ===== Step 2: Top-down 分組合併 =====
    def build_recursive(node_list, depth=0):
        """
        遞歸分組合併

        Args:
            node_list: [node1, node2, ...] 當前組的節點
            depth: 當前深度

        Returns:
            KaryTreeNode
        """
        # 終止條件：只有單一唯一值
        unique_values = get_unique_values_from_nodes(node_list)

        if len(unique_values) == 1:
            # 所有節點的值都相同
            value = list(unique_values)[0]

            # 只有一個節點，直接返回
            if len(node_list) == 1:
                return node_list[0]

            # 多個節點，用 OR 合併成 Internal Node
            internal_node = KaryTreeNode(val=f"merge_{value}", k=len(node_list))
            internal_node.children = node_list
            internal_node.is_leaf = False

            # OR 運算
            bt_list = [node.BT for node in node_list]
            internal_node.BT = bt_or_operation_kary(bt_list)

            # 生成 Ciphertext
            size = len(internal_node.BT)
            c = [0] * size
            for i in range(size):
                if internal_node.BT[i] == 0:
                    c[i] = aes(0 + i)
                else:
                    c[i] = aes(1 + i)

            internal_node.c = c
            return internal_node

        # 按節點數量比例分割
        groups = split_nodes_by_count(node_list, ratios)

        # 遞歸建立子樹
        children = []
        for group_nodes in groups:
            if group_nodes:  # 非空組
                child = build_recursive(group_nodes, depth + 1)
                children.append(child)

        # 建立 Internal Node
        internal_node = KaryTreeNode(val=f"internal_d{depth}", k=len(children))
        internal_node.children = children
        internal_node.is_leaf = False

        # OR 運算所有子節點的 BT
        bt_list = [child.BT for child in children]
        internal_node.BT = bt_or_operation_kary(bt_list)

        # 生成 Ciphertext
        size = len(internal_node.BT)
        c = [0] * size
        for i in range(size):
            if internal_node.BT[i] == 0:
                c[i] = aes(0 + i)
            else:
                c[i] = aes(1 + i)

        internal_node.c = c
        return internal_node

    # 從所有 leaf nodes 開始遞歸
    root = build_recursive(leaf_nodes, depth=0)

    return root


# ---------------------------
# 統計函式
# ---------------------------
def count_total_nodes(node):
    """計算樹的總節點數"""
    if node is None:
        return 0

    count = 1
    if hasattr(node, 'children'):
        for child in node.children:
            count += count_total_nodes(child)

    return count


def get_tree_height(node):
    """計算樹的高度"""
    if node is None:
        return 0

    if node.is_leaf:
        return 1

    max_height = 0
    for child in node.children:
        max_height = max(max_height, get_tree_height(child))

    return max_height + 1


def count_internal_nodes(node):
    """計算 internal nodes 數量"""
    if node is None:
        return 0

    if node.is_leaf:
        return 0

    count = 1  # 當前 internal node
    for child in node.children:
        count += count_internal_nodes(child)

    return count

