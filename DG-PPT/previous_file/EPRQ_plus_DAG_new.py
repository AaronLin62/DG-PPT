import sys
from pathlib import Path

# 添加父目錄到 path 以便導入
sys.path.insert(0, str(Path(__file__).parent.parent))

from AES import aes
from range_query_decomposition_v2 import binary
from dag_range_decomposition import dag_get_BTQ_list
from kary_tree import buildAdaptiveKaryTree, count_total_nodes, get_tree_height, count_internal_nodes

# ==========================================
# Token 生成函式
# ==========================================
def token_gen_set_s(q, MAX, key_trap, t, x):
    import random

    # 這裡現在直接拿到 S 的索引了！
    BTQ_indices_list = dag_get_BTQ_list(q, MAX, x)
    T_list = []
    
    # DAG 總位元數
    s = MAX // x
    total_dag_length = x * ((s + 1) * (s + 2) // 2)

    for S_indices in BTQ_indices_list:
        num_encryt = 0
        S = []

        # 直接讀取有 '1' 的位置，不需掃描
        for idx in S_indices:
            num_encryt += aes(1 + idx)
            S.append(idx)

        # 隨機選擇 t 個位置構建 S2
        loc = random.randint(0, t - 1)
        last = loc % 2
        S.append(loc + total_dag_length)

        # 計算 d0 和 d1
        num_encryt += aes(last + loc + total_dag_length)
        d0 = num_encryt + key_trap
        d1 = aes(0, key_trap)

        T_list.append((d0, d1, S))

    return T_list


# ==========================================
# Query 函式
# ==========================================
def dag_query_eprq(ciphertext, tokens):
    """
    基本查詢函式：測試單筆 ciphertext 是否匹配 tokens

    Args:
        ciphertext: 加密的 BT（list of integers）
        tokens: 加密的 token list [(d0, d1, S), ...]

    Returns:
        True if matched, False otherwise
    """
    # 對每個 token 進行測試
    for token in tokens:
        num_encryt = 0
        (d0, d1, S) = token

        # 從 ciphertext 中提取 S 位置的值並累加
        for i in range(len(S)):
            n = S[i]
            if n < len(ciphertext):
                num_encryt += ciphertext[n]

        # 計算解密 key
        key_not = d0 - num_encryt

        # 解密並檢查是否匹配
        key_0 = aes(0, key_not)
        if key_0 == d1:
            return True  # 匹配成功

    return False  # 所有 token 都不匹配


# ==========================================
# k-ary Tree Query 函式
# ==========================================
def kary_tree_query(node, query_tokens, results, stats=None):
    """
    k-ary tree 遍歷查詢

    Args:
        node: k-ary tree 節點
        query_tokens: list of encrypted tokens [(d0, d1, S), ...]
        results: 結果集合（會被修改）
        stats: 統計資訊
    """
    if node is None:
        return

    if stats is None:
        stats = {'visited_nodes': 0, 'pruned_nodes': 0}

    stats['visited_nodes'] += 1

    # 測試當前節點的 ciphertext
    if dag_query_eprq(node.c, query_tokens):
        # 匹配成功
        if node.is_leaf:
            # 葉節點：加入結果
            results.add(node.val)
        else:
            # Internal node：遍歷所有子節點
            for child in node.children:
                kary_tree_query(child, query_tokens, results, stats)
    else:
        # 不匹配：剪枝（不訪問子節點）
        if not node.is_leaf:
            # 計算被剪枝的子樹節點數
            pruned = count_subtree_nodes(node) - 1
            stats['pruned_nodes'] += pruned


def count_subtree_nodes(node):
    """計算子樹的總節點數"""
    if node is None:
        return 0
    if node.is_leaf:
        return 1
    count = 1
    for child in node.children:
        count += count_subtree_nodes(child)
    return count

# ==========================================
# 測試資料集生成
# ==========================================
def generate_test_datasets(size=64, max_value=100):
    """
    生成三種測試資料集

    Returns:
        dict: {
            'continuous': 連續資料,
            'sparse': 非連續資料,
            'repeated': 重複資料
        }
    """
    import random
    random.seed(42)  # 固定隨機種子以便重現

    # 1. 連續性資料
    continuous = list(range(size))

    # 2. 非連續性資料（有 gap）
    # 從 0~max_value 中隨機選 size 個，排序
    sparse = sorted(random.sample(range(max_value), size))

    # 3. 重複性資料（密度不均）
    # 某些值重複多次，某些值只出現一次
    repeated = []
    value = 0
    while len(repeated) < size:
        # 隨機決定這個值重複幾次（1-5 次）
        count = random.choices([1, 2, 3, 4, 5], weights=[10, 30, 30, 20, 10])[0]
        count = min(count, size - len(repeated))
        repeated.extend([value] * count)
        value += 1

    return {
        'continuous': continuous,
        'sparse': sparse,
        'repeated': repeated
    }


if __name__ == "__main__":
    # 測試參數
    MAX = 6  # 支援到 64 (2^6)，可整除 x=2
    t = 2
    x = 2
    ratios = [0.15, 0.70, 0.15]
    key_trap = 20

    # 生成測試資料集
    datasets = generate_test_datasets(size=64, max_value=64)

    for dataset_name, data_list in datasets.items():
        print(f"\n{'='*80}")
        print(f"Dataset: {dataset_name.upper()}")
        print(f"{'='*80}")
        print(f"Data sample: {data_list[:10]}... (total: {len(data_list)})")
        print(f"Data range: [{min(data_list)}, {max(data_list)}]")
        print(f"Ratios: {ratios}")

        root = buildAdaptiveKaryTree(data_list, MAX, t, x, ratios)

        # 統計
        total_nodes = count_total_nodes(root)
        tree_height = get_tree_height(root)
        internal_nodes = count_internal_nodes(root)

        print(f"\nTree Statistics:")
        print(f"  Total nodes:     {total_nodes}")
        print(f"  Leaf nodes:      {len(data_list)}")
        print(f"  Internal nodes:  {internal_nodes}")
        print(f"  Tree height:     {tree_height} layers")

        # 測試查詢
        # 選擇資料範圍內的查詢
        min_val = min(data_list)
        max_val = max(data_list)
        query_start = min_val + (max_val - min_val) // 4
        query_end = min_val + (max_val - min_val) // 2
        query = (query_start, query_end)

        print(f"\n[Query Test: {query}]")
        print("-" * 40)

        # 期望結果（值列表）
        expected = sorted([v for v in data_list if query[0] <= v <= query[1]])
        print(f"Expected: {len(expected)} results")

        # 生成 token
        query_tokens = token_gen_set_s(query, MAX, key_trap, t, x)

        # 執行查詢（results 現在包含 (record_id, value) tuples）
        results = set()
        stats = {'visited_nodes': 0, 'pruned_nodes': 0}
        kary_tree_query(root, query_tokens, results, stats)

        # 提取查詢結果的值（保持重複）
        result_values = sorted([val for (_, val) in results])

        print(f"Found:    {len(result_values)} results")
        print(f"Expected values: {expected}")
        print(f"Query results: {result_values}")
        print(f"\nStatistics:")
        print(f"  Visited nodes: {stats['visited_nodes']}/{total_nodes}")
        print(f"  Pruned nodes:  {stats['pruned_nodes']}")
        print(f"  Efficiency:    {(1 - stats['visited_nodes'] / total_nodes) * 100:.1f}%")

        # 驗證結果
        if result_values == expected:
            print("\n[PASS] Query successful!")
        else:
            print("\n[FAIL] Query failed!")
            print(f"  Expected: {expected[:5]}... (total {len(expected)})")
            print(f"  Got:      {result_values[:5]}... (total {len(result_values)})")
