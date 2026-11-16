import math
import sys
from pathlib import Path

from range_query_decomposition_v2 import binary, gettoken

# 添加父目錄到 path 以便導入
sys.path.insert(0, str(Path(__file__).parent.parent))

# ==========================================
# DAG 基礎函數
# ==========================================

def level_pos_to_dag_index(level, pos):
    """
    將 (level, position) 轉換為 DAG 索引

    DAG 結構中，節點按層級排列：
    - Level 0: 1 個節點 (index 0)
    - Level 1: 2 個節點 (index 1-2)
    - Level 2: 3 個節點 (index 3-5)
    - Level k: k+1 個節點

    Args:
        level: 節點所在層級（0 是 root）
        pos: 節點在該層的位置（0 到 level）

    Returns:
        DAG 中的索引位置

    Example:
        >>> level_pos_to_dag_index(0, 0)  # root
        0
        >>> level_pos_to_dag_index(2, 1)  # level 2, position 1
        4
    """
    return level * (level + 1) // 2 + pos


def dag_size(m):
    """
    計算 m 層 DAG 的節點總數

    Args:
        m: DAG 的深度（bits）

    Returns:
        節點總數

    Example:
        >>> dag_size(4)
        15
    """
    return (m + 1) * (m + 2) // 2


# ==========================================
# DAG BTQ 生成（用於查詢 token）
# ==========================================

def dag_BTQ_generate(binary_string, m):
    dag_size_val = (m + 1) * (m + 2) // 2
    DAG_BTQ = ['*'] * dag_size_val
    
    current_level = 0
    current_pos = 0
    DAG_BTQ[0] = '1'
    
    for bit in binary_string:
        if bit != '*':
            current_level += 1
            if bit == "1":
                current_pos += 1
            # Inline math to avoid function call overhead
            DAG_BTQ[current_level * (current_level + 1) // 2 + current_pos] = '1'
            
    return DAG_BTQ


# ==========================================
# DAG Range Decomposition
# ==========================================

def dag_range_decomposition(q, bits, debug=False):
    """
    純演算法版本的 DAG range decomposition

    **不建立任何節點對象**，純粹用遞迴演算法計算

    核心思想：
    1. 從 root 開始，path = ""，depth = 0
    2. 計算當前 prefix 代表的值範圍 [range_min, range_max]
    3. 判斷三種情況：
       - 完全覆蓋：start <= range_min AND range_max <= end
         → 加入 * token (例如 "010*")
       - 無交集：range_max < start OR range_min > end
         → 剪枝，停止遞迴
       - 部分重疊：其他情況
         → 遞迴處理左子樹 (prefix + "0") 和右子樹 (prefix + "1")

    Args:
        q: 範圍查詢 (start, end)
        bits: 位元數
        debug: 是否輸出詳細追蹤資訊

    Returns:
        list of token patterns (binary strings with *)
    """
    start, end = q
    tokens = []
    call_count = [0]  # 使用 list 來在內部函數中修改

    if debug:
        print(f"\n{'='*70}")
        print(f"DAG Range Decomposition Trace")
        print(f"{'='*70}")
        print(f"Query: [{start}, {end}], bits={bits}")
        print(f"{'='*70}\n")

    def find_covering_nodes(prefix="", depth=0):
        """
        遞迴尋找覆蓋 [start, end] 的最小節點集合

        Args:
            prefix: 當前路徑（二進位字串）
            depth: 當前深度
        """
        call_count[0] += 1
        indent = "  " * depth

        if debug:
            print(f"{indent}[Call #{call_count[0]}] depth={depth}, prefix='{prefix or '(root)'}'")

        # 到達葉節點
        if depth == bits:
            value = int(prefix, 2)
            if debug:
                print(f"{indent}  -> Leaf node: value={value}")
            if start <= value <= end:
                if debug:
                    print(f"{indent}  [MATCH] In range! Add token: '{prefix}'")
                tokens.append(prefix)
            else:
                if debug:
                    print(f"{indent}  [SKIP] Out of range")
            return

        # 計算當前節點代表的範圍
        remaining_bits = bits - depth
        range_min = int(prefix + "0" * remaining_bits, 2) if remaining_bits > 0 else int(prefix, 2)
        range_max = int(prefix + "1" * remaining_bits, 2) if remaining_bits > 0 else int(prefix, 2)

        if debug:
            print(f"{indent}  -> Node range: [{range_min}, {range_max}]")
            print(f"{indent}  -> Query range: [{start}, {end}]")

        # 情況 1: 完全覆蓋 - 當前節點的整個子樹都在查詢範圍內
        if start <= range_min and range_max <= end:
            token = prefix + "*" * remaining_bits
            if debug:
                print(f"{indent}  [FULL COVERAGE] Add wildcard token: '{token}'")
            tokens.append(token)
            return

        # 情況 2: 無交集 - 當前節點完全在範圍外
        if range_max < start or range_min > end:
            if debug:
                print(f"{indent}  [NO INTERSECTION] Prune branch")
            return

        # 情況 3: 部分重疊 - 需要遞迴處理左右子樹
        if debug:
            print(f"{indent}  [PARTIAL OVERLAP] Recurse to children")
            print(f"{indent}  +-- Going LEFT (prefix + '0')")
        find_covering_nodes(prefix + "0", depth + 1)  # 左子樹

        if debug:
            print(f"{indent}  +-- Going RIGHT (prefix + '1')")
        find_covering_nodes(prefix + "1", depth + 1)  # 右子樹

    # 從 root 開始（空字串，深度 0）
    find_covering_nodes()

    if debug:
        print(f"\n{'='*70}")
        print(f"Result: {tokens}")
        print(f"Total recursive calls: {call_count[0]}")
        print(f"{'='*70}\n")

    return tokens


# ==========================================
# DAG BTQ List 生成
# ==========================================

def dag_get_BTQ_list(q, bits, x):
    """
    優化版：直接回傳有 '1' 的 Indices，跳過字串陣列生成
    """
    BTQ_indices_list = []
    tokens = gettoken(q, bits)
    s = bits // x

    for t in tokens:
        S_indices = []
        offset = 0
        for i in range(x):
            sub_token = t[s * i:s * (i + 1)]
            
            # dag_BTQ_generate_indices logic directly here
            current_level = 0
            current_pos = 0
            S_indices.append(offset + 0)
            
            for bit in sub_token:
                if bit != '*':
                    current_level += 1
                    if bit == "1":
                        current_pos += 1
                    S_indices.append(offset + current_level * (current_level + 1) // 2 + current_pos)
            offset += (s + 1) * (s + 2) // 2
            
        BTQ_indices_list.append(S_indices)

    return BTQ_indices_list


if __name__ == "__main__":
    print("=" * 70)
    print("DAG Range Query Decomposition - Test")
    print("=" * 70)

    # 測試 1: 基本功能測試
    print("\n[Test 1: Basic Functionality]")
    test_queries = [
        ((3, 6), 4),
        ((5, 11), 4),
        ((0, 15), 4),
        ((10, 20), 5),
    ]

    for query, bits in test_queries:
        print(f"\nQuery: {query}, bits={bits}")
        print("-" * 40)
        tokens = dag_range_decomposition(query, bits)
        print(f"Tokens: {tokens}")

    # 測試 2: DAG BTQ 生成
    print("\n[Test 2: DAG BTQ Generation]")
    btq = dag_BTQ_generate("01", 2)
    print(f"dag_BTQ_generate('01', 2) = {btq}")
    print(f"Length: {len(btq)} (expected: {dag_size(2)})")

    # 測試 3: DAG BTQ List
    print("\n[Test 3: DAG BTQ List]")
    btq_list = dag_get_BTQ_list((3, 6), 4, 2)
    print(f"Query: (3, 6), bits=4, x=2")
    print(f"BTQ count: {len(btq_list)}")
    for i, btq in enumerate(btq_list):
        print(f"  BTQ {i}: length={len(btq)}, content={''.join(btq[:20])}...")

    # 測試 4: 與原始 gettoken 比較
    print("\n[Test 4: Compare with Original gettoken]")
    from range_query_decomposition_v2 import gettoken

    for query, bits in [((3, 6), 4), ((5, 11), 4)]:
        tokens_original = gettoken(query, bits)
        tokens_dag = dag_range_decomposition(query, bits)

        print(f"\nQuery: {query}, bits={bits}")
        print(f"Original: {tokens_original}")
        print(f"DAG:      {tokens_dag}")

        if set(tokens_original) == set(tokens_dag):
            print("[PASS] Results match!")
        else:
            print("[FAIL] Results differ!")


    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)
