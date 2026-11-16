"""
dynamic_gppt.py
===============
Dynamic G-PPT(DG-PPT)實作

在學長的靜態 G-PPT 基礎上，加入：
  1. 分層索引(Layered Index):用 binary counter 邏輯管理多個靜態 G-PPT
  2. Insert:插入新資料，找到第一個空層放入,沿途合併已有的層
  3. Delete:Lazy Deletion,標記刪除並在合併時清除
  4. 多層查詢：同時查詢所有非空的層，合併結果

加密設計(和學長相容):
  c[i] = aes(bt[i] + i)              ← 密文不含 layer_key
  d0   = sum(aes(1+idx)) + layer_key ← token 含 layer_key
  d1   = aes(0, layer_key)           ← token 含 layer_key

Forward Privacy:
  不同層有不同的 layer_key(由 PPRF 派生)
  舊 token 的 d1 = aes(0, old_key)
  新層的   d1 = aes(0, new_key)
  old_key ≠ new_key → 舊 token 無法匹配新層密文
"""

import sys
import random
import hashlib
from pathlib import Path
from typing import List, Set, Dict, Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent))
from pprf import SimplePPRF


# ==========================================
# 模擬學長的加密函式
# 實際使用時替換：from AES import aes
# ==========================================

def _mock_aes(val, key=0):
    return (val * 1000003 + key * 999983) % (10**9 + 7)


# ==========================================
# 模擬學長的 dag_get_BT
# 實際使用時替換：from BT_DAG import dag_get_BT
# ==========================================

def _mock_dag_get_BT(num, bits, x):
    s = bits // x
    result = []
    binary_str = format(num, f'0{bits}b')

    for seg_idx in range(x):
        sub_bin = binary_str[s * seg_idx: s * (seg_idx + 1)]
        dag_size = (s + 1) * (s + 2) // 2
        bt = [0] * dag_size

        bt[0] = 1  # root 永遠是 1
        level, pos = 0, 0
        for bit in sub_bin:
            level += 1
            if bit == '1':
                pos += 1
            idx = level * (level + 1) // 2 + pos
            bt[idx] = 1

        result.extend(bt)

    return result


# ==========================================
# 模擬學長的 dag_get_BTQ_list
# 實際使用時替換：from dag_range_decomposition import dag_get_BTQ_list
# ==========================================

def _mock_dag_get_BTQ_list(q, bits, x):
    start, end = q
    s = bits // x

    def decompose(lo, hi, depth, prefix_bits):
        if depth == bits:
            val = int(''.join(map(str, prefix_bits)), 2) if prefix_bits else 0
            return [prefix_bits[:]] if lo <= val <= hi else []

        remaining = bits - depth
        pfx_str = ''.join(map(str, prefix_bits))
        range_min = int(pfx_str + '0' * remaining, 2) if pfx_str else 0
        range_max = int(pfx_str + '1' * remaining, 2) if pfx_str else (2**bits - 1)

        if range_max < lo or range_min > hi:
            return []
        if lo <= range_min and range_max <= hi:
            return [prefix_bits[:] + ['*'] * remaining]

        return (decompose(lo, hi, depth + 1, prefix_bits + [0]) +
                decompose(lo, hi, depth + 1, prefix_bits + [1]))

    tokens = decompose(start, end, 0, [])
    result = []

    for token_bits in tokens:
        s_indices = []
        offset = 0
        for seg_idx in range(x):
            sub_token = token_bits[s * seg_idx: s * (seg_idx + 1)]
            s_indices.append(offset + 0)  # root 永遠標 1
            level, pos = 0, 0
            for bit in sub_token:
                if bit != '*':
                    level += 1
                    if bit == 1:
                        pos += 1
                    s_indices.append(offset + level * (level + 1) // 2 + pos)
            offset += (s + 1) * (s + 2) // 2
        result.append(s_indices)

    return result


# ==========================================
# 節點類別
# ==========================================

class DGPPTNode:
    """
    DG-PPT 節點，和學長的 KaryTreeNode 相容
    新增：layer_id, version, record_id, data_value
    """
    def __init__(self, val=None):
        self.val = val
        self.children = []
        self.BT = []
        self.c = []
        self.is_leaf = False
        # 新增欄位
        self.layer_id = None
        self.version = None
        self.record_id = None
        self.data_value = None


# ==========================================
# 建立單層 k-ary PPT
# ==========================================

def build_layer_tree(data_list, layer_key, MAX, t, x, ratios,
                     layer_id, version, start_record_id=0,
                     aes_func=None, dag_get_BT_func=None):
    """
    建立單一層的 k-ary PPT 索引

    加密邏輯（和學長相容）：
      c[i] = aes(bt[i] + i)  ← 不含 layer_key
      layer_key 只用在 token 生成的 d0/d1

    Args:
        data_list: 資料值列表
        layer_key: 層金鑰(只用於 token,不用於 c)
        MAX, t, x, ratios: 索引參數
        layer_id, version: 識別資訊
        start_record_id: 起始 record ID

    Returns:
        DGPPTNode 根節點，若 data_list 為空則回傳 None
    """
    if not data_list:
        return None

    if aes_func is None:
        aes_func = _mock_aes
    if dag_get_BT_func is None:
        dag_get_BT_func = _mock_dag_get_BT

    # ===== 建立所有葉節點 =====
    leaf_nodes = []
    for idx, val in enumerate(data_list):
        node = DGPPTNode(val=(start_record_id + idx, val))
        node.is_leaf = True
        node.layer_id = layer_id
        node.version = version
        node.record_id = start_record_id + idx
        node.data_value = val

        # 生成 bitmap（和學長的 dag_get_BT 相同）
        node.BT = dag_get_BT_func(val, MAX, x)

        # ASHVE+ 擴展：加入 t 個額外位置（和學長相同）
        for i in range(t):
            node.BT.append(i % 2)

        # 加密：c[i] = aes(bt[i] + i)（和學長相同）
        # 在最後附加 layer_key 標籤：c[-1] = aes(0, layer_key)
        # 這讓不同層的密文有不同的「層識別標籤」
        # 查詢時先比對標籤，確保 token 和密文屬於同一層
        size = len(node.BT)
        node.c = [aes_func(node.BT[i] + i) for i in range(size)]
        node.c.append(aes_func(0, layer_key))  # 層標籤

        leaf_nodes.append(node)

    # ===== Top-down 遞迴分組（和學長的 buildAdaptiveKaryTree 相同） =====
    def build_recursive(nodes, depth=0):
        unique_vals = set(n.data_value for n in nodes)

        if len(nodes) == 1:
            return nodes[0]

        if len(unique_vals) == 1:
            # 重複資料：合併成一個內部節點
            internal = DGPPTNode(val=f"dup_{list(unique_vals)[0]}")
            internal.is_leaf = False
            internal.layer_id = layer_id
            internal.version = version
            internal.children = nodes
            internal.BT = _bt_or([n.BT for n in nodes])
            size = len(internal.BT)
            internal.c = [aes_func(internal.BT[i] + i) for i in range(size)]
            internal.c.append(aes_func(0, layer_key))  # 層標籤
            return internal

        groups = _split_by_ratio(nodes, ratios)
        children = [build_recursive(g, depth + 1) for g in groups if g]

        internal = DGPPTNode(val=f"internal_L{layer_id}_d{depth}")
        internal.is_leaf = False
        internal.layer_id = layer_id
        internal.version = version
        internal.children = children
        internal.BT = _bt_or([c.BT for c in children])
        size = len(internal.BT)
        internal.c = [aes_func(internal.BT[i] + i) for i in range(size)]
        internal.c.append(aes_func(0, layer_key))  # 層標籤

        return internal

    return build_recursive(leaf_nodes)


def _bt_or(bt_list):
    if not bt_list:
        return []
    max_len = max(len(bt) for bt in bt_list)
    result = [0] * max_len
    for bt in bt_list:
        for i in range(len(bt)):
            result[i] |= bt[i]
    return result


def _split_by_ratio(nodes, ratios):
    total = len(nodes)
    groups = []
    start = 0
    for i, ratio in enumerate(ratios):
        count = (total - start) if i == len(ratios) - 1 else max(1, int(total * ratio))
        end = min(start + count, total)
        if end > start:
            groups.append(nodes[start:end])
        start = end
    return groups


# ==========================================
# Token 生成（帶 layer_key，確保層隔離）
# ==========================================

def gen_token_for_layer(q, MAX, layer_key, t, x,
                        aes_func=None, dag_get_BTQ_func=None):
    """
    為特定層生成查詢 token

    和學長的 token_gen_set_s 邏輯相同，但用 layer_key 取代 key_trap
    這樣不同層的 token 不可互換，達到 Forward Privacy

    d0 = sum(aes(1+idx) for idx in S1) + aes(extra) + layer_key
    d1 = aes(0, layer_key)
    """
    if aes_func is None:
        aes_func = _mock_aes
    if dag_get_BTQ_func is None:
        dag_get_BTQ_func = _mock_dag_get_BTQ_list

    s = MAX // x
    total_dag_length = x * ((s + 1) * (s + 2) // 2)

    BTQ_indices_list = dag_get_BTQ_func(q, MAX, x)
    T_list = []

    for S_indices in BTQ_indices_list:
        num_encrypt = 0
        S = list(S_indices)

        # S1：BTQ 中值為 '1' 的位置
        for idx in S_indices:
            num_encrypt += aes_func(1 + idx)  # 不含 layer_key，和加密時一致

        # S2：隨機額外位置（隱藏 |S1| 大小）
        loc = random.randint(0, t - 1)
        last = loc % 2
        S.append(loc + total_dag_length)
        num_encrypt += aes_func(last + loc + total_dag_length)

        # d0 和 d1 含 layer_key（不同層不可互換的關鍵）
        d0 = num_encrypt + layer_key
        d1 = aes_func(0, layer_key)

        T_list.append((d0, d1, S))

    return T_list


# ==========================================
# 查詢函式
# ==========================================

def _match(ciphertext, tokens, aes_func=None):
    """
    測試密文是否匹配任意一個 token

    修正版：先比對層標籤再做 ASHVE 匹配
      c[-1] = aes(0, layer_key)  ← 層標籤
      token.d1 = aes(0, layer_key)
      若 c[-1] ≠ token.d1 → 不同層的 token,直接跳過
      → 確保舊 token 無法匹配新層密文(Forward Privacy)
    """
    if aes_func is None:
        aes_func = _mock_aes

    # 取出層標籤（密文最後一個元素）
    layer_tag = ciphertext[-1] if ciphertext else None

    for token in tokens:
        d0, d1, S = token

        # 先比對層標籤：d1 = aes(0, layer_key) = 層標籤
        # 若不符合，直接跳過（不同層的 token）
        if layer_tag is not None and d1 != layer_tag:
            continue

        # 正常的 ASHVE 匹配流程
        # 注意：不包含最後的層標籤位置（c[:-1]）
        num_q = sum(ciphertext[idx] for idx in S if idx < len(ciphertext) - 1)
        key_candidate = d0 - num_q
        if aes_func(0, key_candidate) == d1:
            return True

    return False


def query_single_layer(node, tokens, results, aes_func=None):
    """
    查詢單一層的 k-ary PPT(和學長的 kary_tree_query 相同邏輯)

    匹配 → 葉節點加入結果 / 內部節點遞迴子節點
    不匹配 → 剪枝
    """
    if node is None:
        return
    if aes_func is None:
        aes_func = _mock_aes

    if _match(node.c, tokens, aes_func):
        if node.is_leaf:
            results.add((node.record_id, node.data_value))
        else:
            for child in node.children:
                query_single_layer(child, tokens, results, aes_func)


# ==========================================
# LayeredIndex：核心類別
# ==========================================

class LayeredIndex:
    """
    分層索引管理器

    插入邏輯(Binary Counter):
      插入新資料時，從 Layer 0 開始往上找第一個空層
      沿途把已有的層和新資料合併

      例：插入第 4 筆資料(目前有 Layer 0=1筆, Layer 1=2筆)
        新資料 + Layer 0(1筆)= 2筆 → 繼續往上
        2筆 + Layer 1(2筆)= 4筆 → Layer 1 為空 → 放到 Layer 2 ✓

    Forward Privacy:
      合併時用新 layer_key(由 PPRF 派生)重新加密
      舊 token 的 d1 = aes(0, old_key)
      新層的   d1 = aes(0, new_key)
      old_key ≠ new_key → 舊 token 無法匹配新層
    """

    def __init__(self, MAX=8, t=2, x=2, ratios=None,
                 pprf=None, aes_func=None,
                 dag_get_BT_func=None, dag_get_BTQ_func=None):
        self.MAX = MAX
        self.t = t
        self.x = x
        self.ratios = ratios or [0.15, 0.70, 0.15]

        self.aes_func = aes_func or _mock_aes
        self.dag_get_BT_func = dag_get_BT_func or _mock_dag_get_BT
        self.dag_get_BTQ_func = dag_get_BTQ_func or _mock_dag_get_BTQ_list

        self.pprf = pprf or SimplePPRF()
        self.master_key = self.pprf.gen()

        # layer_id → {'root', 'data', 'key', 'version', 'size'}
        self.layers: Dict[int, dict] = {}

        # 本地刪除列表（伺服器不可見）
        self.delete_list: Set[int] = set()

        self.global_counter = 0
        self._next_record_id = 0

        self.stats = {
            'total_insertions': 0,
            'total_deletions': 0,
            'total_merges': 0,
            'total_queries': 0
        }

    # ------------------------------------------
    # 公開介面
    # ------------------------------------------

    def insert(self, val: int) -> None:
        """
        插入一筆新資料

        正確的 Binary Counter 邏輯：
          從 Layer 0 往上找第一個空層
          沿途把遇到的層和新資料累積合併
          把最終的合併資料放到第一個空層

        Forward Privacy:
          每次合併都用新的 layer_key 加密
          確保舊 token 無法匹配新層
        """
        self.stats['total_insertions'] += 1

        # 累積要放入的資料
        pending_data = [val]
        i = 0

        # 往上找第一個空層，沿途合併
        while i in self.layers:
            old_info = self.layers[i]
            merged = old_info['data'] + pending_data

            # 過濾刪除列表
            merged = [v for v in merged if v not in self.delete_list]

            # 穿孔舊層的金鑰（讓舊 token 失效）
            old_uid = i * 10000 + old_info['version']
            self.pprf.puncture(self.master_key, old_uid)

            # 刪除舊層
            del self.layers[i]
            self.stats['total_merges'] += 1

            pending_data = merged
            self.global_counter += 1
            i += 1

        # 放到第一個空層，用新金鑰加密
        new_key = self._derive_layer_key(i)
        start_rid = self._next_record_id
        self._next_record_id += len(pending_data)

        new_root = build_layer_tree(
            data_list=pending_data,
            layer_key=new_key,
            MAX=self.MAX,
            t=self.t,
            x=self.x,
            ratios=self.ratios,
            layer_id=i,
            version=self.global_counter,
            start_record_id=start_rid,
            aes_func=self.aes_func,
            dag_get_BT_func=self.dag_get_BT_func
        )

        self.layers[i] = {
            'root': new_root,
            'data': pending_data,
            'key': new_key,
            'version': self.global_counter,
            'size': len(pending_data)
        }

        self.global_counter += 1
        print(f"  [Insert] val={val} → Layer {i} "
              f"（大小={len(pending_data)}），"
              f"現有層: {sorted(self.layers.keys())}")

    def delete(self, val: int) -> None:
        """
        刪除資料(Lazy Deletion)
        只在本地 delete_list 記錄，伺服器不知道
        """
        self.delete_list.add(val)
        self.stats['total_deletions'] += 1
        print(f"  [Delete] val={val} 已標記刪除"
              f"（刪除列表大小: {len(self.delete_list)})")

        if self._should_rebuild():
            print(f"  [Delete] 觸發重建...")
            self._rebuild()

    def query(self, q: Tuple[int, int]) -> Set[int]:
        """
        查詢所有層，合併結果，過濾刪除列表

        每層用各自的 layer_key 生成 token
        結果取聯集後過濾 delete_list
        """
        self.stats['total_queries'] += 1
        all_results = set()

        print(f"  [Query] 範圍={q}，查詢 {len(self.layers)} 個層...")

        for layer_id in sorted(self.layers.keys()):
            info = self.layers[layer_id]
            root = info['root']
            layer_key = info['key']

            if root is None:
                continue

            # 用層金鑰生成 token
            tokens = gen_token_for_layer(
                q=q,
                MAX=self.MAX,
                layer_key=layer_key,
                t=self.t,
                x=self.x,
                aes_func=self.aes_func,
                dag_get_BTQ_func=self.dag_get_BTQ_func
            )

            layer_results = set()
            query_single_layer(root, tokens, layer_results, self.aes_func)

            print(f"    Layer {layer_id}({info['size']} 筆）: "
                  f"找到 {len(layer_results)} 筆候選")

            all_results |= layer_results

        # 過濾刪除列表
        final = {val for (_, val) in all_results if val not in self.delete_list}

        print(f"  [Query] 合併 {len(all_results)} 筆候選 → "
              f"過濾後 {len(final)} 筆結果")

        return final

    def layer_summary(self) -> str:
        lines = ["分層索引狀態："]
        for lid in sorted(self.layers.keys()):
            info = self.layers[lid]
            lines.append(
                f"  Layer {lid}: {info['size']} 筆, "
                f"版本={info['version']}, "
                f"金鑰=...{str(info['key'])[-6:]}"
            )
        lines.append(f"  刪除列表: {len(self.delete_list)} 筆")
        lines.append(f"  有效資料: {self.total_size()} 筆")
        return "\n".join(lines)

    def total_size(self) -> int:
        total = sum(info['size'] for info in self.layers.values())
        return max(0, total - len(self.delete_list))

    # ------------------------------------------
    # 私有方法
    # ------------------------------------------

    def _derive_layer_key(self, layer_id: int) -> int:
        """
        派生層金鑰：用 (layer_id * 10000 + global_counter) 作為 PPRF 輸入
        確保每次合併的新層都有全新的金鑰
        """
        unique_id = layer_id * 10000 + self.global_counter
        key = self.pprf.eval(self.master_key, unique_id)
        if key is None:
            # 備用：直接用 hash
            h = hashlib.sha256(
                f"{layer_id}_{self.global_counter}".encode()
            ).hexdigest()
            key = int(h, 16) % (10**9 + 7)
        return key

    def _should_rebuild(self) -> bool:
        total = sum(info['size'] for info in self.layers.values())
        return total > 0 and len(self.delete_list) > max(5, total // 4)

    def _rebuild(self) -> None:
        """完整重建：清除所有已刪除的資料"""
        all_valid = [
            v for info in self.layers.values()
            for v in info['data']
            if v not in self.delete_list
        ]
        print(f"  [Rebuild] 重建 {len(all_valid)} 筆有效資料...")

        self.layers = {}
        self.delete_list = set()
        self.global_counter += 1
        self._next_record_id = 0

        for val in all_valid:
            self.insert(val)

        print(f"  [Rebuild] 完成，現有層: {sorted(self.layers.keys())}")


# ==========================================
# 測試
# ==========================================

if __name__ == "__main__":
    print("=" * 65)
    print("Dynamic G-PPT (DG-PPT) 測試")
    print("=" * 65)

    idx = LayeredIndex(MAX=8, t=2, x=2, ratios=[0.15, 0.70, 0.15])

    # ------------------------------------------
    # 測試一：Binary Counter 插入邏輯
    # ------------------------------------------
    print("\n【測試一:Binary Counter 插入邏輯】")
    print("-" * 45)
    print("預期：插入 8 筆後只剩 Layer 3(容量 8)")

    for v in [10, 20, 30, 40, 50, 60, 70, 80]:
        idx.insert(v)

    print(f"\n{idx.layer_summary()}")
    expected_layers = {3}
    assert set(idx.layers.keys()) == expected_layers, \
        f"層結構錯誤！期望 {expected_layers}，實際 {set(idx.layers.keys())}"
    print("✓ Binary Counter 邏輯正確")

    # ------------------------------------------
    # 測試二：範圍查詢
    # ------------------------------------------
    print("\n【測試二:範圍查詢】")
    print("-" * 45)

    insert_vals = [10, 20, 30, 40, 50, 60, 70, 80]
    queries = [(20, 60), (10, 30), (50, 100)]

    all_pass = True
    for q in queries:
        print(f"\n查詢 {q}:")
        results = idx.query(q)
        expected = {v for v in insert_vals if q[0] <= v <= q[1]}
        ok = results == expected
        if not ok:
            all_pass = False
        print(f"  結果: {sorted(results)}")
        print(f"  期望: {sorted(expected)}")
        print(f"  {'✓ 正確' if ok else '✗ 不正確'}")

    # ------------------------------------------
    # 測試三：刪除後查詢
    # ------------------------------------------
    print("\n【測試三:刪除後查詢】")
    print("-" * 45)

    idx.delete(30)
    idx.delete(50)

    q = (20, 60)
    print(f"\n刪除 30, 50 後查詢 {q}:")
    results = idx.query(q)
    expected = {v for v in insert_vals
                if q[0] <= v <= q[1] and v not in {30, 50}}
    ok = results == expected
    if not ok:
        all_pass = False
    print(f"  結果: {sorted(results)}")
    print(f"  期望: {sorted(expected)}")
    print(f"  {'✓ 正確' if ok else '✗ 不正確'}")

    # ------------------------------------------
    # 測試四：混合操作
    # ------------------------------------------
    print("\n【測試四:混合插入/刪除/查詢】")
    print("-" * 45)

    idx2 = LayeredIndex(MAX=8, t=2, x=2)
    mixed_data = [5, 15, 25, 35, 45, 55, 65, 75]

    for v in mixed_data:
        idx2.insert(v)

    print(f"\n{idx2.layer_summary()}")

    idx2.delete(25)
    idx2.delete(65)
    idx2.insert(30)
    idx2.insert(70)

    print(f"\n刪除 25, 65,插入 30, 70 後：")
    print(idx2.layer_summary())

    q = (20, 70)
    print(f"\n查詢 {q}:")
    results = idx2.query(q)
    valid = (set(mixed_data) - {25, 65}) | {30, 70}
    expected = {v for v in valid if q[0] <= v <= q[1]}
    ok = results == expected
    if not ok:
        all_pass = False
    print(f"  結果: {sorted(results)}")
    print(f"  期望: {sorted(expected)}")
    print(f"  {'✓ 正確' if ok else '✗ 不正確'}")

    # ------------------------------------------
    # 測試五：Forward Privacy 示意
    # ------------------------------------------
    print("\n【測試五:Forward Privacy 示意】")
    print("-" * 45)

    idx3 = LayeredIndex(MAX=8, t=2, x=2)
    idx3.insert(100)

    # 記錄 Layer 0 的金鑰
    old_key = idx3.layers[0]['key']
    old_token = gen_token_for_layer(
        q=(90, 110), MAX=8, layer_key=old_key, t=2, x=2
    )

    # 插入第二筆 → 合併成 Layer 1，Layer 0 消失
    idx3.insert(200)

    print(f"\n插入 100 時 Layer 0 金鑰: ...{str(old_key)[-6:]}")

    if 1 in idx3.layers:
        new_key = idx3.layers[1]['key']
        new_root = idx3.layers[1]['root']
        print(f"合併後 Layer 1 金鑰:     ...{str(new_key)[-6:]}")
        print(f"金鑰不同: {'✓' if old_key != new_key else '✗'}")

        # 舊 token 嘗試匹配新層
        fake_results = set()
        query_single_layer(new_root, old_token, fake_results)
        print(f"\n舊 token 匹配新層結果: {fake_results}")
        fp_ok = len(fake_results) == 0
        if not fp_ok:
            all_pass = False
        print(f"舊 token 無法匹配新層: {'✓ Forward Privacy 成立' if fp_ok else '✗ 失敗'}")

    # ------------------------------------------
    # 測試六：統計資訊
    # ------------------------------------------
    print("\n【測試六:統計資訊(第一個索引)】")
    print("-" * 45)
    print(f"  總插入次數: {idx.stats['total_insertions']}")
    print(f"  總刪除次數: {idx.stats['total_deletions']}")
    print(f"  總合併次數: {idx.stats['total_merges']}")
    print(f"  總查詢次數: {idx.stats['total_queries']}")
    print(f"  Global Counter: {idx.global_counter}")

    print("\n" + "=" * 65)
    print(f"整體結果: {'✓ 全部通過' if all_pass else '✗ 有測試失敗'}")
    print("=" * 65)
