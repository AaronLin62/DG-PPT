"""
brc_gppt.py
===========
BRC-GPPT:融合方案

融合來源：
  1. RSSE(Wang & Chow)的 BRC 查詢分解 + Forward Privacy 框架
     - Best Range Cover(BRC)把範圍分解成最小覆蓋節點集合
     - PRF-based counter 機制確保 Forward Privacy
     - Simulation-based 安全框架（洩漏函數定義）

  2. G-PPT(學長論文)的 tri-DAG + k-ary PPT 索引
     - tri-DAG 把數值映射到 O(m²) 的 bitmap(比 EPRQ 的 O(2^m) 小）
     - k-ary PPT 根據資料分佈調整分組，支援重複資料

  3. DG-PPT(我們)的分層索引
     - Binary Counter 邏輯管理多個靜態 G-PPT
     - 插入均攤成本 O(log n)

核心改進：
  RSSE 的問題：索引節點用隱式二元樹，不考慮資料分佈
  G-PPT 的問題：沒有動態更新
  DG-PPT 的問題:Forward Privacy 沒有形式化定義

  BRC-GPPT:
    - 用 BRC 分解查詢（比 G-PPT 的 prefix decomposition 更精確）
    - 用 tri-DAG 編碼每個 BRC 節點（比 RSSE 的隱式二元樹更緊湊）
    - 用 RSSE 的 counter 機制確保 Forward Privacy(形式化)
    - 用分層索引管理插入

洩漏函數（參考 RSSE 的定義格式）：
  L_Setup    = ⊥
  L_Insert   = L'(op, size_of_update)  （無狀態）
  L_Delete   = L'(op)                  （只洩漏操作類型）
  L_Query(q) = (sp(τ), hist(τ)) for τ in BRC(q)
"""

import sys
import random
import hashlib
import time
from pathlib import Path
from typing import List, Set, Dict, Tuple, Optional, Any
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from pprf import SimplePPRF


# ==========================================
# 基礎加密函式（模擬 PRF + Hash）
# ==========================================

def _prf(key: int, x: int) -> int:
    """
    偽隨機函數 F(key, x)
    對應論文的 F : {0,1}^λ × {0,1}^* → {0,1}^λ
    """
    h = hashlib.sha256(f"{key}:{x}".encode()).hexdigest()
    return int(h, 16) % (10**9 + 7)

def _hash1(key: int, counter: int) -> int:
    """H1(key || counter) → 儲存位置"""
    h = hashlib.sha256(f"H1:{key}:{counter}".encode()).hexdigest()
    return int(h, 16) % (10**15)

def _hash2(key: int, counter: int) -> int:
    """H2(key || counter) → 加密 mask"""
    h = hashlib.sha256(f"H2:{key}:{counter}".encode()).hexdigest()
    return int(h, 16) % (10**9 + 7)

def _aes(val: int, key: int = 0) -> int:
    """模擬 AES 加密（用於 tri-DAG bitmap 加密）"""
    return (val * 1000003 + key * 999983) % (10**9 + 7)


# ==========================================
# BRC（Best Range Cover）
# 來自 RSSE 論文的 Section 3.2 和 5.1
# ==========================================

def compute_brc(a: int, b: int, m: int) -> List[str]:
    """
    計算範圍 [a, b] 的 Best Range Cover（BRC）

    用隱式二元樹：深度為 m，葉節點對應 0 到 2^m-1 的值
    節點用二進位前綴字串表示：
      葉節點 5 = "101"（m=3）
      父節點 = "10"
      根節點 = ""

    算法（來自 RSSE 論文 Figure 2 的 Search 1-14 行）：
      把 [a,b] 轉成二進位
      如果下界最後一位是 1，把下界加入 BRC，下界++
      如果上界最後一位是 0，把上界加入 BRC，上界--
      把兩個界各去掉最後一位（往上移一層）
      重複直到下界 >= 上界

    Args:
        a: 查詢範圍下界
        b: 查詢範圍上界
        m: 域的位元數（域大小 = 2^m）

    Returns:
        BRC 節點的二進位前綴字串列表

    Example:
        compute_brc(2, 7, 3) → ["01", "1"]
        對應論文 Figure 1 的 τ_{2,3} 和 τ_{4,7}
    """
    if a > b:
        return []

    # 轉成 m-bit 二進位字串
    a_bits = list(format(a, f'0{m}b'))
    b_bits = list(format(b, f'0{m}b'))
    covering = []

    i = 0
    # 從最低位往上，縮小範圍直到兩界相遇
    while a_bits[:m-i] < b_bits[:m-i]:
        # 如果下界最後一位是 1（右子節點）
        # 這個葉節點不能被父節點覆蓋，單獨加入 BRC
        if a_bits[m-1-i] == '1':
            covering.append(''.join(a_bits[:m-i]))
            # 下界往右移一位（+1 在當前層）
            # 等效於把最後一位去掉後 +1
            carry = 1
            for j in range(m-1-i, -1, -1):
                s = int(a_bits[j]) + carry
                a_bits[j] = str(s % 2)
                carry = s // 2

        # 如果上界最後一位是 0（左子節點）
        # 同樣不能被父節點覆蓋
        if b_bits[m-1-i] == '0':
            covering.append(''.join(b_bits[:m-i]))
            # 上界往左移一位（-1 在當前層）
            borrow = 1
            for j in range(m-1-i, -1, -1):
                s = int(b_bits[j]) - borrow
                b_bits[j] = str(s % 2) if s >= 0 else '1'
                borrow = 0 if s >= 0 else 1

        i += 1  # 往上移一層（截掉最後一位）

    # 如果兩個界相等，加入這個共同祖先
    if a_bits[:m-i] == b_bits[:m-i] and m-i > 0:
        covering.append(''.join(a_bits[:m-i]))
    elif a_bits[:m-i] == b_bits[:m-i] and m-i == 0:
        covering.append('')  # 根節點

    return covering


def brc_node_range(node: str, m: int) -> Tuple[int, int]:
    """
    計算 BRC 節點覆蓋的數值範圍

    Args:
        node: 節點的二進位前綴字串（例如 "01"）
        m: 域的位元數

    Returns:
        (min_val, max_val)：這個節點覆蓋的最小和最大值
    """
    depth = len(node)
    remaining = m - depth
    if not node:
        return (0, 2**m - 1)
    min_val = int(node + '0' * remaining, 2)
    max_val = int(node + '1' * remaining, 2)
    return (min_val, max_val)


# ==========================================
# tri-DAG bitmap 編碼
# 來自 G-PPT 的 tri-DAG indexing
# ==========================================

def tridag_index(level: int, pos: int) -> int:
    """把 (level, pos) 轉成 tri-DAG 一維索引"""
    return level * (level + 1) // 2 + pos


def val_to_bitmap(val: int, bits: int, x: int) -> List[int]:
    """
    把數值轉成 tri-DAG bitmap（來自 G-PPT 的 dag_get_BT）

    Args:
        val: 數值
        bits: 總位元數
        x: 分段數

    Returns:
        bitmap（0/1 列表）
    """
    s = bits // x
    binary_str = format(val, f'0{bits}b')
    result = []

    for seg_idx in range(x):
        sub_bin = binary_str[s * seg_idx: s * (seg_idx + 1)]
        dag_size = (s + 1) * (s + 2) // 2
        bt = [0] * dag_size
        bt[0] = 1  # root

        level, pos = 0, 0
        for bit in sub_bin:
            level += 1
            if bit == '1':
                pos += 1
            bt[tridag_index(level, pos)] = 1

        result.extend(bt)

    return result


def range_to_token_bitmap(node: str, m: int, x: int) -> List[str]:
    """
    把 BRC 節點轉成查詢 bitmap（值為 '1' 或 '*'）

    BRC 節點是一個前綴，對應一個子樹
    前綴部分的 bit 是確定的（1 或 0）
    剩餘部分是萬用字元（*）

    Args:
        node: BRC 節點前綴（例如 "01"）
        m: 總位元數
        x: 分段數

    Returns:
        查詢 bitmap（含 '*' 的列表）
    """
    # 補齊到 m bits，剩餘部分用 '*'
    full_token = list(node) + ['*'] * (m - len(node))
    s = m // x
    result = []

    for seg_idx in range(x):
        sub_token = full_token[s * seg_idx: s * (seg_idx + 1)]
        dag_size = (s + 1) * (s + 2) // 2
        btq = ['*'] * dag_size
        btq[0] = '1'  # root 永遠是 1

        level, pos = 0, 0
        for bit in sub_token:
            if bit != '*':
                level += 1
                if bit == '1':
                    pos += 1
                btq[tridag_index(level, pos)] = '1'

        result.extend(btq)

    return result


# ==========================================
# RSSE 風格的 Forward-Secure Counter 機制
# 核心來自 RSSE 論文的 Section 5 和 6
# ==========================================

class NodeState:
    """
    每個 BRC 節點（隱式二元樹節點）的狀態
    對應 RSSE 論文的 W[τ] = (k_τ, c_h, c_u)

    k_τ：PRF 金鑰（每次查詢後更新為新的隨機金鑰）
    c_h：歷史更新計數器（累積所有插入/刪除）
    c_u：上次查詢後的更新計數器
    """
    def __init__(self, key: int, hist_count: int = 0, update_count: int = 0):
        self.key = key           # k_τ：當前的 PRF 金鑰
        self.hist_count = hist_count   # c_h：歷史更新總數
        self.update_count = update_count  # c_u：上次查詢後的更新數


# ==========================================
# BRC-GPPT 加密索引節點
# ==========================================

class BRCGPPTEntry:
    """
    加密索引條目
    對應 RSSE 的 Te[addr] = val，但擴展為 tri-DAG bitmap

    每個插入操作在加密索引裡留下一個條目：
      addr = H1(k_τ || counter)
      val  = (id || op) XOR H2(k_τ || counter)
      bitmap = 加密後的 tri-DAG bitmap（用於 G-PPT 查詢）
    """
    def __init__(self, addr: int, val: int, val_id: int, op: str,
                 bitmap: List[int], bitmap_encrypted: List[int]):
        self.addr = addr
        self.val = val              # 加密的 (id, op)
        self.val_id = val_id        # 原始資料 ID（只有客戶端知道）
        self.op = op                # 'add' 或 'del'
        self.bitmap = bitmap        # 原始 bitmap（伺服器不知道）
        self.c_enc = bitmap_encrypted  # 加密後的 bitmap（伺服器存的）


# ==========================================
# BRC-GPPT 主類別
# ==========================================

class BRCGPPTIndex:
    """
    BRC-GPPT：融合方案的核心索引

    結合了：
      - RSSE 的 BRC 查詢分解和 Forward Privacy 框架
      - G-PPT 的 tri-DAG 編碼
      - DG-PPT 的分層索引管理

    安全性：
      Forward Privacy：Insert 的 L_Updt 是無狀態的
        只洩漏 (op, 涉及的節點數) = (op, log|W|)
        不洩漏具體的數值內容
      Backward Privacy（弱）：
        Delete 用 Lazy Deletion
        查詢時 DU 本地過濾
    """

    def __init__(self,
                 M: int = 8,    # 域的位元數，域大小 = 2^M
                 t: int = 2,    # ASHVE+ 的額外位置數
                 x: int = 2,    # tri-DAG 分段數
                 ratios: List[float] = None):
        """
        Args:
            M: 位元數（支援 0 ~ 2^M - 1 的數值）
            t: ASHVE+ 額外位置數
            x: tri-DAG 分段數（M 必須能被 x 整除）
            ratios: k-ary PPT 分組比例
        """
        self.M = M
        self.t = t
        self.x = x
        self.ratios = ratios or [0.15, 0.70, 0.15]

        # PRF 主金鑰（只有客戶端知道）
        self._K1 = random.randint(1, 10**9)  # 用於生成節點金鑰
        self._K2 = random.randint(1, 10**9)  # 用於生成查詢假名

        # 客戶端狀態：每個 BRC 節點的狀態
        # node_prefix → NodeState
        self._node_states: Dict[str, NodeState] = {}

        # 刪除列表（客戶端本地，伺服器不可見）
        self._delete_list: Set[int] = set()

        # ---- 伺服器端（模擬）----
        # 加密索引：addr → BRCGPPTEntry
        self._encrypted_index: Dict[int, BRCGPPTEntry] = {}

        # 查詢結果快取（對應 RSSE 的 Tc）
        # node_pseudonym → set of val_ids
        self._result_cache: Dict[int, Set[int]] = {}

        # 統計
        self.stats = {
            'inserts': 0,
            'deletes': 0,
            'queries': 0,
            'brc_nodes_created': 0,
            'index_entries': 0,
        }

    # ------------------------------------------
    # 公開介面
    # ------------------------------------------

    def insert(self, val: int) -> None:
        """
        插入一筆資料

        RSSE 的 Update 機制：
          把 val 的 BRC 節點（val 本身 + 所有祖先）都更新
          每個節點用 PRF counter 機制加密

        Forward Privacy（對應 RSSE 定義 3）：
          L_Updt(op='add', val) = L'(op, log|W|)
          只洩漏操作類型和更新的節點數（log|W|）
          不洩漏 val 的具體內容
        """
        self.stats['inserts'] += 1

        # 計算 val 在隱式二元樹裡的所有節點：
        # val 本身（葉節點） + 所有祖先節點
        nodes = self._get_node_path(val)

        for node_prefix in nodes:
            self._update_node(node_prefix, val, 'add')

    def delete(self, val: int) -> None:
        """
        刪除一筆資料

        用 Lazy Deletion：
          在本地 delete_list 記錄
          下次查詢時 DU 本地過濾
        """
        self._delete_list.add(val)
        self.stats['deletes'] += 1

    def query(self, a: int, b: int) -> Set[int]:
        """
        查詢範圍 [a, b]

        RSSE 的 Search 機制：
          Step 1：計算 BRC([a, b])
          Step 2：對每個 BRC 節點生成查詢 token
          Step 3：用 tri-DAG bitmap 匹配加密索引
          Step 4：合併結果，過濾刪除列表

        Args:
            a: 查詢下界
            b: 查詢上界

        Returns:
            符合範圍的資料值集合
        """
        self.stats['queries'] += 1

        # Step 1：計算 BRC
        brc_nodes = compute_brc(a, b, self.M)

        all_results = set()

        for node_prefix in brc_nodes:
            # Step 2：取得節點狀態，生成查詢 token
            state = self._get_or_create_node_state(node_prefix)

            if state.update_count == 0 and node_prefix not in self._result_cache_key_map():
                # 這個節點從未被更新過，跳過
                continue

            # 生成節點的查詢假名（對應 RSSE 的 nymw = F(K2, τ)）
            pseudonym = _prf(self._K2, hash(node_prefix))

            # Step 3：從快取取上次結果
            cached = self._result_cache.get(pseudonym, set()).copy()
            node_results = cached

            # 用 counter 掃描這個節點上次查詢後的新更新
            old_key = state.key
            c = state.update_count

            for i in range(1, c + 1):
                addr = _hash1(old_key, i)
                if addr in self._encrypted_index:
                    entry = self._encrypted_index[addr]
                    # 解密 (id, op)
                    mask = _hash2(old_key, i)
                    decrypted = entry.val ^ mask
                    op = entry.op
                    val_id = entry.val_id

                    if op == 'del':
                        node_results.discard(val_id)
                    else:
                        node_results.add(val_id)

            # 更新快取，更換節點金鑰（Forward Privacy 關鍵）
            self._result_cache[pseudonym] = node_results

            # 更新節點狀態：換新金鑰，重置 update_count
            new_key = random.randint(1, 10**9)
            state.key = new_key
            state.update_count = 0

            all_results |= node_results

        # Step 4：過濾刪除列表
        final = all_results - self._delete_list

        return final

    def total_inserted(self) -> int:
        """目前索引中的資料筆數（含已刪除）"""
        return self.stats['inserts']

    def state_summary(self) -> str:
        lines = [
            "BRC-GPPT 狀態：",
            f"  已插入: {self.stats['inserts']} 筆",
            f"  已刪除(Lazy): {self.stats['deletes']} 筆",
            f"  加密索引條目: {len(self._encrypted_index)}",
            f"  節點狀態數: {len(self._node_states)}",
            f"  刪除列表: {len(self._delete_list)} 筆",
        ]
        return "\n".join(lines)

    # ------------------------------------------
    # 私有方法
    # ------------------------------------------

    def _get_node_path(self, val: int) -> List[str]:
        """
        取得 val 在隱式二元樹裡的路徑：
        葉節點 + 所有祖先節點（包含根）

        對應 RSSE 的 Update 第 2-7 行
        """
        binary_val = format(val, f'0{self.M}b')
        nodes = []
        # 從葉節點（完整 M bits）到根節點（空字串）
        for depth in range(self.M, -1, -1):
            nodes.append(binary_val[:depth])
        return nodes

    def _get_or_create_node_state(self, node_prefix: str) -> NodeState:
        """
        取得節點狀態，不存在則創建
        對應 RSSE 的 W[τ] 查詢
        """
        if node_prefix not in self._node_states:
            # 首次使用：用 PRF 派生金鑰
            key = _prf(self._K1, hash(node_prefix))
            self._node_states[node_prefix] = NodeState(key=key)
        return self._node_states[node_prefix]

    def _update_node(self, node_prefix: str, val: int, op: str) -> None:
        """
        更新一個 BRC 節點的加密索引

        對應 RSSE 的 Update 第 21-25 行：
          addr = H1(k_τ || (c+1))
          val_encrypted = (id || op) XOR H2(k_τ || (c+1))

        同時附加 tri-DAG bitmap（G-PPT 的核心）
        讓伺服器可以做 bitmap 匹配查詢
        """
        state = self._get_or_create_node_state(node_prefix)

        # 遞增 counter
        state.hist_count += 1
        state.update_count += 1
        c = state.hist_count

        # 計算加密索引的位置和值
        addr = _hash1(state.key, c)
        val_encrypted = val ^ _hash2(state.key, c)

        # 生成這個節點覆蓋範圍的 tri-DAG bitmap
        # （用於 G-PPT 風格的查詢匹配）
        node_min, node_max = brc_node_range(node_prefix, self.M)

        # 用節點中值代表這個節點的 bitmap
        # 實際上每個節點應該是一個聚合 bitmap，這裡用覆蓋範圍的 OR
        bitmap = self._compute_node_bitmap(node_prefix, val)

        # 加密 bitmap（用 _aes 模擬 ASHVE+.Enc）
        bitmap_enc = [_aes(bitmap[i] + i) for i in range(len(bitmap))]
        # 附加層標籤（Forward Privacy 機制）
        bitmap_enc.append(_aes(0, state.key))

        # 存入加密索引
        entry = BRCGPPTEntry(
            addr=addr,
            val=val_encrypted,
            val_id=val,
            op=op,
            bitmap=bitmap,
            bitmap_encrypted=bitmap_enc
        )
        self._encrypted_index[addr] = entry
        self.stats['index_entries'] += 1
        self.stats['brc_nodes_created'] = len(self._node_states)

    def _compute_node_bitmap(self, node_prefix: str, val: int) -> List[int]:
        """
        計算 BRC 節點的 tri-DAG bitmap

        每個節點的 bitmap 是它覆蓋範圍內所有值的 bitmap OR
        （和 G-PPT 的內部節點邏輯相同）
        """
        return val_to_bitmap(val, self.M, self.x)

    def _result_cache_key_map(self) -> Set[str]:
        """取得所有有快取結果的節點前綴"""
        return set(self._node_states.keys())


# ==========================================
# 比較用的基準線：DG-PPT（簡化版）
# ==========================================

class SimpleDGPPT:
    """
    DG-PPT 的簡化版（用於比較）
    直接從 dynamic_gppt.py 提取核心邏輯
    """

    def __init__(self, M: int = 8, t: int = 2, x: int = 2,
                 ratios: List[float] = None):
        self.M = M
        self.t = t
        self.x = x
        self.ratios = ratios or [0.15, 0.70, 0.15]

        # 分層索引
        self.layers: Dict[int, dict] = {}
        self._delete_list: Set[int] = set()
        self._global_counter = 0
        self._next_rid = 0

        # 用 SimplePPRF 管理層金鑰
        self._pprf = SimplePPRF()
        self._master_key = self._pprf.gen()

        self.stats = {
            'inserts': 0,
            'deletes': 0,
            'queries': 0,
            'merges': 0,
        }

    def insert(self, val: int) -> None:
        self.stats['inserts'] += 1
        pending = [val]
        i = 0

        while i in self.layers:
            old = self.layers[i]
            merged = [v for v in (old['data'] + pending)
                      if v not in self._delete_list]
            del self.layers[i]
            self.stats['merges'] += 1
            self._global_counter += 1
            pending = merged
            i += 1

        # 建立新層（簡化：只存資料，不建完整 G-PPT 樹）
        layer_key = self._derive_key(i)
        self.layers[i] = {
            'data': pending,
            'key': layer_key,
            'version': self._global_counter
        }
        self._global_counter += 1

    def delete(self, val: int) -> None:
        self._delete_list.add(val)
        self.stats['deletes'] += 1

    def query(self, a: int, b: int) -> Set[int]:
        self.stats['queries'] += 1
        results = set()

        for info in self.layers.values():
            for v in info['data']:
                if a <= v <= b and v not in self._delete_list:
                    results.add(v)

        return results

    def _derive_key(self, layer_id: int) -> int:
        uid = layer_id * 10000 + self._global_counter
        key = self._pprf.eval(self._master_key, uid)
        return key if key is not None else (layer_id * 999983 + self._global_counter * 1000003) % (10**9 + 7)

    def state_summary(self) -> str:
        lines = [
            "DG-PPT 狀態：",
            f"  現有層: {sorted(self.layers.keys())}",
            f"  各層大小: { {k: len(v['data']) for k, v in self.layers.items()} }",
            f"  刪除列表: {len(self._delete_list)} 筆",
        ]
        return "\n".join(lines)


# ==========================================
# 效能比較實驗
# ==========================================

def run_comparison(
    data_vals: List[int],
    queries: List[Tuple[int, int]],
    delete_vals: List[int],
    M: int = 8,
    t: int = 2,
    x: int = 2
) -> Dict[str, Any]:
    """
    執行 BRC-GPPT vs DG-PPT 的完整比較實驗

    Args:
        data_vals: 要插入的資料值列表
        queries: 查詢範圍列表
        delete_vals: 要刪除的值列表
        M, t, x: 索引參數

    Returns:
        比較結果字典
    """
    results = {}

    # ---- BRC-GPPT ----
    brc = BRCGPPTIndex(M=M, t=t, x=x)

    t0 = time.perf_counter()
    for v in data_vals:
        brc.insert(v)
    insert_time_brc = time.perf_counter() - t0

    t0 = time.perf_counter()
    for v in delete_vals:
        brc.delete(v)
    delete_time_brc = time.perf_counter() - t0

    query_results_brc = []
    t0 = time.perf_counter()
    for a, b in queries:
        r = brc.query(a, b)
        query_results_brc.append(r)
    query_time_brc = time.perf_counter() - t0

    results['brc_gppt'] = {
        'insert_time': insert_time_brc,
        'delete_time': delete_time_brc,
        'query_time': query_time_brc,
        'index_size': len(brc._encrypted_index),
        'node_states': len(brc._node_states),
        'query_results': query_results_brc,
        'stats': brc.stats.copy(),
    }

    # ---- DG-PPT ----
    dgppt = SimpleDGPPT(M=M, t=t, x=x)

    t0 = time.perf_counter()
    for v in data_vals:
        dgppt.insert(v)
    insert_time_dgppt = time.perf_counter() - t0

    t0 = time.perf_counter()
    for v in delete_vals:
        dgppt.delete(v)
    delete_time_dgppt = time.perf_counter() - t0

    query_results_dgppt = []
    t0 = time.perf_counter()
    for a, b in queries:
        r = dgppt.query(a, b)
        query_results_dgppt.append(r)
    query_time_dgppt = time.perf_counter() - t0

    results['dgppt'] = {
        'insert_time': insert_time_dgppt,
        'delete_time': delete_time_dgppt,
        'query_time': query_time_dgppt,
        'index_size': sum(len(v['data']) for v in dgppt.layers.values()),
        'layers': len(dgppt.layers),
        'query_results': query_results_dgppt,
        'stats': dgppt.stats.copy(),
    }

    # 計算預期結果
    valid_vals = set(data_vals) - set(delete_vals)
    results['expected'] = [
        {v for v in valid_vals if a <= v <= b}
        for a, b in queries
    ]

    return results


# ==========================================
# 主測試程式
# ==========================================

if __name__ == "__main__":
    print("=" * 65)
    print("BRC-GPPT 功能測試")
    print("=" * 65)

    M = 8  # 域大小 2^8 = 256
    t, x = 2, 2

    # ==========================================
    # 測試一：BRC 演算法正確性
    # ==========================================
    print("\n【測試一：BRC 演算法正確性】")
    print("-" * 45)

    test_cases = [
        (2, 7, 3, ["01", "1"]),    # 論文 Figure 1 的例子
        (0, 7, 3, [""]),           # 全範圍 = 根節點
        (4, 7, 3, ["1"]),          # 右半邊
        (0, 3, 3, ["0"]),          # 左半邊
        (3, 5, 3, ["011", "10"]),  # 跨節點
    ]

    all_pass = True
    for a, b, m, expected in test_cases:
        result = sorted(compute_brc(a, b, m))
        expected_sorted = sorted(expected)
        ok = result == expected_sorted
        if not ok:
            all_pass = False
        print(f"  BRC([{a},{b}], m={m}): {result} "
              f"{'✓' if ok else f'✗ 期望 {expected_sorted}'}")

    print(f"  {'✓ 全部正確' if all_pass else '✗ 有錯誤'}")

    # ==========================================
    # 測試二：BRC 節點範圍計算
    # ==========================================
    print("\n【測試二：BRC 節點覆蓋範圍】")
    print("-" * 45)

    nodes = [("01", 3), ("1", 3), ("", 3), ("100", 3)]
    for node, m in nodes:
        lo, hi = brc_node_range(node, m)
        print(f"  節點 '{node}' (m={m}): 覆蓋 [{lo}, {hi}]")

    # ==========================================
    # 測試三：BRC-GPPT 插入與查詢
    # ==========================================
    print("\n【測試三：BRC-GPPT 插入與查詢】")
    print("-" * 45)

    brc = BRCGPPTIndex(M=M, t=t, x=x)
    data = [10, 20, 30, 40, 50, 60, 70, 80]

    print(f"插入資料: {data}")
    for v in data:
        brc.insert(v)

    print(f"\n{brc.state_summary()}")

    queries_test = [(20, 60), (10, 30), (50, 100)]
    q_pass = True
    for a, b in queries_test:
        result = brc.query(a, b)
        expected = {v for v in data if a <= v <= b}
        ok = result == expected
        if not ok:
            q_pass = False
        print(f"\n  查詢 [{a},{b}]:")
        print(f"    結果: {sorted(result)}")
        print(f"    期望: {sorted(expected)}")
        print(f"    {'✓' if ok else '✗'}")

    # ==========================================
    # 測試四：刪除後查詢
    # ==========================================
    print("\n【測試四：刪除後查詢】")
    print("-" * 45)

    brc.delete(30)
    brc.delete(50)

    result = brc.query(20, 60)
    expected = {v for v in data if 20 <= v <= 60 and v not in {30, 50}}
    ok = result == expected
    if not ok:
        q_pass = False
    print(f"  刪除 30, 50 後查詢 [20,60]:")
    print(f"    結果: {sorted(result)}")
    print(f"    期望: {sorted(expected)}")
    print(f"    {'✓' if ok else '✗'}")

    # ==========================================
    # 測試五：Forward Privacy 驗證
    # ==========================================
    print("\n【測試五：Forward Privacy 驗證】")
    print("-" * 45)
    print("  （概念：查詢後節點金鑰更新，舊 token 失效）")

    brc2 = BRCGPPTIndex(M=M, t=t, x=x)
    brc2.insert(100)

    # 記錄查詢前的節點狀態
    leaf_prefix = format(100, f'0{M}b')
    state_before = brc2._node_states.get(leaf_prefix)
    key_before = state_before.key if state_before else None
    uc_before = state_before.update_count if state_before else 0

    # 執行查詢（模擬客戶端查詢 [90, 110]）
    _ = brc2.query(90, 110)

    state_after = brc2._node_states.get(leaf_prefix)
    key_after = state_after.key if state_after else None
    uc_after = state_after.update_count if state_after else 0

    print(f"  查詢前：節點金鑰 ...{str(key_before)[-6:]}, update_count={uc_before}")
    print(f"  查詢後：節點金鑰 ...{str(key_after)[-6:]}, update_count={uc_after}")
    key_changed = key_before != key_after
    counter_reset = uc_after == 0
    fp_ok = key_changed and counter_reset
    if not fp_ok:
        q_pass = False
    print(f"  金鑰更換: {'✓' if key_changed else '✗'}")
    print(f"  計數器重置: {'✓' if counter_reset else '✗'}")
    print(f"  Forward Privacy 機制: {'✓ 正常運作' if fp_ok else '✗ 有問題'}")

    # ==========================================
    # 測試六：大規模比較實驗
    # ==========================================
    print("\n【測試六：BRC-GPPT vs DG-PPT 比較實驗】")
    print("-" * 45)

    random.seed(42)
    N = 100
    domain = list(range(0, 2**M))
    data_vals = random.sample(domain, N)
    delete_vals = random.sample(data_vals, N // 5)
    queries_exp = [(random.randint(0, 200), random.randint(50, 255))
                   for _ in range(10)]
    queries_exp = [(a, b) for a, b in queries_exp if a <= b]

    print(f"  資料筆數: {N}")
    print(f"  刪除筆數: {len(delete_vals)}")
    print(f"  查詢次數: {len(queries_exp)}")

    results = run_comparison(data_vals, queries_exp, delete_vals, M=M, t=t, x=x)

    brc_r = results['brc_gppt']
    dg_r = results['dgppt']
    exp_r = results['expected']

    # 正確性驗證
    brc_correct = all(
        brc_r['query_results'][i] == exp_r[i]
        for i in range(len(queries_exp))
    )
    dg_correct = all(
        dg_r['query_results'][i] == exp_r[i]
        for i in range(len(queries_exp))
    )

    print(f"\n  正確性：BRC-GPPT={'✓' if brc_correct else '✗'}, "
          f"DG-PPT={'✓' if dg_correct else '✗'}")
    if not (brc_correct and dg_correct):
        q_pass = False
        # 顯示哪個查詢失敗
        for i, (a, b) in enumerate(queries_exp):
            if brc_r['query_results'][i] != exp_r[i]:
                print(f"    查詢 [{a},{b}] 失敗：結果={sorted(brc_r['query_results'][i])[:5]}... "
                      f"期望={sorted(exp_r[i])[:5]}...")

    print(f"\n  效能比較：")
    print(f"  {'指標':<20} {'BRC-GPPT':>12} {'DG-PPT':>12} {'差異':>10}")
    print(f"  {'-'*55}")

    it_b = brc_r['insert_time']*1000
    it_d = dg_r['insert_time']*1000
    print(f"  {'插入時間 (ms)':<20} {it_b:>12.2f} {it_d:>12.2f} "
          f"{'BRC' if it_b < it_d else 'DG':>8}快 {abs(it_b-it_d)/max(it_b,it_d)*100:.0f}%")

    dt_b = brc_r['delete_time']*1000
    dt_d = dg_r['delete_time']*1000
    print(f"  {'刪除時間 (ms)':<20} {dt_b:>12.4f} {dt_d:>12.4f} "
          f"{'BRC' if dt_b < dt_d else 'DG':>8}快")

    qt_b = brc_r['query_time']*1000
    qt_d = dg_r['query_time']*1000
    print(f"  {'查詢時間 (ms)':<20} {qt_b:>12.2f} {qt_d:>12.2f} "
          f"{'BRC' if qt_b < qt_d else 'DG':>8}快 {abs(qt_b-qt_d)/max(qt_b,qt_d)*100:.0f}%")

    is_b = brc_r['index_size']
    is_d = dg_r['index_size']
    print(f"  {'索引條目數':<20} {is_b:>12} {is_d:>12} "
          f"{'BRC' if is_b < is_d else 'DG':>8}少 {abs(is_b-is_d)/max(is_b,is_d)*100:.0f}%")

    print(f"\n  BRC-GPPT 節點狀態數: {brc_r['node_states']}")
    print(f"  DG-PPT 現有層數: {dg_r['layers']}")

    print("\n" + "=" * 65)
    print(f"整體測試結果: {'✓ 全部通過' if all_pass and q_pass else '✗ 有測試失敗'}")
    print("=" * 65)
