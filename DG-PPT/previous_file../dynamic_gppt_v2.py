"""
dynamic_gppt_v2.py
==================
動態 G-PPT，直接使用學長的真實模組：
  AES.aes / BT_DAG.dag_get_BT / dag_range_decomposition.dag_range_decomposition

和 v1 的差別（對應上一輪列出的問題）：
  1. 密文改成「帶層金鑰」：c[i] = aes(bit + i, K_layer)
     學長原版的 c[i] = aes(bit + i) 完全沒有金鑰，任何人窮舉 bit∈{0,1} 就能還原。
     帶金鑰後，層與層之間的隔離來自密碼運算本身，不再需要 v1 的「層標籤」。
  2. token 的 d0/d1 用「每個 token 全新的隨機 key_trap」，d1 不再是固定值。
  3. 客戶端 / 伺服器分離：伺服器節點只有密文、子節點與 rid。
  4. 刪除按 record id（rid），不再按值，所以「刪除後重新插入同值」是對的。
  5. 每次合併/建層前依 (值, rid) 排序，k-ary 樹的剪枝才有效。
  6. 不使用 PPRF（見檔尾說明）：層金鑰用 HMAC-SHA256(master, uid) 派生。

仍然是「功能與效能模擬」，不是安全實作：
  - aes() 是學長的 AES 模擬（把 4 個字相加壓成 32 bits），不是標準的 PRF 用法。
  - 沒有 ASHVE+ 的 nonce r（學長程式碼本來就沒有）。
"""
import hashlib
import hmac
import os
import random
from typing import Dict, List, Optional, Set, Tuple

from AES import aes
from BT_DAG import dag_get_BT
from dag_range_decomposition import dag_range_decomposition


# ------------------------------------------------------------
# 伺服器端資料結構：只有密文 + 結構 + rid
# ------------------------------------------------------------
class ServerNode:
    __slots__ = ("c", "children", "rid")

    def __init__(self):
        self.c: List[int] = []
        self.children: List["ServerNode"] = []
        self.rid: Optional[int] = None  # 只有葉節點有；內部節點為 None

    @property
    def is_leaf(self) -> bool:
        return self.rid is not None


def _or(bts: List[List[int]]) -> List[int]:
    out = [0] * len(bts[0])
    for bt in bts:
        for i, b in enumerate(bt):
            out[i] |= b
    return out


def _split(items: list, ratios: List[float]) -> List[list]:
    total, start, groups = len(items), 0, []
    for i, r in enumerate(ratios):
        cnt = (total - start) if i == len(ratios) - 1 else max(1, int(total * r))
        end = min(start + cnt, total)
        if end > start:
            groups.append(items[start:end])
        start = end
    return groups


def encrypt_bt(bt: List[int], key: int) -> List[int]:
    """c[i] = aes(bt[i] + i, key)：和學長相同的形式，但帶金鑰。"""
    return [aes(bt[i] + i, key) for i in range(len(bt))]


def build_layer(records: List[Tuple[int, int]], key: int, MAX: int, t: int,
                x: int, ratios: List[float]) -> ServerNode:
    """records: [(rid, value)]，建立一層 k-ary PPT（回傳伺服器端根節點）。"""
    records = sorted(records, key=lambda r: (r[1], r[0]))  # 依值排序

    def leaf(rid: int, val: int):
        bt = dag_get_BT(val, MAX, x)
        bt = bt + [i % 2 for i in range(t)]  # ASHVE 擴展位置（學長寫法）
        n = ServerNode()
        n.rid = rid
        n.c = encrypt_bt(bt, key)
        return n, bt

    def rec(items):
        if len(items) == 1:
            return leaf(*items[0])
        vals = {v for _, v in items}
        if len(vals) == 1:  # 全是重複值 → 直接把它們掛在一個內部節點下
            kids = [leaf(*it) for it in items]
        else:
            kids = [rec(g) for g in _split(items, ratios) if g]
        node = ServerNode()
        bt = _or([b for _, b in kids])
        node.c = encrypt_bt(bt, key)
        node.children = [n for n, _ in kids]
        return node, bt

    return rec(records)[0]



def btq_indices(q: Tuple[int, int], MAX: int, x: int) -> List[List[int]]:
    """每個覆蓋 token 回傳 bitmap 中值為 '1' 的位置索引（含各段的 root）。

    與學長的 dag_get_BTQ_list 輸出相同，差別只在分解步驟：
      dag_get_BTQ_list → gettoken：每個新查詢要建 2^(MAX+1) 個節點的樹，成本 O(2^MAX)，且有 lru_cache
      這裡 → dag_range_decomposition：遞迴分解，成本約 O(MAX)，沒有快取
    """
    s = MAX // x
    seg = (s + 1) * (s + 2) // 2
    out = []
    for tok in dag_range_decomposition(q, MAX):
        S, offset = [], 0
        for i in range(x):
            S.append(offset)  # 每段的 root 一定是 1
            lvl = pos = 0
            for bit in tok[s * i:s * (i + 1)]:
                if bit != "*":
                    lvl += 1
                    if bit == "1":
                        pos += 1
                    S.append(offset + lvl * (lvl + 1) // 2 + pos)
            offset += seg
        out.append(S)
    return out

# ------------------------------------------------------------
# Token 與匹配（形式同學長的 TokenGen / query，但帶層金鑰）
# ------------------------------------------------------------
def gen_token(q: Tuple[int, int], MAX: int, key: int, t: int, x: int):
    s = MAX // x
    L0 = x * ((s + 1) * (s + 2) // 2)  # 擴展位置之前的 bitmap 長度
    tokens = []
    for S_idx in btq_indices(q, MAX, x):
        key_trap = random.randint(1, 10**9)  # 每個 token 全新
        total = sum(aes(1 + i, key) for i in S_idx)
        S = list(S_idx)
        loc = random.randint(0, t - 1)
        S.append(L0 + loc)
        total += aes(loc % 2 + L0 + loc, key)
        tokens.append((total + key_trap, aes(0, key_trap), S))
    return tokens


def match(c: List[int], tokens) -> bool:
    for d0, d1, S in tokens:
        key_not = d0 - sum(c[i] for i in S)
        if aes(0, key_not) == d1:
            return True
    return False


def search_layer(node: ServerNode, tokens, out: List[int]) -> int:
    """回傳被造訪的節點數；匹配的葉節點把 rid 放進 out。"""
    visited = 1
    if match(node.c, tokens):
        if node.is_leaf:
            out.append(node.rid)
        else:
            for ch in node.children:
                visited += search_layer(ch, tokens, out)
    return visited


# ------------------------------------------------------------
# 客戶端：分層索引管理
# ------------------------------------------------------------
class DynamicGPPT:
    def __init__(self, MAX=8, t=2, x=2, ratios=None):
        assert MAX % x == 0
        self.MAX, self.t, self.x = MAX, t, x
        self.ratios = ratios or [0.15, 0.70, 0.15]
        self._master = os.urandom(32)
        self._uid = 0                    # 每建一層就遞增 → 每層金鑰唯一
        self._next_rid = 0
        # ---- 客戶端狀態（O(n)，這是此設計的主要代價）----
        self.values: Dict[int, int] = {}  # rid -> value
        self.deleted: Set[int] = set()
        # ---- 伺服器端（模擬）----
        self.layers: Dict[int, dict] = {}  # layer_id -> {root, key, rids}
        self.stats = {"merges": 0, "layer_builds": 0, "visited": 0}

    # 金鑰派生：K = HMAC(master, uid)，取 31 bits 當 aes 的 key_val
    def _derive(self, uid: int) -> int:
        h = hmac.new(self._master, str(uid).encode(), hashlib.sha256).digest()
        return int.from_bytes(h[:4], "big") & 0x7FFFFFFF

    def insert(self, val: int) -> int:
        assert 0 <= val < 2 ** self.MAX
        rid = self._next_rid
        self._next_rid += 1
        self.values[rid] = val

        pending = [rid]
        i = 0
        while i in self.layers:  # binary counter：往上找空層，沿途合併
            pending = self.layers.pop(i)["rids"] + pending
            self.stats["merges"] += 1
            i += 1
        pending = [r for r in pending if r not in self.deleted]  # 合併時真正清掉已刪除
        self._build(i, pending)
        return rid

    def _build(self, layer_id: int, rids: List[int]):
        if not rids:
            return
        self._uid += 1
        key = self._derive(self._uid)
        root = build_layer([(r, self.values[r]) for r in rids], key,
                           self.MAX, self.t, self.x, self.ratios)
        self.layers[layer_id] = {"root": root, "key": key, "rids": list(rids)}
        self.stats["layer_builds"] += 1

    def delete(self, rid: int) -> None:
        """Lazy deletion：只在客戶端標記；下次合併時才從索引中消失。"""
        if rid in self.values:
            self.deleted.add(rid)

    def query(self, q: Tuple[int, int]) -> Set[int]:
        """回傳符合範圍且未刪除的 rid 集合（客戶端再用 values 對應回值）。"""
        found: List[int] = []
        for info in self.layers.values():
            tokens = gen_token(q, self.MAX, info["key"], self.t, self.x)
            self.stats["visited"] += search_layer(info["root"], tokens, found)
        return {r for r in found if r not in self.deleted}

    def query_values(self, q) -> List[int]:
        return sorted(self.values[r] for r in self.query(q))

    # 便利函式（測試用）
    def live(self) -> Dict[int, int]:
        return {r: v for r, v in self.values.items() if r not in self.deleted}


# ------------------------------------------------------------
# 關於 PPRF（說明）
# ------------------------------------------------------------
# 這個設計的 Forward Privacy 來自「每次建層都用全新、互不相關的金鑰」，
# 舊 token 對新層的密文不會匹配（見 test_dynamic_v2.py 的實驗）。
# 上一版我把 PPRF 說成是達成 Forward Privacy 的核心，這是不準確的：
# 穿孔（puncture）解決的是「把金鑰委派給別人，但排除某些輸入」的問題，
# 在單一 DO/DU 的模型下用不到。多 DU 授權、撤銷 DU 時才會需要，之後再評估。
