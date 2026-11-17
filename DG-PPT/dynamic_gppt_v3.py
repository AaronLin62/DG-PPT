"""
dynamic_gppt_v3.py
==================
動態 G-PPT,把 v2 的 aes() 加密換成 ashve_plus.py 的 ASHVE+。

和 v2 的差別
------------
                 v2                                    v3
  加密           c[i] = aes(bit + i, 層金鑰)            ASHVE+.Enc(msk_層, bitmap)
  層金鑰         HMAC 取 31 bits,當 aes 的明文字使用     HMAC-SHA256(master, uid) 的完整 32 bytes,當 ASHVE+ 的 msk
  token          d0 = Σaes + key_trap、d1 = aes(0,…)    ASHVE+.GenKey:XOR、d1 = Sym.Enc(K, 0…0)
  nonce r        沒有                                   有,nonce_mode 可選(見 ashve_plus.py)
  額外位置       i % 2、固定加 1 個                      H(j)、S2 隨機選使 |S| 為偶數

解決的問題:A1(密文沒有金鑰)、A2(沒有 nonce)、B8(31 位元金鑰可窮舉)。
沒有改變的部分:分層方式(binary counter)、lazy deletion、排序建樹、
tri-DAG 編碼與範圍分解(仍用學長的 dag_get_BT、dag_range_decomposition)。
所以 v2 的洩漏 L1–L4(查詢範圍、葉序、合併時的名次與被刪除的 rid)在 v3 仍然存在。

nonce_mode(對應問題 A5,等學長回覆)
  "per_node"  【論文 VI-B Theorem 1 證明的說法】每個節點各自取新的 r。預設值。
  "per_build" 【論文 IV-C ASHVE+ 小節的說法】同一次建層(= 一次 IndexBuild)共用一個 r。
DG-PPT 每次合併都是一次建層,所以 per_build 下每一層各自共用一個 r。
"""
import hashlib
import hmac
import os
from typing import Dict, List, Optional, Set, Tuple

from ashve_plus import ASHVEPlus, Ciphertext, Token
from BT_DAG import dag_get_BT
from dynamic_gppt_v2 import _or, _split, btq_indices


def bitmap_len(MAX: int, x: int) -> int:
    """擴展位置之前的 bitmap 長度 L0 = x·(s+1)(s+2)/2。"""
    s = MAX // x
    return x * (s + 1) * (s + 2) // 2


# ------------------------------------------------------------
# 伺服器端資料結構:只有密文 + 結構 + rid
# ------------------------------------------------------------
class ServerNode:
    __slots__ = ("ct", "children", "rid")

    def __init__(self):
        self.ct: Optional[Ciphertext] = None
        self.children: List["ServerNode"] = []
        self.rid: Optional[int] = None  # 只有葉節點有

    @property
    def is_leaf(self) -> bool:
        return self.rid is not None


def build_layer(records: List[Tuple[int, int]], scheme: ASHVEPlus, MAX: int,
                x: int, ratios: List[float]) -> ServerNode:
    """records: [(rid, value)]。建一層 k-ary PPT,每個節點用 ASHVE+ 加密。
    整層是一次 IndexBuild:nonce 依 scheme.nonce_mode 決定共用或每節點新取。"""
    ctx = scheme.begin_build()
    records = sorted(records, key=lambda r: (r[1], r[0]))  # 依值排序,剪枝才有效

    def leaf(rid: int, val: int):
        bt = dag_get_BT(val, MAX, x)  # 額外位置由 ASHVE+ 內部補 H(1)…H(t)
        n = ServerNode()
        n.rid = rid
        n.ct = ctx.enc(bt)
        return n, bt

    def rec(items):
        if len(items) == 1:
            return leaf(*items[0])
        if len({v for _, v in items}) == 1:  # 全是重複值
            kids = [leaf(*it) for it in items]
        else:
            kids = [rec(g) for g in _split(items, ratios) if g]
        node = ServerNode()
        bt = _or([b for _, b in kids])
        node.ct = ctx.enc(bt)
        node.children = [n for n, _ in kids]
        return node, bt

    return rec(records)[0]


# ------------------------------------------------------------
# Token 與查詢
# ------------------------------------------------------------
def gen_token(q: Tuple[int, int], MAX: int, scheme: ASHVEPlus, x: int) -> List[Token]:
    """覆蓋 q 的每個前綴各產生一個 ASHVE+ token(謂詞:這些位置都是 1)。"""
    return [scheme.gen_key({i: 1 for i in S}) for S in btq_indices(q, MAX, x)]


def match(ct: Ciphertext, tokens: List[Token]) -> bool:
    return any(ASHVEPlus.query(tk, ct) for tk in tokens)


def search_layer(node: ServerNode, tokens: List[Token], out: List[int]) -> int:
    """回傳被造訪的節點數;匹配的葉節點把 rid 放進 out。"""
    visited = 1
    if match(node.ct, tokens):
        if node.is_leaf:
            out.append(node.rid)
        else:
            for ch in node.children:
                visited += search_layer(ch, tokens, out)
    return visited


# ------------------------------------------------------------
# 客戶端:分層索引管理
# ------------------------------------------------------------
class DynamicGPPT:
    def __init__(self, MAX=8, t=2, x=2, ratios=None, nonce_mode="per_node"):
        assert MAX % x == 0, "m 必須能被 x 整除(問題 A6)"
        self.MAX, self.t, self.x = MAX, t, x
        self.ratios = ratios or [0.15, 0.70, 0.15]
        self.nonce_mode = nonce_mode
        self.n = bitmap_len(MAX, x)
        self._master = os.urandom(32)
        self._uid = 0
        self._next_rid = 0
        # ---- 客戶端狀態(O(n))----
        self.values: Dict[int, int] = {}
        self.deleted: Set[int] = set()
        # ---- 伺服器端(模擬)----
        # layers[i] = {"root": 伺服器端根節點, "scheme": 該層的 ASHVE+(含 msk,屬於客戶端祕密), "rids": [...]}
        self.layers: Dict[int, dict] = {}
        self.stats = {"merges": 0, "layer_builds": 0, "visited": 0}

    def _layer_scheme(self, uid: int) -> ASHVEPlus:
        """層的 msk = HMAC-SHA256(master, uid),完整 32 bytes。"""
        msk = hmac.new(self._master, b"layer|" + str(uid).encode(), hashlib.sha256).digest()
        return ASHVEPlus(self.n, self.t, msk=msk, nonce_mode=self.nonce_mode)

    def insert(self, val: int) -> int:
        assert 0 <= val < 2 ** self.MAX
        rid = self._next_rid
        self._next_rid += 1
        self.values[rid] = val
        pending, i = [rid], 0
        while i in self.layers:  # binary counter:往上找空層,沿途合併
            pending = self.layers.pop(i)["rids"] + pending
            self.stats["merges"] += 1
            i += 1
        pending = [r for r in pending if r not in self.deleted]
        self._build(i, pending)
        return rid

    def _build(self, layer_id: int, rids: List[int]):
        if not rids:
            return
        self._uid += 1
        scheme = self._layer_scheme(self._uid)
        root = build_layer([(r, self.values[r]) for r in rids], scheme,
                           self.MAX, self.x, self.ratios)
        self.layers[layer_id] = {"root": root, "scheme": scheme, "rids": list(rids)}
        self.stats["layer_builds"] += 1

    def delete(self, rid: int) -> None:
        """Lazy deletion:只在客戶端標記;下次合併時才從索引中消失。"""
        if rid in self.values:
            self.deleted.add(rid)

    def query(self, q: Tuple[int, int]) -> Set[int]:
        found: List[int] = []
        for info in self.layers.values():
            tokens = gen_token(q, self.MAX, info["scheme"], self.x)
            self.stats["visited"] += search_layer(info["root"], tokens, found)
        return {r for r in found if r not in self.deleted}

    def query_values(self, q) -> List[int]:
        return sorted(self.values[r] for r in self.query(q))

    def live(self) -> Dict[int, int]:
        return {r: v for r, v in self.values.items() if r not in self.deleted}
