"""
pprf.py
=======
Puncturable Pseudorandom Function (PPRF) 實作
基於 GGM 樹結構

核心概念：
  - GGM 樹：用 HMAC-SHA256 模擬 PRG，建立一棵二元樹
  - Eval：從根節點沿著輸入 bits 走到葉節點
  - Puncture：收集「到達 x* 路徑上所有兄弟節點」
              讓持有人可以計算所有 x ≠ x* 的輸出
              但無法計算 x* 的輸出

在 DG-PPT 裡的用途：
  - 每一層的金鑰由主金鑰 K_master 派生
  - 層消失後，對 K_master 做 Puncture
  - 確保舊的查詢 token 無法匹配新插入的資料
  - 達到 Forward Privacy
"""

import hmac
import hashlib
import os
from typing import List, Tuple, Optional


# ==========================================
# 底層 PRG（偽隨機數生成器）
# ==========================================

def _prg(seed: bytes, direction: int) -> bytes:
    """
    用 HMAC-SHA256 模擬 PRG

    把一個種子擴展成新的偽隨機位元串
    direction = 0：往左走（左子節點）
    direction = 1：往右走（右子節點）

    Args:
        seed: 當前節點的值（bytes）
        direction: 0 或 1

    Returns:
        子節點的值（bytes）
    """
    h = hmac.new(
        seed,
        msg=direction.to_bytes(1, 'big'),
        digestmod=hashlib.sha256
    )
    return h.digest()


def _int_to_bits(n: int, length: int) -> List[int]:
    """
    把整數轉成固定長度的 bits 列表

    Args:
        n: 整數
        length: bits 長度

    Returns:
        bits 列表，高位在前

    Example:
        _int_to_bits(5, 4) → [0, 1, 0, 1]
    """
    bits = []
    for i in range(length - 1, -1, -1):
        bits.append((n >> i) & 1)
    return bits


# ==========================================
# PPRF 主要函式
# ==========================================

class PPRF:
    """
    Puncturable PRF 基於 GGM 樹

    用法：
        pprf = PPRF(depth=10)           # 支援 2^10 個不同輸入
        K = pprf.gen()                  # 產生主金鑰
        y = pprf.eval(K, 5)             # 計算輸入 5 的輸出
        K_p = pprf.puncture(K, [5])     # 穿孔輸入 5
        y2 = pprf.eval_punctured(K_p, 3)  # 用穿孔金鑰計算輸入 3
    """

    def __init__(self, depth: int = 10):
        """
        Args:
            depth: GGM 樹的深度，支援 2^depth 個不同輸入
                   在 DG-PPT 裡，depth = ceil(log2(最大層數))
                   例如最多 1024 筆資料 → 最多 10 層 → depth = 4 就夠
        """
        self.depth = depth

    def gen(self) -> bytes:
        """
        產生隨機主金鑰

        Returns:
            32 bytes 的隨機金鑰
        """
        return os.urandom(32)

    def eval(self, key: bytes, x: int) -> bytes:
        """
        計算 PPRF(key, x)

        從根節點出發，按照 x 的 bits 往下走到葉節點

        Args:
            key: 主金鑰（或完整的未穿孔金鑰）
            x: 輸入值（整數）

        Returns:
            葉節點的值（bytes），作為派生金鑰

        Example:
            K = pprf.gen()
            layer_key = pprf.eval(K, layer_id)
        """
        bits = _int_to_bits(x, self.depth)
        current = key
        for bit in bits:
            current = _prg(current, bit)
        return current

    def puncture(self, key: bytes, puncture_set: List[int]) -> List[dict]:
        """
        穿孔金鑰：收集「可計算所有 x ∉ puncture_set 的資訊」

        對每個要穿孔的輸入 x*：
          沿著 x* 的路徑從根往下走
          在每一層，記錄「兄弟節點」的值和它負責的子樹前綴
          這些兄弟節點合在一起可以覆蓋所有 x ≠ x* 的路徑
          但無法計算 x* 本身

        Args:
            key: 原始主金鑰
            puncture_set: 要穿孔的輸入集合（整數列表）

        Returns:
            穿孔後的金鑰：一組 {node_value, prefix, depth} 的列表

        Note:
            穿孔多個點時，會合併所有點的兄弟節點集合
            並移除被覆蓋的冗餘節點
        """
        if not puncture_set:
            # 沒有要穿孔的點，回傳一個能計算所有值的完整表示
            return [{'node': key, 'prefix': [], 'node_depth': 0}]

        # 對每個要穿孔的點，收集兄弟節點
        all_siblings = []
        for x_star in puncture_set:
            siblings = self._collect_siblings(key, x_star)
            all_siblings.extend(siblings)

        # 去除冗餘節點（被其他節點的子樹覆蓋的節點）
        cleaned = self._remove_redundant(all_siblings, puncture_set)

        return cleaned

    def eval_punctured(self, punctured_key: List[dict], x: int) -> Optional[bytes]:
        """
        用穿孔金鑰計算 x 的輸出（x 不能是被穿孔的點）

        尋找 punctured_key 裡哪個兄弟節點的前綴是 x 路徑的前綴
        從那個節點繼續往下走剩餘的路徑

        Args:
            punctured_key: pprf.puncture() 的輸出
            x: 要計算的輸入（不能是被穿孔的點）

        Returns:
            計算結果（bytes），如果 x 是被穿孔的點則回傳 None
        """
        bits = _int_to_bits(x, self.depth)

        for entry in punctured_key:
            prefix = entry['prefix']
            node = entry['node']
            node_depth = entry['node_depth']

            # 檢查 x 的路徑是否以這個前綴開頭
            if bits[:node_depth] == prefix:
                # 從這個節點繼續走剩餘的 bits
                remaining = bits[node_depth:]
                current = node
                for bit in remaining:
                    current = _prg(current, bit)
                return current

        # 找不到對應的節點 → x 是被穿孔的點
        return None

    def _collect_siblings(self, key: bytes, x_star: int) -> List[dict]:
        """
        收集穿孔 x* 所需的兄弟節點

        Args:
            key: 主金鑰
            x_star: 要穿孔的輸入

        Returns:
            兄弟節點列表

        Example（depth=3, x*=101）：
            深度 1：x* 走右（1），兄弟是左子節點 K_0
                   prefix = [0], depth = 1
            深度 2：x* 走左（0），兄弟是右子節點 K_11
                   prefix = [1, 1], depth = 2
            深度 3：x* 走右（1），兄弟是左子節點 K_100
                   prefix = [1, 0, 0], depth = 3
        """
        bits = _int_to_bits(x_star, self.depth)
        siblings = []
        current = key

        for depth_idx, bit in enumerate(bits):
            # 兄弟節點走相反方向
            sibling_bit = 1 - bit
            sibling_node = _prg(current, sibling_bit)

            # 兄弟節點的前綴：到這一層為止，最後一個 bit 換成兄弟的方向
            sibling_prefix = bits[:depth_idx] + [sibling_bit]

            siblings.append({
                'node': sibling_node,
                'prefix': sibling_prefix,
                'node_depth': depth_idx + 1
            })

            # 繼續往 x* 的方向走
            current = _prg(current, bit)

        return siblings

    def _remove_redundant(
        self,
        siblings: List[dict],
        puncture_set: List[int]
    ) -> List[dict]:
        """
        移除冗餘節點

        當穿孔多個點時，某些兄弟節點可能包含被穿孔點的路徑
        這些節點需要被它們的子節點取代

        Args:
            siblings: 所有收集到的兄弟節點
            puncture_set: 被穿孔的輸入集合

        Returns:
            清理後的節點列表
        """
        # 把所有被穿孔點的 bits 路徑算出來
        puncture_bits = [
            _int_to_bits(x, self.depth) for x in puncture_set
        ]

        cleaned = []
        for entry in siblings:
            prefix = entry['prefix']
            node_depth = entry['node_depth']

            # 檢查這個節點的子樹是否包含任何被穿孔的點
            covers_punctured = False
            for pb in puncture_bits:
                if pb[:node_depth] == prefix:
                    covers_punctured = True
                    break

            if not covers_punctured:
                cleaned.append(entry)

        # 去除重複的前綴
        seen_prefixes = set()
        unique_cleaned = []
        for entry in cleaned:
            prefix_key = tuple(entry['prefix'])
            if prefix_key not in seen_prefixes:
                seen_prefixes.add(prefix_key)
                unique_cleaned.append(entry)

        return unique_cleaned

    def bytes_to_int(self, b: bytes, mod: int = 10**9 + 7) -> int:
        """
        把 PPRF 輸出的 bytes 轉成整數金鑰

        Args:
            b: PPRF 輸出（bytes）
            mod: 取模值，確保金鑰在合理範圍內

        Returns:
            整數金鑰
        """
        return int.from_bytes(b, 'big') % mod


# ==========================================
# 簡化版 PPRF（不需要穿孔時使用）
# ==========================================

class SimplePPRF:
    """
    簡化版 PPRF：只用 HMAC 派生金鑰，不實作完整穿孔機制

    適合用在：
      - 原型實作階段
      - 只需要金鑰獨立性，不需要嚴格 Forward Privacy 證明的情況

    在你的專題裡：
      - 第一版實作先用這個
      - 之後換成完整 PPRF 做安全性分析
    """

    def __init__(self):
        self.punctured = set()  # 記錄哪些輸入被穿孔了

    def gen(self) -> bytes:
        return os.urandom(32)

    def eval(self, key: bytes, x: int) -> int:
        """
        用 HMAC 把 (key, x) 映射到一個整數金鑰

        Args:
            key: 主金鑰（bytes）
            x: 層的識別符（整數）

        Returns:
            整數金鑰，用於 ASHVE+ 加密
        """
        if x in self.punctured:
            return None  # 被穿孔的點無法計算

        h = hmac.new(
            key,
            msg=str(x).encode(),
            digestmod=hashlib.sha256
        )
        return int(h.hexdigest(), 16) % (10**9 + 7)

    def puncture(self, key: bytes, x: int) -> bytes:
        """
        穿孔輸入 x：之後無法計算 eval(key, x)

        Args:
            key: 主金鑰
            x: 要穿孔的輸入

        Returns:
            同一把 key（簡化版不實際修改金鑰結構）
        """
        self.punctured.add(x)
        return key  # 簡化版直接記錄在 self.punctured


# ==========================================
# 測試
# ==========================================

if __name__ == "__main__":
    print("=" * 60)
    print("PPRF 測試")
    print("=" * 60)

    pprf = PPRF(depth=4)  # 支援 0~15 的輸入

    # 產生主金鑰
    K = pprf.gen()
    print(f"\n[1] 主金鑰: {K.hex()[:16]}...")

    # 計算幾個值
    print("\n[2] 計算 PPRF 輸出：")
    for x in [0, 3, 5, 7, 10]:
        y = pprf.eval(K, x)
        y_int = pprf.bytes_to_int(y)
        print(f"  PPRF(K, {x:2d}) = {y.hex()[:12]}... → int: {y_int}")

    # 穿孔 x* = 5
    print("\n[3] 穿孔 x* = 5：")
    K_punctured = pprf.puncture(K, [5])
    print(f"  穿孔後金鑰包含 {len(K_punctured)} 個節點")

    # 用穿孔金鑰計算其他值（應該和原來一樣）
    print("\n[4] 用穿孔金鑰計算（應和原值相同）：")
    all_correct = True
    for x in [0, 3, 7, 10]:
        y_orig = pprf.eval(K, x)
        y_punct = pprf.eval_punctured(K_punctured, x)
        match = y_orig == y_punct
        if not match:
            all_correct = False
        print(f"  x={x:2d}: 原值={y_orig.hex()[:8]}... "
              f"穿孔後={y_punct.hex()[:8]}... "
              f"{'✓ 相同' if match else '✗ 不同'}")

    # 嘗試計算被穿孔的點（應該失敗）
    print("\n[5] 嘗試計算被穿孔的 x*=5（應該失敗）：")
    y_star = pprf.eval_punctured(K_punctured, 5)
    print(f"  結果: {y_star} "
          f"{'✓ 正確（無法計算）' if y_star is None else '✗ 錯誤（不應計算出值）'}")

    print("\n[6] 穿孔多個點 [3, 7]：")
    K_multi = pprf.puncture(K, [3, 7])
    for x in range(10):
        y = pprf.eval_punctured(K_multi, x)
        if x in [3, 7]:
            status = "✓ 無法計算（正確）" if y is None else "✗ 錯誤"
        else:
            orig = pprf.eval(K, x)
            status = "✓ 正確" if y == orig else "✗ 不同"
        print(f"  x={x}: {status}")

    print("\n" + "=" * 60)
    print("SimplePPRF 測試（原型版本）")
    print("=" * 60)

    simple = SimplePPRF()
    K2 = simple.gen()

    print("\n[1] 各層金鑰派生：")
    for layer_id in range(5):
        key = simple.eval(K2, layer_id)
        print(f"  Layer {layer_id} 金鑰: {key}")

    print("\n[2] 穿孔 Layer 1 後：")
    K2 = simple.puncture(K2, 1)
    for layer_id in range(5):
        key = simple.eval(K2, layer_id)
        status = "（無法計算，已穿孔）" if key is None else f"{key}"
        print(f"  Layer {layer_id} 金鑰: {status}")
