"""
test_leakage.py
===============
驗證 dynamic_gppt_v2.py（動態 G-PPT）對「伺服器」洩漏了什麼。
每個測試對應洩漏函數裡的一項：

  L1  token 的 S 洩漏查詢範圍          → L_Srch 中的 cover(q)
  L2  葉節點順序 = 值的順序            → L_Updt 中的 ord(ℓ')
  L3  合併時新值的 rank 被洩漏          → L_Updt（forward privacy 的實質打折）
  L4  合併時被刪除的 rid 被洩漏         → L_Updt 中的 dropped(u)
  P1  （未洩漏）同一查詢的 token 不可連結 → d1 每次都不同
  P2  （未洩漏）舊 token 對新層不匹配    → 密文層面的 forward privacy

執行方式（需和學長的 AES.py、BT_DAG.py、dag_range_decomposition.py、
range_query_decomposition_v2.py 放在同一個資料夾）：
    python3 test_leakage.py

注意：這些測試是對「這份實作」的檢查，不是安全證明。
L1 檢查的是 token 格式本身；論文的安全遊戲是否對 q0、q1 有額外限制，請另行確認。
"""
import random
import sys
from math import isqrt

from dynamic_gppt_v2 import DynamicGPPT, gen_token, search_layer

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


# ------------------------------------------------------------
# 輔助：只用伺服器看得到的資訊（token 的 S、樹的結構）
# ------------------------------------------------------------
def decode_prefix(S, MAX, x):
    """由 token 的 S 還原前綴字串。tri-DAG 節點 idx = lvl(lvl+1)/2 + pos，
    pos = 目前為止走了幾個「1」，所以相鄰層的 pos 差就是該層的 bit。"""
    s = MAX // x
    seg = (s + 1) * (s + 2) // 2
    L0 = x * seg
    S = sorted(i for i in S if i < L0)  # 去掉 ASHVE 的額外位置
    bits = ""
    for k in range(x):
        nodes = [i - k * seg for i in S if k * seg <= i < (k + 1) * seg]
        prev = 0
        for idx in nodes:
            if idx == 0:  # root
                continue
            lvl = (isqrt(8 * idx + 1) - 1) // 2
            pos = idx - lvl * (lvl + 1) // 2
            bits += str(pos - prev)
            prev = pos
    return bits


def decode_range(tokens, MAX, x):
    lo, hi = 2 ** MAX, -1
    for _, _, S in tokens:
        p = decode_prefix(S, MAX, x)
        lo = min(lo, int(p + "0" * (MAX - len(p)), 2))
        hi = max(hi, int(p + "1" * (MAX - len(p)), 2))
    return lo, hi


def leaf_rids(node):
    """伺服器視角：由左到右的葉節點 rid。"""
    if node.is_leaf:
        return [node.rid]
    return [r for c in node.children for r in leaf_rids(c)]


def server_rids(idx):
    """伺服器目前存放的所有 rid。"""
    return {r for layer in idx.layers.values() for r in leaf_rids(layer["root"])}


# ------------------------------------------------------------
# L1：token 的 S 洩漏查詢範圍
# ------------------------------------------------------------
def test_L1_token_reveals_range(trials=300, MAX=8, x=2, t=2):
    random.seed(11)
    ok = 0
    for _ in range(trials):
        a = random.randint(0, 2 ** MAX - 1)
        b = random.randint(a, 2 ** MAX - 1)
        ok += decode_range(gen_token((a, b), MAX, 12345, t, x), MAX, x) == (a, b)
    record("L1 只看 token 的 S 就能還原查詢範圍", ok == trials, f"{ok}/{trials}")


# ------------------------------------------------------------
# L2：葉節點順序 = 值的順序
# ------------------------------------------------------------
def test_L2_leaf_order_is_value_order():
    all_ok = True
    for seed in range(5):
        random.seed(seed)
        d = DynamicGPPT(MAX=8)
        val_of = {}
        for v in [random.randint(0, 255) for _ in range(16)]:  # 16 筆 → 單一層
            val_of[d.insert(v)] = v
        assert len(d.layers) == 1
        seq = [val_of[r] for r in leaf_rids(next(iter(d.layers.values()))["root"])]
        all_ok &= seq == sorted(seq)
    record("L2 葉節點由左到右的 rid 對應的值為由小到大", all_ok, "5 個隨機種子")


# ------------------------------------------------------------
# L3：合併時新值的 rank 被洩漏
# ------------------------------------------------------------
def test_L3_rank_leak_on_merge():
    random.seed(5)
    pool = [v for v in range(256) if v != 100]
    old_vals = random.sample(pool, 15)  # 15 = 0b1111，下一次插入會合併成單一層
    d = DynamicGPPT(MAX=8)
    val_of = {}
    for v in old_vals:
        val_of[d.insert(v)] = v
    new_rid = d.insert(100)
    val_of[new_rid] = 100
    merged = len(d.layers) == 1
    order = leaf_rids(next(iter(d.layers.values()))["root"])
    p = order.index(new_rid)
    left = val_of[order[p - 1]] if p > 0 else None
    right = val_of[order[p + 1]] if p + 1 < len(order) else None
    true_left = max((v for v in old_vals if v < 100), default=None)
    true_right = min((v for v in old_vals if v > 100), default=None)
    ok = merged and left == true_left and right == true_right
    record("L3 合併後，新 rid 在葉序中的左右鄰就是值的前驅與後繼", ok,
           f"新值 100 的鄰居 = ({left}, {right})")


# ------------------------------------------------------------
# L4：合併時被刪除的 rid 被洩漏；刪除當下不洩漏
# ------------------------------------------------------------
def test_L4_dropped_rids_visible_on_merge():
    d = DynamicGPPT(MAX=8)
    rids = [d.insert(v) for v in (10, 20, 30)]  # 層 1 與層 0
    before_delete = server_rids(d)
    d.delete(rids[0])
    after_delete = server_rids(d)  # 刪除當下，伺服器端沒有任何變化
    d.insert(40)  # 觸發合併
    after_merge = server_rids(d)
    vanished = before_delete - after_merge
    ok = (before_delete == after_delete) and vanished == {rids[0]}
    record("L4 刪除當下伺服器無變化，合併後消失的 rid = 被刪除的 rid", ok,
           f"消失的 rid = {sorted(vanished)}")


# ------------------------------------------------------------
# P1：未洩漏 —— 同一查詢的 token 不可由 d1 連結
# ------------------------------------------------------------
def test_P1_tokens_unlinkable_by_d1(MAX=8, x=2, t=2):
    t1 = gen_token((10, 50), MAX, 12345, t, x)
    t2 = gen_token((10, 50), MAX, 12345, t, x)
    ok = all(a[1] != b[1] for a, b in zip(t1, t2))
    record("P1 同一查詢兩次產生的 token，d1 全部不同", ok)


# ------------------------------------------------------------
# P2：未洩漏 —— 舊 token 對合併後的新層不匹配
# ------------------------------------------------------------
def test_P2_old_token_misses_new_layer():
    d = DynamicGPPT(MAX=8)
    d.insert(100)
    layer0 = d.layers[0]
    old_token = gen_token((90, 110), 8, layer0["key"], 2, 2)
    hit_old = []
    search_layer(layer0["root"], old_token, hit_old)
    d.insert(105)  # 合併 → 新層、新金鑰
    new_layer = next(iter(d.layers.values()))
    hit_new = []
    search_layer(new_layer["root"], old_token, hit_new)
    ok = len(hit_old) == 1 and hit_new == []
    record("P2 舊 token 能匹配舊層，但對合併後的新層匹配不到", ok,
           f"舊層命中 {hit_old}，新層命中 {hit_new}")


if __name__ == "__main__":
    test_L1_token_reveals_range()
    test_L2_leaf_order_is_value_order()
    test_L3_rank_leak_on_merge()
    test_L4_dropped_rids_visible_on_merge()
    test_P1_tokens_unlinkable_by_d1()
    test_P2_old_token_misses_new_layer()

    print("\n" + "=" * 60)
    print("L 開頭 = 確認「有洩漏」；P 開頭 = 確認「沒有洩漏」。PASS 代表現象如預期。")
    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"結果：{len(RESULTS) - len(failed)}/{len(RESULTS)} 項如預期")
    sys.exit(1 if failed else 0)
