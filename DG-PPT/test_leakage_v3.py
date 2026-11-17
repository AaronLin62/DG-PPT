"""
test_leakage_v3.py
==================
在 dynamic_gppt_v3.py(ASHVE+ 版)上重跑 test_leakage.py 的 6 項,並新增 4 項。
預設 nonce_mode="per_node"【論文 VI-B Theorem 1 證明的說法】;
L5 另外用 "per_build"【論文 IV-C ASHVE+ 小節的說法】做對照。

沿用 v2 的 6 項(預期結果與 v2 相同,因為洩漏來自編碼與分層方式,不是加密):
  L1  token 的 S 洩漏查詢範圍          → L_Srch 中的 cover(q)
  L2  葉節點順序 = 值的順序            → L_Updt 中的 ord(ℓ')
  L3  合併時新值的名次被洩漏            → forward privacy 打折
  L4  合併時被刪除的 rid 被洩漏         → L_Updt 中的 dropped(u)
  P1  (未洩漏)同一查詢的 token 不可由 d1 連結
  P2  (未洩漏)舊 token 對合併後的新層不匹配

新增(ASHVE+ 帶來的差異):
  P3  (未洩漏)沒有 msk 無法窮舉還原 bitmap        ← v2 會洩漏(問題 A1、B8)
  P4  (未洩漏)per_node 下,同一層內重複值的密文不同
  L5  per_build 下,同一層內重複值的密文相同         → 對照組:per_build 會洩漏「哪些值相同」
  P5  (未洩漏)同一個值在不同層的密文不同(兩種模式皆然)

執行方式:與 ashve_plus.py、dynamic_gppt_v2.py、dynamic_gppt_v3.py 及學長的模組放同一資料夾
    python3 test_leakage_v3.py
"""
import os
import random
import sys

from ashve_plus import ASHVEPlus, F, _encode
from dynamic_gppt_v3 import DynamicGPPT, gen_token, search_layer
from test_leakage import decode_prefix, leaf_rids, server_rids

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def decode_range(tokens, MAX, x):
    lo, hi = 2 ** MAX, -1
    for tk in tokens:
        p = decode_prefix(tk.S, MAX, x)
        lo = min(lo, int(p + "0" * (MAX - len(p)), 2))
        hi = max(hi, int(p + "1" * (MAX - len(p)), 2))
    return lo, hi


def new_scheme(MAX=8, x=2, t=2, mode="per_node"):
    s = MAX // x
    return ASHVEPlus(x * (s + 1) * (s + 2) // 2, t, nonce_mode=mode)


def leaves(node):
    if node.is_leaf:
        return [node]
    return [l for c in node.children for l in leaves(c)]


# ---------------- 沿用 v2 的 6 項 ----------------
def test_L1(trials=300, MAX=8, x=2):
    rnd = random.Random(11)
    sch = new_scheme(MAX, x)
    ok = 0
    for _ in range(trials):
        a = rnd.randint(0, 2 ** MAX - 1)
        b = rnd.randint(a, 2 ** MAX - 1)
        ok += decode_range(gen_token((a, b), MAX, sch, x), MAX, x) == (a, b)
    record("L1 只看 token 的 S 就能還原查詢範圍", ok == trials, f"{ok}/{trials}")


def test_L2():
    all_ok = True
    for seed in range(5):
        rnd = random.Random(seed)
        d = DynamicGPPT(MAX=8)
        val_of = {}
        for v in [rnd.randint(0, 255) for _ in range(16)]:
            val_of[d.insert(v)] = v
        seq = [val_of[r] for r in leaf_rids(next(iter(d.layers.values()))["root"])]
        all_ok &= len(d.layers) == 1 and seq == sorted(seq)
    record("L2 葉節點由左到右的值由小到大", all_ok, "5 個隨機種子")


def test_L3():
    rnd = random.Random(5)
    old_vals = rnd.sample([v for v in range(256) if v != 100], 15)
    d = DynamicGPPT(MAX=8)
    val_of = {}
    for v in old_vals:
        val_of[d.insert(v)] = v
    new_rid = d.insert(100)
    val_of[new_rid] = 100
    order = leaf_rids(next(iter(d.layers.values()))["root"])
    p = order.index(new_rid)
    left = val_of[order[p - 1]] if p > 0 else None
    right = val_of[order[p + 1]] if p + 1 < len(order) else None
    ok = len(d.layers) == 1 and left == max(v for v in old_vals if v < 100) \
        and right == min(v for v in old_vals if v > 100)
    record("L3 合併後,新 rid 的左右鄰就是值的前驅與後繼", ok, f"新值 100 的鄰居 = ({left}, {right})")


def test_L4():
    d = DynamicGPPT(MAX=8)
    rids = [d.insert(v) for v in (10, 20, 30)]
    before = server_rids(d)
    d.delete(rids[0])
    after_delete = server_rids(d)
    d.insert(40)
    vanished = before - server_rids(d)
    record("L4 刪除當下伺服器無變化,合併後消失的 rid = 被刪除的 rid",
           before == after_delete and vanished == {rids[0]}, f"消失的 rid = {sorted(vanished)}")


def test_P1():
    sch = new_scheme()
    t1, t2 = gen_token((10, 50), 8, sch, 2), gen_token((10, 50), 8, sch, 2)
    ok = all(a.d1 != b.d1 and a.d0 != b.d0 for a, b in zip(t1, t2))
    record("P1 同一查詢兩次產生的 token,d0、d1 全部不同", ok)


def test_P2():
    d = DynamicGPPT(MAX=8)
    d.insert(100)
    layer0 = d.layers[0]
    old_token = gen_token((90, 110), 8, layer0["scheme"], 2)
    hit_old, hit_new = [], []
    search_layer(layer0["root"], old_token, hit_old)
    d.insert(105)
    search_layer(next(iter(d.layers.values()))["root"], old_token, hit_new)
    record("P2 舊 token 能匹配舊層,但對合併後的新層匹配不到",
           len(hit_old) == 1 and hit_new == [], f"舊層命中 {hit_old},新層命中 {hit_new}")


# ---------------- 新增 ----------------
def test_P3(guesses=200):
    """攻擊者知道公開參數與 r,但沒有 msk:用猜的金鑰窮舉每個位置的 bit。"""
    d = DynamicGPPT(MAX=8)
    for v in (3, 77, 150, 201):
        d.insert(v)
    leaf = leaves(next(iter(d.layers.values()))["root"])[0]
    ct, n = leaf.ct, d.n
    hits = 0
    for _ in range(guesses):
        g = os.urandom(32)
        mask = F(g, b"nonce|" + ct.r)
        for l in range(n):
            for b in (0, 1):
                hits += bytes(p ^ q for p, q in zip(F(g, _encode(b, l)), mask)) == ct.c[l]
    record("P3 沒有 msk 無法窮舉還原 bitmap", hits == 0,
           f"{guesses} 把猜測金鑰 × {n} 個位置,猜中 {hits} 次(v2 可全部還原)")


def dup_leaf_ct_equal(mode):
    d = DynamicGPPT(MAX=8, nonce_mode=mode)
    for v in (5, 42, 42, 42, 99, 130, 42, 250):   # 8 筆 → 單一層,含 4 個 42
        d.insert(v)
    root = next(iter(d.layers.values()))["root"]
    cts = [b"".join(l.ct.c) for l in leaves(root) if d.values[l.rid] == 42]
    return len(cts), len(set(cts))


def test_P4_L5():
    n, distinct = dup_leaf_ct_equal("per_node")
    record("P4 per_node:同一層內 4 筆重複值的密文都不同", n == 4 and distinct == 4,
           f"4 筆值為 42 的葉節點,不同密文 {distinct} 種")
    n, distinct = dup_leaf_ct_equal("per_build")
    record("L5 per_build:同一層內 4 筆重複值的密文完全相同(會洩漏哪些值相同)",
           n == 4 and distinct == 1, f"4 筆值為 42 的葉節點,不同密文 {distinct} 種")


def test_P5():
    ok = True
    for mode in ("per_node", "per_build"):
        d = DynamicGPPT(MAX=8, nonce_mode=mode)
        d.insert(42)                                        # 層 0
        c_old = b"".join(d.layers[0]["root"].ct.c)
        d.insert(7)                                         # 合併成層 1(新 msk)
        root = d.layers[1]["root"]
        c_new = [b"".join(l.ct.c) for l in leaves(root) if d.values[l.rid] == 42][0]
        ok &= c_old != c_new
    record("P5 同一個值在合併前後(不同層)的密文不同,兩種模式皆然", ok)


if __name__ == "__main__":
    print("--- 沿用 v2 的 6 項(nonce_mode = per_node)---")
    test_L1(); test_L2(); test_L3(); test_L4(); test_P1(); test_P2()
    print("\n--- 新增:ASHVE+ 帶來的差異 ---")
    test_P3(); test_P4_L5(); test_P5()
    print("\n" + "=" * 60)
    print("L 開頭 = 確認「有洩漏」;P 開頭 = 確認「沒有洩漏」。PASS 代表現象如預期。")
    ok = sum(o for _, o in RESULTS)
    print(f"結果:{ok}/{len(RESULTS)} 項如預期")
    sys.exit(0 if ok == len(RESULTS) else 1)
