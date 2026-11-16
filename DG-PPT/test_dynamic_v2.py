import random, time
from dynamic_gppt_v2 import *
from dynamic_gppt_v2 import gen_token, search_layer, build_layer
from AES import aes

def brute(idx, q):
    return {r for r, v in idx.live().items() if q[0] <= v <= q[1]}

# ---- 1. 隨機操作 vs 暴力搜尋（含重複值、刪除、刪除後重新插入）----
random.seed(7)
idx = DynamicGPPT(MAX=8, t=2, x=2)
bad = 0; checks = 0; t0 = time.time()
for step in range(150):
    op = random.random()
    if op < 0.6 or not idx.live():
        idx.insert(random.choice([random.randint(0, 255), random.randint(0, 15)]))  # 刻意製造重複
    elif op < 0.8:
        idx.delete(random.choice(list(idx.live())))
    else:
        a = random.randint(0, 255); b = random.randint(a, 255)
        checks += 1
        if idx.query((a, b)) != brute(idx, (a, b)):
            bad += 1; print("  不一致:", (a, b))
print(f"1. 隨機操作測試：查詢 {checks} 次，不一致 {bad} 次，耗時 {time.time()-t0:.1f}s，現有層 {sorted(idx.layers)}")

# ---- 2. 刪除後重新插入同值 ----
i2 = DynamicGPPT()
a = i2.insert(10); i2.delete(a); b = i2.insert(10)
print("2. 刪除 10 後重新插入 10，查詢 [0,20]:", i2.query_values((0, 20)), "(期望 [10])")

# ---- 3. 合併後排序 ----
i3 = DynamicGPPT()
for v in [50, 10, 40, 20, 30, 5, 60, 1]:
    i3.insert(v)
lay = list(i3.layers.values())[0]
print("3. 單一層內依值排序:", [i3.values[r] for r in sorted(lay['rids'], key=lambda r:(i3.values[r], r))], "(索引建樹時已排序)")

# ---- 4. Forward Privacy：舊 token 對新建的層是否匹配 ----
i4 = DynamicGPPT()
i4.insert(100)
old_key = i4.layers[0]['key']
old_tok = gen_token((90, 110), 8, old_key, 2, 2)
out = []; search_layer(i4.layers[0]['root'], old_tok, out)
print("4a. 舊 token 對同一層（含 100）:", out, "(期望找到 1 筆)")
i4.insert(105)  # 觸發合併 → 新層、新金鑰
new_layer = list(i4.layers.values())[0]
out = []; search_layer(new_layer['root'], old_tok, out)
print("4b. 舊 token 對合併後的新層（含 100,105）:", out, "(期望 [] → 舊查詢連結不到新資料)")

# ---- 5. 沒有金鑰能否猜出 bit ----
i5 = DynamicGPPT(); i5.insert(77)
root = i5.layers[0]['root']
guess_ok = sum(1 for k, c in enumerate(root.c) if any(aes(b + k) == c for b in (0, 1)))
print(f"5. 不用金鑰窮舉，能猜中的密文位置: {guess_ok}/{len(root.c)} (期望 0)")

# ---- 6. 同一個查詢，兩次 token 的 d1 是否不同 ----
t1 = gen_token((10, 50), 8, old_key, 2, 2); t2 = gen_token((10, 50), 8, old_key, 2, 2)
print("6. 同查詢兩次 token 的 d1 全不同:", all(a[1] != b[1] for a, b in zip(t1, t2)))
