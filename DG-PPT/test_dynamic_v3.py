"""
test_dynamic_v3.py
==================
dynamic_gppt_v3.py 的正確性與成本測試,兩種 nonce 模式都跑:
  per_node  【論文 VI-B Theorem 1 證明的說法】每節點新 r
  per_build 【論文 IV-C ASHVE+ 小節的說法】每次建層共用 r

  C1  隨機插入、刪除、刪除後重新插入、重複值,每次查詢都和暴力搜尋比對
  C2  資料筆數不是 2 的次方(多層同時存在)時,查詢仍正確
  C3  成本:v2(aes)與 v3(ASHVE+)的插入與查詢時間(只印出,不判定)

執行方式(與學長的 AES.py、BT_DAG.py、dag_range_decomposition.py、
range_query_decomposition_v2.py,以及 ashve_plus.py、dynamic_gppt_v2.py 放同一資料夾):
    python3 test_dynamic_v3.py
"""
import random
import sys
import time

import dynamic_gppt_v2 as v2
import dynamic_gppt_v3 as v3

MODES = ("per_node", "per_build")
RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def brute(idx, q):
    return sorted(v for v in idx.live().values() if q[0] <= v <= q[1])


def c1_random_ops(mode, steps=200, seed=7):
    rnd = random.Random(seed)
    idx = v3.DynamicGPPT(MAX=8, nonce_mode=mode)
    checks = bad = 0
    for _ in range(steps):
        op = rnd.random()
        if op < 0.55 or not idx.live():
            idx.insert(rnd.choice([rnd.randrange(256), 42, 42, 200]))  # 刻意放重複值
        elif op < 0.75:
            rid = rnd.choice(list(idx.live()))
            val = idx.values[rid]
            idx.delete(rid)
            if rnd.random() < 0.3:
                idx.insert(val)                                        # 刪除後重新插入同值
        else:
            a = rnd.randrange(256)
            q = (a, min(255, a + rnd.randint(0, 60)))
            checks += 1
            bad += idx.query_values(q) != brute(idx, q)
    record(f"C1 隨機操作與暴力搜尋一致({mode})", bad == 0,
           f"{steps} 步、查詢 {checks} 次、錯誤 {bad} 次;最後的層:{sorted(idx.layers)}")


def c2_multilayer(mode):
    rnd = random.Random(3)
    ok, detail = True, []
    for n in (37, 100, 203):
        idx = v3.DynamicGPPT(MAX=10, nonce_mode=mode)
        for _ in range(n):
            idx.insert(rnd.randrange(1024))
        for _ in range(15):
            a = rnd.randrange(1024)
            q = (a, min(1023, a + rnd.randint(0, 200)))
            ok &= idx.query_values(q) == brute(idx, q)
        detail.append(f"n={n}:層 {sorted(idx.layers)}")
    record(f"C2 非 2 的次方、多層查詢正確({mode})", ok, ";".join(detail))


def c3_cost():
    print("\n  C3 成本比較(MAX=12、x=2、t=2,插入 255 筆 = 8 層同時存在,只印出不判定)")
    rnd = random.Random(11)
    vals = [rnd.randrange(4096) for _ in range(255)]
    qs = [(a, a + 160) for a in (rnd.randrange(4096 - 160) for _ in range(20))]
    rows = [("v2(aes)", lambda: v2.DynamicGPPT(MAX=12))]
    rows += [(f"v3 {m}", (lambda m=m: v3.DynamicGPPT(MAX=12, nonce_mode=m))) for m in MODES]
    for name, make in rows:
        idx = make()
        t0 = time.perf_counter()
        for v in vals:
            idx.insert(v)
        ins = (time.perf_counter() - t0) / len(vals)
        t0 = time.perf_counter()
        for q in qs:
            idx.query(q)
        qt = (time.perf_counter() - t0) / len(qs)
        print(f"    {name:14s} 平均插入 {ins * 1000:6.1f} ms  平均查詢 {qt * 1000:6.1f} ms  "
              f"平均造訪節點 {idx.stats['visited'] / len(qs):.0f}")


if __name__ == "__main__":
    for m in MODES:
        c1_random_ops(m)
        c2_multilayer(m)
    c3_cost()
    print("\n" + "=" * 60)
    print(f"結果:{sum(RESULTS)}/{len(RESULTS)} 項通過")
    sys.exit(0 if all(RESULTS) else 1)
