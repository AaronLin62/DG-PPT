"""
test_decomposition_equiv.py
===========================
驗證 dynamic_gppt_v2.btq_indices（走 dag_range_decomposition）
與學長的 dag_range_decomposition.dag_get_BTQ_list（走 gettoken）輸出一致，
並量測兩者在不同 MAX 下的 token 分解成本。

執行：python3 test_decomposition_equiv.py
"""
import random
import sys
import time

from dag_range_decomposition import dag_get_BTQ_list
from range_query_decomposition_v2 import gettoken
from dynamic_gppt_v2 import btq_indices


def canon(lst):  # 順序無關地比較
    return sorted(tuple(x) for x in lst)


def test_equivalence():
    random.seed(2024)
    bad = total = 0
    for MAX in (4, 6, 8, 10, 12):
        xs = [x for x in range(1, MAX + 1) if MAX % x == 0]
        for x in xs:
            edge = [(0, 0), (0, 2**MAX - 1), (2**MAX - 1, 2**MAX - 1), (0, 1), (1, 2**MAX - 2)]
            rand = []
            for _ in range(60):
                a = random.randint(0, 2**MAX - 1)
                rand.append((a, random.randint(a, 2**MAX - 1)))
            for q in edge + rand:
                total += 1
                if canon(btq_indices(q, MAX, x)) != canon(dag_get_BTQ_list(q, MAX, x)):
                    bad += 1
                    if bad <= 3:
                        print("  不一致:", q, "MAX", MAX, "x", x)
    print(f"[{'PASS' if bad == 0 else 'FAIL'}] 新舊分解輸出一致：{total - bad}/{total}（MAX∈{{4,6,8,10,12}}、所有整除的 x、含邊界查詢）")
    return bad == 0


def bench():
    print("\nToken 分解成本（每個 MAX 取 20 個「互不相同」的查詢，避開 lru_cache 的好處）")
    print(f"  {'MAX':>4} {'舊(gettoken路徑)':>18} {'新(dag_range_decomp)':>22} {'加速':>8}")
    for MAX in (8, 10, 12, 14):
        random.seed(MAX)
        qs = []
        for _ in range(20):
            a = random.randint(0, 2**MAX - 2)
            qs.append((a, random.randint(a, 2**MAX - 1)))
        gettoken.cache_clear()
        t0 = time.perf_counter()
        for q in qs:
            dag_get_BTQ_list(q, MAX, 2)
        old = (time.perf_counter() - t0) / len(qs) * 1000
        t0 = time.perf_counter()
        for q in qs:
            btq_indices(q, MAX, 2)
        new = (time.perf_counter() - t0) / len(qs) * 1000
        print(f"  {MAX:>4} {old:>15.2f} ms {new:>19.3f} ms {old/new:>7.0f}x")


if __name__ == "__main__":
    ok = test_equivalence()
    bench()
    sys.exit(0 if ok else 1)
