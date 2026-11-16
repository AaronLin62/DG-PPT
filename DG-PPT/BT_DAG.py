from typing import List, Dict, Set, Tuple
import hashlib
import sys
from pathlib import Path

# 添加父目錄到 path 以便導入
sys.path.insert(0, str(Path(__file__).parent.parent))

from AES import aes
from range_query_decomposition_v2 import binary
from dag_range_decomposition import level_pos_to_dag_index

# ==========================================
# DAG 編碼核心函式（用於 DB 加密）
# ==========================================
def dag_BT_generate(binary_string, m):
    """
    DAG 結構：每個 level 有 level+1 個節點，節點之間共享子節點

    Args:
        binary_string: e.g., "01"
        m: bit length

    Returns:
        DAG bitmap (長度為 (m+1)*(m+2)/2)
    """
    # DAG 大小（等差級數公式）
    dag_size = (m + 1) * (m + 2) // 2

    # 初始化 DAG bitmap
    DAG_BT = [0] * dag_size

    # 從 root 開始 (level=0, pos=0)
    current_level = 0
    current_pos = 0

    # 標記 root
    DAG_BT[level_pos_to_dag_index(current_level, current_pos)] = 1

    # 走訪路徑（像原始 BT_generate 風格）
    for bit in binary_string:
        # 移動到下一層
        current_level += 1

        if bit == "0":
            # 往左：pos 不變
            pass
        else:
            # 往右：pos + 1
            current_pos += 1

        # 標記當前節點
        dag_idx = level_pos_to_dag_index(current_level, current_pos)
        DAG_BT[dag_idx] = 1

    return DAG_BT


# ==========================================
# DAG 版本的 get_BT（用於 DB 加密）
# ==========================================
def dag_get_BT(num, bits, x):
    """
    DAG 版本的 get_BT（用於 DB 加密階段）

    將數值分成 x 個 segment，每個 segment 用 DAG 編碼後連接

    Args:
        num: 資料值
        bits: 總位元數
        x: segment 數量

    Returns:
        DAG BT concatenation
    """
    s = bits // x  # 每個 segment 的位元數
    binary_num = binary(num, bits)
    BT = []

    for i in range(x):
        sub_binary = binary_num[s * i:s * (i + 1)]
        BT = BT + dag_BT_generate(sub_binary, s)

    return BT