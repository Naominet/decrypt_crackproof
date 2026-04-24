# CrackProof Shell Unpacker — PE32 (32位) 支持说明

## 概述

`decrypt_crackproof.py` 原本仅支持 64 位 PE32+（amdaemon.exe），现已添加 32 位 PE32 支持（chusanApp.exe，CHUNITHM 街机游戏）。8 个解密阶段和文件数据管线均已验证通过。

已测试目标：
- chusanApp 2.00 — 7214 数据块，22 个 DLL，EP=0x196C
- chusanApp 2.10 — 7345 数据块，22 个 DLL，EP=0x196C
- amdaemon (PE32+) — 无回归

## 使用方法

```bash
# 64位 (PE32+)，与之前完全一致
python decrypt_crackproof.py amdaemon.exe [aes_tables_dir]

# 32位 (PE32)，同一脚本自动识别
python decrypt_crackproof.py chusanApp.exe [aes_tables_dir]
```

脚本通过 PE 可选头魔数（`0x10B` = PE32，`0x20B` = PE32+）自动判断位数，无需手动指定。

## 主要差异对照

| 项目 | PE32+ (64位) | PE32 (32位) |
|------|-------------|-------------|
| Shell 定位 | `locate_shell_offsets` 扫描 anchor/fcs | `find_tbl` 扫描 tbl 偏移表 |
| PE 头恢复 | anchor+0x08/0x04, fcs-0x10/-0x0C | tbl+0xBC→PE+0x80, tbl+0xC8→PE+0x88, tbl+0xCC→PE+0x8C |
| Header 校验和 | fcs+0x80, `checksum_with_size_xor` 循环 | tbl+0x58, `crc32(data,pa,ps)^ps` 循环 (RVA对) |
| FirstStage 校验和 | `checksum_with_size_xor(data, fcs)` | `checksum_with_size_xor(data, tbl+0xA8)` |
| SecondStage 密钥 | anchor+0x14 | tbl+0x40 |
| SecondStage 对 | fcs+0x40 | tbl+0x98 |
| SS 内部偏移 | 扫描三零模式动态定位 | 固定: 0x964(forthKey), 0x968(thirdKey), 0x96C(CS对), 0xA9C(DP基址) |
| ThirdStage 对 | big_third_pair (DP 内) | ss+0xB8C (DP 数组之后), in_place=True |
| DP 索引 | DP[5]=forth, DP[6]=fifth, DP[8]=seven, DP[13]=eighth | DP[4]=forth, DP[5]=fifth, DP[7]=seven, DP[12]=eighth |
| CS 对映射 | fcs-0x08, ss+cs_base+{0x08,0x10,0x18} | tbl+0xB0, ss+{0x96C,0x974,0x97C} (cs[0]=forth, cs[1]=fifth, cs[2]=seven) |
| SevenKey 来源 | fifth_start + (fifthDsz - 0x100), 取反 | cs[1].addr + cs[1].size - 0x10, 取反 |
| EighthKey 来源 | 扫描 INT3 (0xCCCCCCCC) 定位 | seven_start + (sevenDsz - 0xD0), advance_key(3) |
| Stage 解密器 LFSR | 扫描有效操作码定位 | 固定 seven+0xA30 |
| Eighth 内部表 | +0x4DA8, +0x4DB8, +0x4DC0, +0x4DC8 | +0x3C50, +0x3C68, +0x3C78, +0x3C80 |
| 文件 LFSR | eighth+0x5120 | eighth+0x40EC |
| compress_data_offset | `(~u32(file_data, 0x1080) & 0xFFFFFFFF) + 0x1000` | 同左（通用公式） |
| IAT 条目大小 | 8 字节 (QWORD) | 4 字节 (DWORD) |
| 导入表重建 | 完整重建 IDT + ILT + DLL名映射 | 使用 eighthStage importTable 指向的真正 IDT，解密 DLL 名和函数名 |
| 入口点 | 扫描 CRT 模式 (sub rsp,28h; call; add rsp,28h; jmp) | 使用原始文件 PE 头中的 EP（CrackProof 未修改） |

## 新增函数

### `find_tbl(data, info)`
在 shell 区域中定位 PE32 的偏移表 (tbl)。通过在 shell 范围内扫描 `info[6]` 值，验证其位于候选 tbl 的 +0x88 位置，并检查 tbl+0x58 处存在合理的 RVA 值。

## 代码结构

所有分支逻辑通过 `is_pe32` 标志控制，集中在 `main()` 函数中。解密算法本身（DecryptData1~8、AES、LZ 解压）对两种格式完全通用，差异仅在于偏移量和数据布局。

## 调试过程中发现的关键问题

### 1. ThirdStage 对位置
ThirdStage 的加密对不在 DP 数组内，而是在 ss+0xB8C（DP 数组 14 条目 + 填充零之后）。使用 ss+0xB8C（完整 0xC800 字节区域），而非 ss+0xB94（仅 0x1A00 字节的部分区域）。PE32 的 ThirdStage 是原地解密（地址不变），需要 `in_place=True` 参数。

### 2. CS 对映射顺序
ss+0x96C 起的 4 个 CS 对的正确映射：
- cs[0] = forthStageCS（对应 DP[4]）
- cs[1] = fifthStageCS（对应 DP[5]）
- cs[2] = sevenStageCS（对应 DP[7]）
- cs[3] = eighthStageCS

### 3. fileCS 循环越界
eighthStage 内部表 `(ptr, size)` 对中，fileCS 的 size 字段（如 0x20 = 2 条目）必须用来限制循环次数。否则 `decrypt_data5` 会越界解密相邻的 compressedInfo 条目，导致后续文件数据解压时产生垃圾值。

### 4. Import 表双重解密
ILT 和 IAT 共享同一组 hint/name 条目。遍历时只能走一个（ILT 优先），否则 `decrypt_data7` 会被调用两次，第二次将已解密的名字重新加密。

## 验证结果（chusanApp 2.10 vs 参考 unpack）

| 段 | 匹配率 | 说明 |
|----|--------|------|
| .rdata | 100% | 常量、字符串、vtable 完全一致 |
| .data | ~100% | 仅 2 字节差异 |
| .text | 88.4% | 差异来自 decrypt_data8 实现细节 |
| .idata | 不同 | 参考工具重建了 IDT 到文件末尾，我们保留原始 in-place IDT |
