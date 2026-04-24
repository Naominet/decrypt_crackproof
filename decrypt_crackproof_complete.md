# CrackProof Shell Unpacker 完整技术文档

`decrypt_crackproof.py` — 用于解包受 CrackProof 保护的 PE32/PE32+ 可执行文件（SEGA 街机游戏）。

本文档整合自以下 6 份独立文档，并补充了最新修复（2025-03-11）：
- `crackproof_exe_notes.md` — 原始 PE32+ (amdaemon) 技术文档
- `crackproof_x86_analysis.md` — PE32 (chusanApp) x86 分析文档
- `decrypt_crackproof_pe32_notes.md` — PE32 支持说明
- `decrypt_crackproof_changelog.md` — 修改记录
- `decrypt_crackproof_notes.md` / `decrypt_crackproof_notes0310.md` — 综合文档

---

## 目录

1. [使用方法](#1-使用方法)
2. [脱壳流程概览](#2-脱壳流程概览)
3. [Stage 1-2: 通用解密](#3-stage-1-2-通用解密)
4. [Stage 3: SecondStage](#4-stage-3-secondstage)
5. [Stage 4: ThirdStage](#5-stage-4-thirdstage)
6. [Stage 5-7: ForthStage / FifthStage / SevenStage](#6-stage-5-7)
7. [Stage 8: EighthStage](#7-stage-8-eighthstage)
8. [最终阶段: 文件数据解密](#8-最终阶段-文件数据解密)
9. [DecryptData8 详解](#9-decryptdata8-详解)
10. [导入表处理](#10-导入表处理)
11. [入口点修复](#11-入口点修复)
12. [PE 头修复](#12-pe-头修复)
13. [PE32+ 与 PE32 差异对照表](#13-pe32-与-pe32-差异对照表)
14. [PE32+ 老壳/新壳区分](#14-pe32-老壳新壳区分)
15. [解密函数说明](#15-解密函数说明)
16. [SecondStage 内部布局](#16-secondstage-内部布局)
17. [ThirdStage 内部布局](#17-thirdstage-内部布局)
18. [EighthStage 内部布局](#18-eighthstage-内部布局)
19. [调试中发现的关键问题](#19-调试中发现的关键问题)
20. [测试结果](#20-测试结果)
21. [修改记录](#21-修改记录)
22. [参考文件](#22-参考文件)

---

## 1. 使用方法

```bash
python decrypt_crackproof.py <input.exe> [aes_tables_dir]
```

- 输出: `<input>.unpack.exe`
- AES 表默认路径: `F:\SEGA\DecryptCrackproofDll64\`（含 `aes_sbox`, `aes_colum_mix1~4`）
- 脚本通过 PE 可选头魔数自动判断位数：`0x10B` = PE32 (32-bit)，`0x20B` = PE32+ (64-bit)

已测试目标：
- **PE32+ (64-bit)**: amdaemon.exe（5 个版本全部通过）
- **PE32 (32-bit)**: chusanApp.exe（9 个版本脱壳通过）

---

## 2. 脱壳流程概览

```
文件尾部 → [Stage 1: DecryptData1] → info[8]
         → [Stage 2: DecryptData2] → 内存映像 (shell 解密)
         → [Stage 3: SecondStage]  → 壳结构 (密钥/校验和/对)
         → [Stage 4: ThirdStage]   → 内部结构 (slots/keys/infoTable)
         → [Stage 5: ForthStage]   → 解密解压
         → [Stage 6: FifthStage]   → 解密解压
         → [Stage 7: SevenStage]   → 解密解压 + customDecryptor (LFSR)
         → [Stage 8: EighthStage]  → 解密解压 → 文件数据表
         → [文件数据解密]          → 逐块 AES + LFSR + LZ 解压
         → [后处理]                → decrypt_data8 / 节表修复 / 导入表 / EP
```

8 层嵌套解密，每层使用前层产生的密钥和校验和。最终从 EighthStage 中提取文件数据管线所需的表（compressedInfo、fileCS、fileLFSR、importTable、zeroList），逐块将原始文件还原到内存映像中。

---

## 3. Stage 1-2: 通用解密

### Stage 1: DecryptData1

从文件尾部读取加密的 info 数组（8 个 uint32）：

| 字段 | 含义 |
|------|------|
| info[0] | 解密种子 |
| info[1] | 0x4E4E4F4B ("KONN" magic) |
| info[2] | shell 偏移 |
| info[3] | 数据基地址（壳代码起始）|
| info[4] | shell 大小 |
| info[5] | 剩余数据大小 |
| info[6] | shell 基地址 |
| info[7] | 尾部标记大小 |

PE32/PE32+ 通用，无差异。

### Stage 2: DecryptData2

解密 shell 区域到内存映像缓冲区：
- `image_size` = PE 可选头中的 SizeOfImage
- `decrypt_size = info[6] - info[3] + 0x2000`
- 解密后将剩余未加密数据复制到映像缓冲区
- 复制原始文件的 PE 头（前 0x1000 字节）

PE32/PE32+ 通用，无差异。

---

## 4. Stage 3: SecondStage

SecondStage 包含壳的核心结构：密钥、校验和对、阶段指针对。

### PE32+ 路径

1. **定位 anchor**: 在 shell 区域扫描 `info[3]` 值，验证 `info[6]` 在 anchor+0x20~0x58 范围内
2. **定位 fcs**: `fcs = anchor + delta`（delta 通过扫描确定，典型值 0x38~0x40）
3. **PE 头恢复**: `anchor+0x08` = import_rva, `anchor+0x04` = import_size; `fcs-0x10` = resource_rva, `fcs-0x0C` = resource_size
4. **Header 校验和**: 从 `fcs+0x80` 循环读取 (addr, size) 对，`checksum_with_size_xor` 累计 XOR
5. **FirstStage 校验和**: `checksum_with_size_xor(data, fcs)`
6. **SecondStage 密钥**: `anchor+0x14`
7. **解密**: `key = headerChecksum ^ firstStageCS ^ secondStageKey`，`decrypt_data3(data, fcs+0x40, key, shift=21)`

内部偏移通过 `"Kernel32.dll"` 字符串锚点动态定位：
- thirdStageKey = anchor_off - 0x34
- forthStageKey = anchor_off - 0x30
- CS 对 = anchor_off - 0x20 起（4 对）
- 阶段对使用 `pair_shift = ss_size - 0x10C8` 调整

### PE32 路径

1. **定位 tbl**: `find_tbl()` 在 shell 区域扫描 `info[6]` 值，验证 tbl+0x58 处有合理 RVA
2. **PE 头恢复**: `tbl+0xBC` → PE+0x80, `tbl+0xC8` → PE+0x88, `tbl+0xCC` → PE+0x8C
3. **Header 校验和**: `tbl+0x58`，`crc32(data, pa, ps) ^ ps` 循环（RVA 对）
4. **FirstStage 校验和**: `checksum_with_size_xor(data, tbl+0xA8)`
5. **SecondStage 密钥**: `tbl+0x40`
6. **SS 对**: `tbl+0x98`
7. **解密**: 同 PE32+

内部偏移固定：
- forthStageKey = ss+0x964
- thirdStageKey = ss+0x968
- CS 对 = ss+0x96C（4 对 addr+size）
- DP 基址 = ss+0xA9C
- ThirdStage 对 = ss+0xB8C（在 DP 数组之后，不在 DP 内）

---

## 5. Stage 4: ThirdStage

### 解密

使用 thirdStageKey，`decrypt_data3(shift=19)` 解密。

### infoTable 处理

自动检测：扫描 type=1 或 0x11 后跟 type=2 的模式。

- `keysAddr = infoTable - 0x58`
- slot0: type=1/0x11 → `decrypt_data4`（8 字节 XOR 解密）
- slot1: type=2 → copy list（`decrypt_data5` + memcpy 循环）

### keyOffsets 提取

从 keysAddr 读取 4 个 keyOffset（每组 32 字节，含地址和 rounds）：

| keyOffset | 用途 | 典型 rounds |
|-----------|------|------------|
| [0] | LZ 解压查找表 | ~59400（非 AES）|
| [1] | LZ 解压查找表（备选）| ~34056 |
| [2] | AES-256 密钥调度 | 14 |
| [3] | AES-256 密钥调度（备选）| 14 |

PE32+ 使用 keyOffsets[3] (AES) + keyOffsets[1] (LZ)；PE32 使用 keyOffsets[2] (AES) + keyOffsets[0] (LZ)。

---

## 6. Stage 5-7

### ForthStage / FifthStage

逐层 `decrypt_and_decompress`，每层使用不同校验和组合作为密钥：
- **ForthStage key**: forthStageKey（从 SS 提取）
- **FifthStage key**: forthStage 校验和

### SevenStage

- 解密解压后包含 customDecryptor（LFSR 多态解密器）
- **LFSR 扫描方向**: 必须使用**后向扫描**（`scan_backward=True`），取最后一个 LFSR 块
  - SevenStage 中有多个 LFSR 块，前面的属于反调试代码
  - 实际 customDecryptor 在 SevenStage 后部
- **SevenStage key**: `fifthStage checksum addr + size - 0x10`，取反（~）

### EighthStage key 定位

暴力搜索策略（PE32+ 和 PE32 统一）：
1. 从 customDecryptor 位置向前搜索多个 gap（0x70, 0xD0, 0x28, ...）
2. 从 sevenStage 尾部向前搜索多个 gap（0xD0, 0xC0, 0xE0, ...）
3. 扫描 customDecryptor 前 0x100 范围内的非零/非字符串值
4. 逐个尝试 `decrypt_and_decompress`，找到能成功解压的即为正确 key

---

## 7. Stage 8: EighthStage

使用 customDecryptor 和 eighthStageKey 解密解压。

EighthStage 内部偏移因样本而异，使用**自动检测**：

- **fileLFSR**: 扫描所有 LFSR 候选（`find_lfsr_block`），后向匹配有效 fileCS 指针
- **fileCS**: fileLFSR 前方 gap 处的 (ptr, size) 指针，trial-decrypt 验证
- **compressedInfo**: 指针指向的数据 trial-decrypt 后满足压缩块格式（有效地址、合理大小）
- **importTable**: 指针指向全零区域（IDT 尚未填充）或有效 IDT
- **zeroList**: 指针指向的数据 trial-decrypt 后为有效 (addr, size) 对

---

## 8. 最终阶段: 文件数据解密

### 处理流程

1. **zeroList 清零**: 在文件解压前执行，清零指定内存区域
2. **逐块解压文件数据**: 从 compressedInfo 读取 (src_off, src_size, dst_addr, dst_size) 列表
   - 从原始文件复制压缩数据
   - AES-ECB 解密（keyOffsets[2] 或 [3]）
   - LFSR 自定义字节解密（fileLFSR 生成的 256 字节查找表）
   - LZ 变种解压（keyOffsets[0] 或 [1]）
3. **节表修复**: `SizeOfRawData = VirtualSize`, `PointerToRawData = VirtualAddress`
4. **段权限修复**:
   - `.rdata` (PE32+) / `.idata` (PE32): characteristics = `0xC0000040`（RW，供 loader 写入 IAT）
5. **decrypt_data8**: 解密 .text 段（EXE 特有，按页加密）— 详见下节
6. **导入表恢复/重建** — 详见导入表章节
7. **入口点修复** — 详见入口点章节

---

## 9. DecryptData8 详解

CrackProof 对 EXE 的 .text 段按页（0x1000 字节 = 256 个 16 字节块）加密。每页独立调用 decrypt_data8，循环从 block 1 开始（跳过 block 0），每个 16 字节块 XOR 修改 1 字节。

### 算法

```python
def decrypt_data8(data, page_offset, key):
    k = key
    rk = ror32(k, 15)
    k = rk
    for bi in range(1, 256):  # 跳过 block 0
        rk = ror32(k, 15)
        ri = (rk + bi) & 0xFFFFFFFF
        k = (ri + bi) & 0xFFFFFFFF
        tidx = page_offset + bi * 16 + (ri & 0xF)
        data[tidx] ^= (k & 0xFF)
```

### 双密钥公式

不同版本使用不同密钥公式：

| 公式 | 计算方式 | 适用版本 |
|------|----------|----------|
| page+1 | `key = page_index + 1` | 较新版本（amdaemon_4, amdaemon_1_dt145, chusanApp 2.05~2.25）|
| 0x8000*(page+1) | `key = 0x8000 * (page_index + 1)` | 较旧版本（amdaemon_2.45_io4, chusanApp 2.40/2.45）|

### 自动检测机制

#### PE32+ 路径（EP prologue 评分）

仅对 Layout A 样本执行。对三个选项（无解密 / page+1 / 0x8000*(page+1)）在 EP 所在页和 call target 所在页做测试解密，通过 EP 质量评分选择最优：

| 检查项 | 得分 |
|--------|------|
| EP 处 `48 83 EC 28 E8`（sub rsp, 0x28; call） | +10 |
| call 目标前 16 字节内有 `48 83 EC XX`（sub rsp, XX） | +20 |
| call 目标处 `48 89`（mov [rsp+...], reg） | +5 |

#### PE32 路径（0xCC int3 填充计数）

EP 评分法对 PE32 不适用（EP 经常是 JMP thunk），改用 **0xCC (int3) 填充字节计数**：

原理：编译器在函数之间插入 `0xCC` (int3) 作为对齐填充。正确解密后这些字节保持为 `0xCC`，错误公式会破坏它们（每页约破坏 ~255 个）。

实现：
1. 在 .text 段内部取样本页（25%、50%、75% 位置）
2. 对每个候选公式执行测试解密
3. 统计 `0xCC` 字节总数
4. 选择 0xCC 计数最高的公式

```python
sample_pages = [int(num_pages * f) for f in (0.25, 0.5, 0.75)]
for fname, ffunc in [('page+1', lambda p: p+1), ('0x8000*(page+1)', lambda p: 0x8000*(p+1))]:
    total_cc = sum(test_decrypt(page).count(0xCC) for page in sample_pages)
```

### 密钥公式发现过程

对比 amdaemon_3（正常）与 amdaemon_1_dt145（失败）的 .text 段：
- 339,743 字节差异，每 16 字节块恰好 1 个差异 → decrypt_data8 特征
- 旧公式 `key = 0x8000*(page+1)` 反而增加差异到 596,124
- 暴力搜索发现：page 0 正确 key = 1, page 1 = 2 → `key = page + 1`
- EP prologue 检查误判原因：小 key 的 XOR 字节不落在 EP 前 5 字节，但 call target 处代码错误（adc 而非 sub rsp）

---

## 10. 导入表处理

### PE32+ — 双路径

#### IDT 有效时（老壳，ss_size=0x10C8）

从 metadata 恢复的 IDT 可用，原位 `decrypt_data7` 解密 DLL 名和函数名：
- `decrypt_data7(rva + 2, rva & 0xFF)` 解密每个 hint/name 条目
- 保留原始 DLL 名大小写

#### IDT 无效时（新壳）

IAT scan + 函数名识别 + IDT 重建：
1. IAT 位于 .rdata，包含多个 DLL 组（以 8 字节 null 分隔）
2. 每个 IAT 条目指向 hint/name，用 `decrypt_data7` 解密
3. 通过函数名签名识别 DLL 归属（硬编码映射表）
4. 在导入表区域构建完整的 IDT + DLL 名称 + ILT

### PE32

使用 eighthStage 中 importTable 指向的 IDT：
1. 验证 eighthStage 和 metadata 两个导入指针，选择有效的
2. 遍历 **ILT 优先**（不走 IAT），避免双重解密问题
3. `decrypt_data7` 解密 DLL 名和函数名
4. 更新 PE 头 Import 目录
5. **清除 IAT 目录**（PE32: pe+0xD8 = 0）— 与参考工具行为一致

---

## 11. 入口点修复

### PE32+

| 壳版本 | 方式 |
|--------|------|
| 老壳 (ss_size=0x10C8) | 从 `info[3]+0x40` 读取（DecryptData5 解密后）|
| 新壳 (ss_size=0x10B8/0x1158) | 搜索 CRT 模式: `sub rsp,28h; call; add rsp,28h; jmp` |

### PE32

使用 metadata 中的 EP（从 `info[3]` 区域提取）。若 metadata 无效则回退到原始 PE 头的 EP（CrackProof 通常不修改 PE32 的 EP）。

---

## 12. PE 头修复

### PE32+

| 项目 | 老壳 | 新壳 |
|------|------|------|
| 数据目录 | DecryptData5 解密 info[3]+0x40, 恢复全部 16 个 | 仅恢复 Import/Resource, 清零 BaseReloc |
| Subsystem | 2 (GUI) | 3 (CUI) |
| DllCharacteristics | 0x0060 | 0x0000 |
| TLS | 清零 | 清零 |

### PE32

- **数据目录**: 从 metadata_dirs 恢复（128 字节 = 16 个目录项）
- **TLS 目录重建**: 若 TLS 结构全零（24 字节），从 .tls 和 .data 节信息重建有效结构（防止 0xC0000005）
- **IAT 目录**: 清零（pe+0xD8 = 0, pe+0xDC = 0）
- **Subsystem**: 保持原值
- **DllCharacteristics**: 清零
- **BaseReloc**: 清零

### TLS 目录重建（PE32 特有）

CrackProof 的解压块不覆盖 .rdata 中的 TLS 结构体（IMAGE_TLS_DIRECTORY32），导致 24 字节全零。`AddressOfIndex = 0` 会让 PE loader 写入 NULL 地址，触发 0xC0000005。

重建逻辑：
```
StartAddressOfRawData = ImageBase + .tls VA
EndAddressOfRawData   = StartAddressOfRawData  (空 TLS 数据)
AddressOfIndex        = ImageBase + .data VA + .data Size - 16  (借用 .data 尾部)
AddressOfCallbacks    = ImageBase + .data VA + .data Size - 8   (借用 .data 尾部)
SizeOfZeroFill        = 0
Characteristics       = 0x300000
```

若找不到 .tls 或 .data 节，则直接清零 TLS 数据目录。

---

## 13. PE32+ 与 PE32 差异对照表

### Shell 定位与偏移

| 项目 | PE32+ (64-bit) | PE32 (32-bit) |
|------|-------------|-------------|
| Shell 定位 | anchor/fcs 扫描 | `find_tbl` 偏移表扫描 |
| PE 头恢复 | anchor+0x08/0x04, fcs-0x10/-0x0C | tbl+0xBC→PE+0x80, tbl+0xC8→PE+0x88 |
| Header 校验和 | fcs+0x80, `checksum_with_size_xor` | tbl+0x58, `crc32^size` |
| FirstStage CS | `checksum_with_size_xor(data, fcs)` | `checksum_with_size_xor(data, tbl+0xA8)` |
| SS 密钥 | anchor+0x14 | tbl+0x40 |
| SS 对 | fcs+0x40 | tbl+0x98 |
| SS 内部偏移 | `"Kernel32.dll"` 锚点动态定位 | 固定: 0x964/0x968/0x96C/0xA9C |
| ThirdStage 对 | big_third_pair (DP 内) | ss+0xB8C (DP 后), in_place=True |
| DP 索引 | [5]=forth [6]=fifth [8]=seven [13]=eighth | [4]=forth [5]=fifth [7]=seven [12]=eighth |
| IAT 条目大小 | 8 字节 (QWORD) | 4 字节 (DWORD) |
| PE 数据目录偏移 | pe+0x88 (136 字节) | pe+0x78 (128 字节) |
| AES key | keyOffsets[3] | keyOffsets[2] |
| LZ key | keyOffsets[1] | keyOffsets[0] |

### SevenStage → EighthStage

| 项目 | PE32+ | PE32 |
|------|-------|------|
| customDecryptor LFSR | 后向扫描 sevenStage | 后向扫描 sevenStage |
| EighthKey 定位 | 暴力搜索 | 暴力搜索 |

### 导入表

| PE32+ | PE32 |
|-------|------|
| IDT 有效（老壳）: decrypt_data7 原位解密 | 使用 eighthStage importTable 指向的 IDT |
| IDT 无效（新壳）: IAT scan + 函数名识别 + IDT 重建 | ILT 优先遍历，避免双重解密 |

### 入口点

| PE32+ | PE32 |
|-------|------|
| 老壳: info[3]+0x40 读取（DecryptData5 解密） | metadata EP 或原始 PE 头 EP |
| 新壳: CRT 模式搜索 | |

### decrypt_data8 自动检测

| PE32+ | PE32 |
|-------|------|
| EP prologue + call target 质量评分 | 0xCC (int3) 填充计数 |

---

## 14. PE32+ 老壳/新壳区分

通过 ss_size 区分：

| 项目 | 老壳 (ss_size=0x10C8) | 新壳 (ss_size=0x10B8/0x1158) |
|------|----------------------|------------------------------|
| 数据目录恢复 | DecryptData5 解密 info[3]+0x40, 恢复全部 16 个 | 仅恢复 Import/Resource, 清零 BaseReloc |
| EP | info[3]+0x40 读取 | CRT 模式搜索 |
| Subsystem | 2 (GUI) | 3 (CUI) |
| DllCharacteristics | 0x0060 | 0x0000 |
| IDT | 有效，原位解密 | 无效，需重建 |

### Layout A / Layout B

PE32+ 另有一层区分（通过 `info[3]+0x10` 的值判断）：

| 项目 | Layout A (test_val < 0x10000) | Layout B (test_val > 0x10000) |
|------|------|------|
| metadata 位置 | info[3]+0x40, 144 字节 | info[3]+0x10, 0x290 字节 |
| EP 来源 | info[3]+0x40 (解密后) | info[3]+0x20 |
| 数据目录 | info[3]+0x50, 128 字节 | info[3]+0x30, 128 字节 |
| decrypt_data8 | 需要（自动检测公式） | 不需要 |

---

## 15. 解密函数说明

| 函数 | 用途 | 算法概要 |
|------|------|----------|
| `decrypt_data1` | 从文件尾部解密 info 数组 | 迭代 XOR，种子从尾部读取 |
| `decrypt_data2` | 解密壳代码到内存映像 | 大块 XOR + 字节操作 |
| `decrypt_data3` | 带移位的 XOR 解密（Stage 3/4）| `key = ror32(key, shift) ^ data`，逐 DWORD |
| `decrypt_data4` | 8 字节 XOR 解密 | 查找表预计算，8 字节一组 XOR |
| `decrypt_data5` | 旋转+XOR 密码 | `key = addr & 0xFF`，rol8/ror8 + XOR 逐字节 |
| `decrypt_data6` | LFSR 解密（多态代码）| 15-bit LFSR，反馈多项式 0x8003 |
| `decrypt_data7` | 半字节交换+减法（导入函数名）| nibble 交换后减去 `key = rva & 0xFF`，逐字节 |
| `decrypt_data8` | 按 16 字节块 XOR（.text 按页加密）| ror32(key,15) 递推，每块 1 字节 XOR |
| `aes_decrypt` | AES-ECB 解密 | 标准 AES-256，使用外部 S-box 和 MixColumn 表 |
| `decompress` | LZ 变种解压 | Huffman 风格变长编码 + 滑动窗口 |
| `decrypt_and_decompress` | 复合解密 | AES + DecryptData3 + 可选自定义解密 + LZ |
| `generate_custom_decryptor` | 从多态代码生成 LFSR 字节解密函数 | 解码 LFSR 加密的 x86 操作码序列 |
| `find_lfsr_block` | 在数据中定位 LFSR 编码块 | 验证解码后的操作码合法性（0x04/0x2C/0x34/0x90/0xC0/0xC3/0xFE）|
| `find_tbl` | PE32: 定位 shell 偏移表 | 扫描 info[6] 值，验证 +0x58 处 RVA |
| `advance_key` | 密钥迭代推进 | 多次 `ror32(key, 15)` |

---

## 16. SecondStage 内部布局

### PE32+ (动态偏移)

通过 `"Kernel32.dll"` 字符串锚点定位，`pair_shift = ss_size - 0x10C8`：

| 项目 | 基线偏移 | 定位方式 |
|------|----------|----------|
| thirdStageKey | 0x0D74 + key_shift | Kernel32 - 0x34 |
| forthStageKey | 0x0D78 + key_shift | Kernel32 - 0x30 |
| CS 对 (second/seven/fifth/forth) | 0x0D88 + key_shift | Kernel32 - 0x20 起 |
| thirdStage pair | 0x0E30 + pair_shift | 固定偏移 |
| forthStage pair | 0x0E88 + pair_shift | 固定偏移 |
| fifthStage pair | 0x0E98 + pair_shift | 固定偏移 |
| sevenStage pair | 0x0EB8 + pair_shift | 固定偏移 |
| eighthStage pair | 0x0F08 + pair_shift | 固定偏移 |

### PE32 (固定偏移)

| 偏移 | 内容 |
|------|------|
| 0x000 | ss 自身地址 |
| 0x004-0x390 | 代码区 (obfuscated x86) |
| 0x964 | forthStageKey |
| 0x968 | thirdStageKey |
| 0x96C | checksum pairs（4 对 addr+size）|
| 0xA9C | DP 基址 |
| 0xAAC | 14 个 entries（每个 16 字节）|
| 0xB8C | thirdStage pair |
| 0xBD0 | ss_size 结束 |

CS 对映射顺序（ss+0x96C 起）：
- cs[0] = forthStageCS（对应 DP[4]）
- cs[1] = fifthStageCS（对应 DP[5]）
- cs[2] = sevenStageCS（对应 DP[7]）
- cs[3] = eighthStageCS

---

## 17. ThirdStage 内部布局

### PE32

| 偏移 | 内容 |
|------|------|
| 0x000-0x673 | 代码/数据 |
| 0x674-0x1483 | 嵌入式 PE DLL |
| 0x1484 | Slot 0: thirdStage 自身 |
| 0x14A4 | Slot 1: forthStage |
| 0x14C4 | Slot 2: fifthStage |
| 0x14E4 | Slot 3: sevenStage |
| 0x1504-0x1584 | 空 slots (4-7) |
| 0x1588 | keysAddr（4 个 keyOffset）|
| 0x15E0 | infoTable |

#### Slot 结构（32 字节）

```
+0x00: addr          加密数据地址
+0x04: size          加密数据大小
+0x08: size2         = size（备份）
+0x0C: comp_size     解密后压缩大小
+0x10: decomp_size   解压后大小（0=不需要解压）
+0x14: cd_size       custom decryptor 大小（0x28 或 0）
+0x18: reserved      0
+0x1C: checksum      校验值
```

Stage 数据在 thirdStage 内的位置：
- Slot 1 (forthStage): ts+0x1E00
- Slot 2 (fifthStage): ts+0x6E00
- Slot 3 (sevenStage): ts+0x8600

---

## 18. EighthStage 内部布局

EighthStage 内部偏移因样本而异，使用自动检测而非固定偏移。

### 参考偏移（仅供调试）

| 用途 | PE32+ (DLL) | PE32+ (EXE) | PE32 |
|------|-------------|-------------|------|
| importTable | +0x2EF0 | +0x4DA8 | ~+0x3C50 |
| fileChecksums | +0x3018 | +0x4DB8 | ~+0x3C68 |
| compressedInfo | +0x2EC8 | +0x4DC0 | ~+0x3C78 |
| zeroList | CDI 内嵌 | +0x4DC8 | ~+0x3C80 |
| fileDecryptor | +0x3070 | +0x5120 | ~+0x40EC |

### 自动检测流程

1. **fileLFSR**: `find_lfsr_block` 扫描 eighthStage 中的所有 LFSR 候选
2. **fileCS**: fileLFSR 前方 gap 处的 (ptr, size) 对，用 trial-decrypt 验证
3. **compressedInfo**: trial-decrypt 后检查压缩块格式
4. **importTable**: 指向全零区域（IDT 未填充）或有效 IDT
5. **zeroList**: trial-decrypt 后为有效 (addr, size) 对

---

## 19. 调试中发现的关键问题

### 1. decrypt_data8 密钥公式误判（PE32+）

**现象**: amdaemon_4、amdaemon_1_dt145 脱壳后段错误。

**原因**: 这些样本使用 `key = page + 1`（非旧公式 `0x8000*(page+1)`）。小 key 值的 XOR 不影响 EP 前 5 字节（sub rsp, 0x28; call），导致 EP prologue 检查看起来正常但 call target 处代码错误（adc 而非 sub rsp）。

**修复**: 三路自动检测（none / page+1 / 0x8000*(page+1)），检查 EP prologue + call target 质量评分。

### 2. decrypt_data8 自动检测对 PE32 无效

**现象**: chusanApp 2.45/2.40 选错公式，.text 匹配率仅 88%。

**原因**: PE32 的 EP 经常是 JMP thunk 表而非标准 prologue，EP 评分法失效。

**修复**: 改用 0xCC (int3) 填充字节计数法，在 .text 内部页面取样。

### 3. PE32 sevenStage LFSR 前向扫描选错

**现象**: chusanApp PE32 脱壳时 "could not locate file LFSR in eighthStage"。

**原因**: sevenStage 有多个 LFSR 块（如 0x673 和 0xA30），前向扫描选了第一个（反调试代码），导致 customDecryptor 错误，eighthStage 解密失败。

**修复**: 改为后向扫描（与 PE32+ 一致），取最后一个 LFSR 块。

### 4. PE32 eighthStageKey 固定偏移不通用

**现象**: 固定 `seven_dsz - 0xD0` 定位 eighthStageKey 对部分样本不适用。

**修复**: 改为暴力搜索（与 PE32+ 一致），从 customDecryptor 附近和 sevenStage 尾部搜索候选。

### 5. fileCS 循环越界

**现象**: PE32 文件数据解压产生垃圾。

**原因**: fileCS 的 size 字段必须限制循环次数，否则 `decrypt_data5` 越界解密相邻的 compressedInfo。

### 6. Import 表双重解密

**现象**: PE32 导入函数名乱码。

**原因**: ILT 和 IAT 共享同一组 hint/name 条目，遍历两次会将已解密的名字重新加密。

**修复**: 只走 ILT 即可。

### 7. ThirdStage 对位置

**现象**: PE32 stages 5-8 解密失败。

**原因**: ThirdStage 加密对在 ss+0xB8C（DP 数组后），不在 DP 内。PE32 ThirdStage 是原地解密（in_place=True）。

### 8. TLS 目录全零导致 0xC0000005

**现象**: chusanApp io4 版本（2.45、2.40）脱壳后启动即崩溃 (0xC0000005)。

**原因**: CrackProof 的解压块不覆盖 .rdata 中的 IMAGE_TLS_DIRECTORY32 结构体，24 字节全零。`AddressOfIndex = 0` 导致 PE loader 写入 NULL 地址。

**修复**: 检测 TLS 结构全零时，从 .tls 和 .data 节信息重建有效的 TLS 目录结构。

### 9. IAT 目录不匹配

**现象**: PE32 脱壳文件与参考文件的 PE 头不一致。

**原因**: 参考文件的 IAT 数据目录为 0/0，而脚本设置了计算值。

**修复**: 清除 IAT 数据目录（pe+0xD8 = 0, pe+0xDC = 0）。

---

## 20. 测试结果

### amdaemon (PE32+) — 全部通过

| 样本 | Layout | decrypt_data8 | 脱壳 | 运行(log) |
|------|--------|---------------|------|-----------|
| amdaemon_3 | B | none | ✓ | ✓ |
| amdaemon_4_fgo1151 | A | key=page+1 | ✓ | ✓ |
| amdaemon_2.45_io4 | A | key=0x8000*(page+1) | ✓ | ✓ |
| amdaemon_2 | B | none | ✓ | ✓ |
| amdaemon_1_dt145 | A | key=page+1 | ✓ | ✓ |

### chusanApp (PE32) — .text 匹配率

| 样本 | decrypt_data8 | .text 匹配率 | 脱壳 | 备注 |
|------|---------------|-------------|------|------|
| chusanApp_2.45_io4 | 0x8000*(page+1) | 100.00% | ✓ | TLS 重建 |
| chusanApp_2.40_io4 | 0x8000*(page+1) | 100.00% | ✓ | TLS 重建 |
| chusanApp_2.25_odd | page+1 | 99.91% | ✓ | |
| chusanApp_2.20_odd | page+1 | 100.00% | ✓ | |
| chusanApp_2.16_odd | page+1 | 100.00% | ✓ | |
| chusanApp_2.10_odd | page+1 | 100.00% | ✓ | 7345 数据块, 22 DLL |
| chusanApp_2.05_odd | page+1 | 100.00% | ✓ | |
| chusanApp_2.00_odd | — | 30.16% | ✓* | 结构差异较大 |
| chusanApp_HJ_1.20_odd | — | 2.92% | ✓* | 暂未研究 |

\* 脱壳流程完成但 .text 匹配率低，可能存在其他结构差异。

---

## 21. 修改记录

### 2025-03-11: PE32 decrypt_data8 + TLS + IAT 修复

1. **decrypt_data8 PE32 自动检测**: EP 评分法对 JMP thunk 不适用，改为 0xCC int3 填充计数
   - 2.45/2.40 正确选择 0x8000*(page+1)，匹配率从 88% 提升到 100%
   - 2.16/2.10/2.05 正确选择 page+1，保持 100%
2. **TLS 目录重建**: 检测全零 TLS 结构，从 .tls/.data 节信息重建，防止 0xC0000005
3. **IAT 目录清除**: PE32 的 IAT 数据目录设为 0/0，与参考工具行为一致

### 2025-03-10: amdaemon 全样本成功 + PE32 eighthStage 修复

1. **decrypt_data8 双密钥公式**: 发现 `key = page + 1`（新版）vs `key = 0x8000*(page+1)`（旧版）
2. **三路自动检测**: EP prologue + call target 质量评分（PE32+ 路径）
3. **PE32 sevenStage LFSR**: 前向扫描改为后向扫描，取最后一个 LFSR 块
4. **PE32 eighthStageKey**: 固定偏移改为暴力搜索

### 2025-03-09: PE32+ 老壳/新壳区分

1. **decrypt_data8 区分**: 老壳按 C# 参考方式，新壳保持原有方式
2. **数据目录恢复**: 老壳恢复全部 16 个，新壳仅 Import/Resource
3. **入口点**: 老壳从 info[3]+0x40 读取，新壳 CRT 模式搜索
4. **导入表重建**: IDT 有效时原位解密，无效时 IAT scan + IDT 重建

### 2025-03-08 及之前: PE32 支持

1. PE32 (32-bit) 整体支持：Stages 1-8 + 文件数据管线
2. `find_tbl` 偏移表定位
3. EighthStage 内部表自动检测
4. PE32 固定偏移和 DP 索引映射

---

## 22. 参考文件

| 文件 | 说明 |
|------|------|
| `F:\decrypt_crackproof.py` | 当前工作脚本 |
| `F:\SEGA\DecryptCrackproofDll64\Program.cs` | C# DLL 脱壳工具源码（参考实现）|
| `F:\SEGA\sega-master\DecryptCrackproofExe64\DecryptCrackproofExe64.exe` | C# EXE 脱壳工具（二进制）|
| `F:\decompiled.cs` | C# EXE 工具反编译（DecryptData8 行 658, DecryptData5 行 341）|
| `F:\decrypt_crackproof0226-0245.py` | 旧版 Python 脚本 |
| `F:\SEGA\DecryptCrackproofDll64\aes_sbox` 等 | AES 查找表文件 |
