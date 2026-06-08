# CrackProof Shell Unpacker 完整技术文档

`decrypt_crackproof.py` — 用于解包受 CrackProof 保护的 PE32/PE32+ 可执行文件（SEGA 街机游戏）。

本文档为最终合并版（2026-05-23），汇总了 amdaemon / chusanApp / Assembly-CSharp / 大型 UE 游戏等所有已知样本族的处理细节，并记录了多轮修复历史。

## 当前覆盖（2026-05-23 全量测试 84 个样本）

- 81 个 `F:\0000amdaemon\crackproof\*` 样本：全部脱壳成功
- 3 个外部样本（`sgxsegaboot.exe` / `sgosupdate.exe` / `util_sgxsegaboot.dll`，来自 `C:\Windows\SEGA\System\`）：全部脱壳成功
- 覆盖 PE32 / PE32+，包含 amdaemon、Assembly-CSharp.dll (.NET CLR)、UE5 大型 EXE (70MB)、小型系统 DLL/EXE 等多种 layout

详见末尾「修改记录 / 2026-05-23」一节。

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


---

## 修改记录 / 2026-05-23 — 多版本壳兼容修复

针对 C:\Windows\SEGA\System\sgxsegaboot.exe / sgosupdate.exe / util_sgxsegaboot.dll 等小程序脱壳失败、以及 chusanApp_HJ_1.20 / SDGT170GameProject-Win64-Shipping.exe 的 IDT 损坏问题，做了 4 处修复。

### 修复 1: pointer 过滤阈值
**位置**: PE32+ path, eighthStage compressedInfo 扫描

旧代码 if 0x10000 < val < len(data) - 16 把所有 RVA < 0x10000 的指针都过滤掉，导致小程序（image_size < 0x10000）找不到任何 compressedInfo 候选。

**改为** if 0x1000 < val < len(data) - 16，覆盖 info[3] 落在低地址（如 sgosupdate.exe info[3]=0x6000）的情况。

### 修复 2: Layout A/B 判定改为 dual-try
**位置**: PE32+ path, import table reconstruction & metadata restore

旧逻辑用 `u32(data, info[3]+0x10) > 0x10000 → Layout B` 判定。这是 brittle 启发：当 Layout A 的 padding 区恰好含大值时（sgx/sgo/util 都是这种情况）会误判 Layout B，导致 EP 读到 0、import RVA 读到 0。

**改为 dual-try**：
1. 同时试解 Layout A (decrypt_data5(info[3]+0x40, 0x20)) 和 Layout B (decrypt_data5(info[3]+0x10, 0x30))；
2. 谁的 EP 落在 image 内 [0x1000, image_size) 即采用谁；
3. 双方都合理时，按 ss_size 判定（ss_size == 0x10C8 → 老壳 Layout A）。

同时把 metadata restore 阶段的第二次 layout 判定改为复用同一个 is_layout_a 变量。

### 修复 3: PE32 path fileLFSR 候选选择
**位置**: decrypt_crackproof.py:2102

旧逻辑 min(lfsr_candidates, key=lambda c: abs(c - off_file_lfsr)) 选离 expected 绝对距离最小的候选。chusanApp_HJ_1.20 出现 5 个候选 [0x407C, 0x4093, 0x40DC, 0x4111, 0x4201]，expected=0x40FC：
- 正确的是  x40DC（delta -32，与其他 chusanApp_2.20+ 样本一致）
- 旧逻辑选了  x4111（delta +21，是 false candidate）

**改为分层优先**：精确匹配 > 最近的负 delta > 最近的正 delta。

### 修复 4: PE32+ path fileLFSR 候选选择
**位置**: PE32+ path file LFSR loop

旧逻辑 or lfsr_off in reversed(all_lfsrs) 选最后一个有 in-image pointer 的候选。SDGT170GameProject 有 3 个 in-image 候选，最后一个 +0x5060 的 fileCS=0x2A8F624 落在 image 中段；真正的 +0x5000 fileCS=0x45908D0 在 info[3]=0x454B000 之后（符合所有 OK 样本的模式）。

**改为按 fileCS 距 info[3] 的最小正距离选择**：fileCS 必须 ≥ info[3]（fileCS 表在元数据区域之后），选 dist 最小的。fallback 仍是旧 reversed 逻辑（保持已通过样本不回归）。

### 测试结果（修复后）

84 个 CrackProof 样本（包括 .NET CLR DLL、大型 UE5 EXE、小型系统 DLL/EXE）全部脱壳成功，关键样本：

| 样本族 | 数量 | 脱壳 | 关键指标 |
|---|---|---|---|
| amdaemon (PE32+) | 30+ | ✓ | imports 21-23 个 |
| Assembly-CSharp.dll (.NET) | 11 | ✓ | COR20 header 完整，无 native import |
| Sinmai.exe | 9 | ✓ | imports 2 个 |
| chusanApp_*_orig.exe (PE32) | 9 | ✓ | imports 22-35 个 |
| sgxsegaboot/sgosupdate/util_sgxsegaboot | 3 | ✓ | imports 1-3 个 |
| SDGT170GameProject (PE32+, 70MB UE5) | 1 | ✓ | imports 41 个 |
| 其他 (mu3, CardMaker, ServerBox 等) | ~20 | ✓ | imports 17-23 个 |

并行批量耗时约 250s (19 workers)，相比之前的串行 ~660s 快约 2.6×。


---

## 修改记录 / 2026-05-23 (II) — PE32+ metadata 路径重构 + DLL 名规范化

针对用户报告 `util_sgxsegaboot.dll/sgosupdate.exe 脱完还有标识`、`sgxsegaboot.exe 无法启动`，重构 PE32+ path 的 metadata + import + EP 处理：

### 修复 5: PE32+ metadata layout 解析
- 旧逻辑用 `info[3]+0x10` 处的值大小启发式判 Layout，不可靠
- 新逻辑：dual-decrypt（同时尝试 Layout A @+0x40/144B 和 Layout B @+0x10/0x290B），按 EP 是否落在 image 内挑选；ss_size 仅做 tie-break

### 修复 6: Import RVA picker
- metadata 与 anchor 给出的 Import RVA 经常不一致：
  - amdaemon 类：anchor 给 fake、metadata 才是真值
  - sgxsegaboot 类：metadata 不存 import dir（全 0），anchor 才是真值
- 新逻辑：在 `[metadata-B dirs[1], metadata-A dirs[1], anchor]` 三个候选里依次验证 IDT 第一项 NameRVA 非 0、走得通即用

### 修复 7: DLL/函数名解密幂等性
- 旧 guard 只看首字节 ASCII，sgxsegaboot 类 IDT 已是 `KeRnEl32.dLl` 这种全 ASCII 形态（CrackProof 故意 case-混淆），跳过了 decrypt
- 同时 amdaemon 类 IDT 中段可能首字节凑巧 ASCII 但其余加密，旧 guard 误判已解
- 新 guard：仅在整个字符串通过 `all(0x20<=b<0x7F)` 且 `endswith('.dll'|'.exe')` 时跳过 decrypt
- 配合 lowercase normalize 把 `KeRnEl32.dLl` 规范化为 `kernel32.dll`

### 修复 8: COR20 fake header 清零
- CrackProof metadata 在 dirs[14] 留垃圾指针 (RVA=0x2000/0x48)，但目标位置 `cb=0` 不是真 .NET COR20
- 这会让 PE loader 误入 .NET 加载路径，正常 native EXE 加载失败
- 新逻辑：检测 dirs[14] 指向位置 cb 字段为 0 时清零 COR20 directory

### 修复 9: Subsystem 保留 protected 文件原值
- 旧逻辑硬编码 sub=3 (CUI)，破坏了 Windows GUI EXE (如 sgxsegaboot.exe sub=2)
- 新逻辑：`data[:0x1000] = file_data[:0x1000]` 已经从 protected file 复制了 PE 头，Subsystem 字段自然保留正确值

### 简化效果
- PE32+ path 的 metadata + import + EP + .text + section fixup 块从 ~370 行压缩到 ~220 行
- 删除了 `is_layout_a` / `is_dotnet` / `peeked_ep` / 双层 Layout switch 等中间变量
- 单次 `decrypt_data5` 解密块 + 直接 picker，逻辑线性
- 总行数从 2837 行减少到 ~2468 行

### 全量测试结果（84 个样本）
- 81 个 `F:\0000amdaemon\crackproof\*` 样本：**全部 OK**
- 3 个外部样本（sgxsegaboot.exe / sgosupdate.exe / util_sgxsegaboot.dll）：**全部 OK**
- DLL 名输出全部规范化为 lowercase（无 mix-case 标识）
- COR20 fake header 已清零


---

## 修改记录 / 2026-05-23 (III) — .NET MetaData 恢复

针对用户报告 `sgxsegaboot 在 DIE 里看就剩操作系统标识`、`sgosupdate / util_sgxsegaboot 脱完就什么都不是了`：脱壳器漏掉了 **.NET MetaData 复制步骤**。

### 修复 10: .NET COR20 header + BSJB MetaData 恢复

**根因**：所有 5 个 .NET 样本（sgxsegaboot.exe / sgosupdate.exe / util_sgxsegaboot.dll / Assembly-CSharp.dll * 11 / SDGY260AMDaemon.NET.dll）的 protected 文件在 PE 数据目录 `dirs[14]` (CLR) 指向的 RVA 处保留了**真实未加密**的 COR20 header（cb=0x48），以及在 metadata 区指向的 RVA 处保留了完整 BSJB MetaData。但 stage 8 解压**完全没覆盖这两块区域**，导致脱壳后：
- DIE 工具识别不出 .NET assembly
- mscoree._CorExeMain 读 cb=0 失败 → STATUS_DLL_INIT_FAILED (0xC0000142)

**修复**：在 Layout 处理之后、import 处理之前，从 protected file 直接复制：

1. COR20 header (0x48 bytes) 从 `protected[RVA->file_off(CLR_dir.RVA)]` 到 `image[CLR_dir.RVA]`
2. BSJB MetaData (size 由 COR20.MetaData 字段给出) 从 `protected[RVA->file_off(MD.RVA)]` 到 `image[MD.RVA]`

校验：COR20 header 首 dword 必须 == 0x48，BSJB MetaData 首 4 字节必须 == `BSJB`。两个条件都通过才执行复制。

### 测试效果（5 个 .NET 样本）

| 样本 | COR20 RVA | MetaData (RVA/size) | BSJB version |
|---|---|---|---|
| sgxsegaboot.exe | 0x2000 | 0x5F3FC / 0x38F90 | v4.0.30319 |
| sgosupdate.exe | 0x2000 | 0x2610 / 0x1424 | v4.0.30319 |
| util_sgxsegaboot.dll | 0x2000 | 0x40D8 / 0x48BC | v4.0.30319 |
| SDDT115Assembly-CSharp.dll | 0x2008 | 0x188B50 / 0x21894C | v2.0.50727 |
| SDGY260AMDaemon.NET.dll | 0x2008 | 0xAFE4 / 0x20768 | v2.0.50727 |

DIE 现在能正确识别这些样本为 .NET assembly（不再只显示操作系统标识）。

### 最终全量测试（84 个样本）

- 81 个 `F:\0000amdaemon\crackproof\*` 样本 + 3 个外部样本（sgxsegaboot / sgosupdate / util_sgxsegaboot）：**全部成功**
- 其中 14 个 .NET assembly（带 COR20 + BSJB）正确识别为 OK_CLR
- 67 个 native EXE/DLL 正确识别为 OK
- 0 个 BROKEN_imports


---

## 修改记录 / 2026-05-23 (IV) — sevenKey 候选筛选放宽 (sgimagemount.exe 修复)

针对 `C:\Windows\SEGA\System\sgimagemount.exe` 在 stage 7 失败 (`ERROR: could not decrypt sevenStage with any key offset`):

### 修复 11: sevenKey ASCII filter 移除 + 偏移列表扩展

**根因**: sgimagemount.exe 是新版壳 (ss_size=0x1158, fifth_dsz=0x930), 它的 sevenKey 值 `0x4F466231` 字节序列恰好全是 ASCII 可见字符 (`'1bFO'`)。脚本旧逻辑用 `not all(32 <= b < 127 for b in val_bytes)` 把 "看起来像字符串" 的 4 字节 candidate 全过滤掉，结果真正的 sevenKey 被误丢。

**修复**:
- 去掉 ASCII filter — trial-decrypt 本身就是最可靠的 validator, 不需要预过滤
- 候选偏移列表新增 `0x830`, `0x858/0x860/0x868/0x870/0x878/0x880` 等新版壳常见偏移
- 扫描范围从 "最后 0x200 字节" 扩展到 "fifthStage 后半段"

### 测试效果

- **C:\Windows\SEGA\System** 15 个样本全部通过 (10 OK + 5 OK_CLR)
- **F:\0000amdaemon\crackproof** 81 个样本全部通过 (67 OK + 14 OK_CLR), 无回归
- 总计 **99 个样本** 脱壳成功

### SEGA System 全量结果 (15 个)

| 样本 | 类型 | 解压块 | imports |
|---|---|---|---|
| sgimagemount.exe | OK | 103 | 10 |
| sglaunch.exe | OK | 110 | 2 |
| sgsetdisplaysetting.exe | OK | 54 | 3 |
| sgxBootSetup.exe | OK | 94 | 15 |
| sgxkct.exe | OK | 79 | 6 |
| sgxmaster.exe | OK | 161 | 5 |
| sgxprestartup.exe | OK | 47 | 3 |
| sgxsystemdaemon.exe | OK | 488 | 16 |
| util_changeroutersettings.dll | OK | 32 | 13 |
| util_downloadui.dll | OK | 157 | 26 |
| sgosupdate.exe | OK_CLR (.NET v4) | 3 | 3 |
| sgxsegaboot.exe | OK_CLR (.NET v4) | 31 | 3 |
| util_sgxsegaboot.dll | OK_CLR (.NET v4) | 5 | 1 |
| speaker_test_managerMD.dll | OK_CLR (.NET v4) | 19 | 12 |
| system_share_data_wrapperMD.dll | OK_CLR (.NET v4) | 23 | 9 |


---

## 修改记录 / 2026-05-23 (V) — decrypt_data8 启发式重写 (sgxmaster 0xC0000005)

针对用户报告 sgxmaster.exe（包括 `L:\0001_StandardCommon_111\System\` 和 `C:\Windows\SEGA\System\sgxmaster.exeorig`）脱壳后启动报 0xC0000005 (STATUS_ACCESS_VIOLATION)：

### 根因

旧的 0xCC count 启发式有根本缺陷：
- 一个 page 共 4096 字节，decrypt_data8 只修改 255 字节（每 16 字节块的 1 字节）
- 整页 0xCC 总数主要由**未修改**的 ~3841 字节贡献（CrackProof 没动这些字节，跟原文件一致）
- 三个公式 (none/page+1/0x8000*(page+1)) 的 0xCC count 差异通常只 **3-15 字节**（统计噪声范围）
- 旧逻辑贪婪选 score 最高的，碰上 sgxmaster 这种 .text 已被修改但样本 byte 分布特殊的情况，**0x8000*(page+1) 比 none 多 4 个 0xCC**，被选成赢家
- 但实际上 `EP[5..9]` 解出来 `E8 43 09 00 00` (call rel32) 才是正确的，none 是 `83 43 09 00 00` (add rel32)
- 选错就把 .text 整体破坏 → loader 跳到 EP 执行垃圾 → 0xC0000005

之前我加的 `delta < 90 -> skip` 阈值正好把 sgxmaster 这种**真的需要 decrypt_data8** 但 0xCC delta 小的样本也跳过 — 同样错。

### 修复 12: 只统计 decrypt_data8 实际修改位置的 0xCC 命中率

新启发式：**对 decrypt_data8 mutate 的 255 个位置（每 16 字节块的 `ri & 0xF` 偏移），统计有多少在变换后 == 0xCC**。

`python
for bi in range(1, 256):
    rk = ((k >> 15) | (k << 17)) & 0xFFFFFFFF
    ri = (rk + bi) & 0xFFFFFFFF
    k = (ri + bi) & 0xFFFFFFFF
    tidx = bi * 16 + (ri & 0xF)
    mutated = src[tidx] ^ (k & 0xFF)
    if mutated == 0xCC:
        hits += 1
`

baseline `none` 用 `tidx = bi * 16` 等距采样原页面，count 已是 0xCC 的位置。

判定规则：仅当 `best >= 2x baseline` 才应用 decrypt_data8，否则视为已是明文。

### 验证（sgxmaster live + 111）

| 文件 | none hits | page+1 hits | 0x8000*(page+1) hits | 决策 |
|---|---|---|---|---|
| sgxmaster.exeorig (live) | low | low | **high (>2x)** | 应用 0x8000*(page+1) ✓ |
| sgxmaster (2).exeorig (111) | low | low | **high (>2x)** | 应用 0x8000*(page+1) ✓ |

EP 解出：`48 83 EC 28 E8 43 09 00 00 48 83 C4 28 E9 7A FE` (sub rsp, 0x28; call; ...; jmp) — 标准 x64 函数 prologue ✓

### 全量回归

- **F:\0000amdaemon\crackproof** 81 个：全部通过 (67 OK + 14 OK_CLR)
- **C:\Windows\SEGA\System\\*.exeorig/.dllorig** 16 个：全部通过 (11 OK + 5 OK_CLR)
- 包括之前需要 decrypt_data8 的 amdaemon_4 / chusanApp_HJ_1.20 等 — 新启发式正确触发 decrypt_data8

总计 **100 个 CrackProof 样本** 脱壳成功，无回归。


---

## 修改记录 / 2026-05-23 (VI) — TLS 目录清零 (sgxmaster 0xC0000005 真正修复)

针对用户报告 sgxmaster.exe 脱完仍 0xC0000005「应用程序无法正常启动」，用 cdb 调试器精确定位崩溃点：

`ntdll!LdrpAllocateTlsEntry+0xc8: mov dword ptr [rcx],edx  ds:00000000 0000000=????????`

### 根因

CrackProof metadata 把 TLS 数据目录字段填入了一个 RVA (0x85900, size 0x28)，但指向的 `IMAGE_TLS_DIRECTORY64` 结构体**全是 0**（RawStart=0, RawEnd=0, AddressOfIndex=0, AddressOfCallBacks=0）。PE loader 在 process init 期间处理静态 TLS 时调用 `LdrpAllocateTlsEntry` 解引用 NULL 指针 → **STATUS_ACCESS_VIOLATION (0xC0000005) 在 EP 执行之前就抛出**。

之前的 (V) 修复（decrypt_data8 hit-based 启发式）让 EP 处的代码正确解码，但崩溃发生在 EP 之前的 loader 阶段，所以代码看起来正确但程序仍然崩。

### 修复 13: TLS 目录 defensive cleanup

跟 COR20 一样的处理逻辑 —— 检测 TLS dir 指向的结构体若全为 0，就清零 TLS 目录字段：

`python
tls_dir_off = exe_pe + 0xD0
tls_rva = u32(data, tls_dir_off)
if tls_rva and tls_rva + 24 <= len(data):
    raw_start = u64(data, tls_rva)
    raw_end   = u64(data, tls_rva + 8)
    cb_addr   = u64(data, tls_rva + 16)
    if raw_start == 0 and raw_end == 0 and cb_addr == 0:
        w32(data, tls_dir_off, 0)
        w32(data, tls_dir_off + 4, 0)
`

清零后 PE loader 跳过静态 TLS 处理，进程能正常启动。

### 验证（cdb 抓崩溃前后对比）

**修复前**：
- sgxmaster_live.unpack.exe: 启动立即 `ntdll!LdrpAllocateTlsEntry` NULL deref → 0xC0000005
- sgxmaster_111_fresh.unpack.exe: 同上

**修复后**：
- sgxmaster_live.unpack.exe: exit code 0x00000000（进程正常启动，运行完后自然退出）
- sgxmaster_111_fresh.unpack.exe: exit code 0x00000000

### 全量回归（无回归）

- `F:\0000amdaemon\crackproof` 81 个：全部通过 (67 OK + 14 OK_CLR)
- `C:\Windows\SEGA\System\*.exeorig/.dllorig` 15 个：全部通过 (10 OK + 5 OK_CLR)
- L:\0001_StandardCommon_111\System\sgxmaster.exe：脱壳 + 启动均通过

至此，CrackProof 脱壳器对 **PE 头四个常见崩溃源**都做了 defensive cleanup：
1. 修复 8: COR20 (CLR) dir fake header (cb=0)
2. 修复 13: TLS dir 全零结构体（**新**）
3. BaseReloc dir：fake RVA 不指向真实 .reloc 数据时清零
4. DllCharacteristics：清零避免 ASLR 强制
