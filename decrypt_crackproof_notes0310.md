# CrackProof Shell Unpacker 技术文档

`decrypt_crackproof.py` — 用于解包受 CrackProof 保护的 PE32/PE32+ 可执行文件。

## 使用方法

```bash
python decrypt_crackproof.py <input.exe> [aes_tables_dir]
```

- 输出: `<input>.unpack.exe`
- AES 表默认路径: `F:\SEGA\DecryptCrackproofDll64\`（含 `aes_sbox`, `aes_colum_mix1~4`）
- 脚本通过 PE 可选头魔数（`0x10B` = PE32, `0x20B` = PE32+）自动判断位数

## 脱壳流程（8 层嵌套解密 + 后处理）

### Stage 1: DecryptData1（通用）

从文件尾部读取加密的 info 数组（8 个 uint32）：

| 字段 | 含义 |
|------|------|
| info[0] | 解密种子 |
| info[1] | 0x4E4E4F4B ("KONN" magic) |
| info[2] | shell 偏移 |
| info[3] | 数据基地址（壳代码起始）|
| info[4] | shell 大小 |
| info[6] | shell 基地址 |
| info[7] | 尾部标记大小 |

### Stage 2: DecryptData2（通用）

解密 shell 区域到内存映像缓冲区。`decrypt_size = info[6] - info[3] + 0x2000`

### Stage 3: SecondStage（PE32/PE32+ 分支）

| 项目 | PE32+ | PE32 |
|------|-------|------|
| 定位方式 | anchor + firstStageCS 扫描 | tbl 偏移表扫描 |
| SS 密钥 | anchor+0x14 | tbl+0x40 |
| SS 对 | fcs+0x40 | tbl+0x98 |

密钥 = `headerChecksum ^ firstStageCS ^ secondStageKey`，用 `decrypt_data3(shift=21)` 解密。

### Stage 4: ThirdStage

从 SecondStage 提取 thirdStageKey 和 forthStageKey，处理 infoTable，提取 keyOffsets[0..3]。

| keyOffset | 用途 |
|-----------|------|
| [0] | LZ 解压查找表 |
| [1] | LZ 解压查找表（备选）|
| [2] | AES-256 密钥调度 |
| [3] | AES-256 密钥调度（备选）|

### Stage 5-7: ForthStage / FifthStage / SevenStage

逐层解密解压，每层使用不同校验和组合作为密钥。SevenStage 包含 customDecryptor（LFSR 多态解密器）。

**SevenStage LFSR 扫描**：SevenStage 内有多个 LFSR 块，必须用**后向扫描**取最后一个（实际 customDecryptor）。前面的 LFSR 属于反调试代码。

### Stage 8: EighthStage

使用 customDecryptor 解密。eighthStageKey 通过暴力搜索定位（从 customDecryptor 位置向前搜索多个 gap，逐个尝试 decrypt_and_decompress）。

### 最终阶段：文件数据解密

1. zeroList 清零指定内存区域
2. 逐块解压文件数据：原始文件复制 → AES 解密 → LFSR 自定义解密 → LZ 解压
3. 节表修复（SizeOfRawData = VirtualSize, PointerToRawData = VirtualAddress）
4. .rdata characteristics 设为 0xC0000040（RW，供 loader 写入 IAT）
5. decrypt_data8 解密 .text 段（EXE 特有，按页加密）
6. 导入表恢复/重建
7. 入口点修复

## 解密函数说明

| 函数 | 用途 |
|------|------|
| decrypt_data1 | 从文件尾部解密 info 数组 |
| decrypt_data2 | 解密壳代码到内存映像 |
| decrypt_data3 | 带移位的 XOR 解密（Stage 3/4）|
| decrypt_data4 | 8 字节 XOR 解密 |
| decrypt_data5 | 旋转+XOR 密码（地址低字节为密钥）|
| decrypt_data6 | LFSR 解密（多态代码）|
| decrypt_data7 | 半字节交换+减法（导入函数名，key = rva & 0xFF）|
| decrypt_data8 | 按 16 字节块 XOR（.text 按页加密，ror32(key,15) 递推）|
| aes_decrypt | AES-ECB 解密 |
| decompress | LZ 变种解压（Huffman 风格变长编码表）|
| decrypt_and_decompress | AES + DecryptData3 + 可选自定义解密 + LZ |
| generate_custom_decryptor | 从多态代码生成 LFSR 字节解密函数 |

## DecryptData8 详解

CrackProof 对 EXE 的 .text 段按页（0x1000 字节 / 256 个 16 字节块）加密。每页独立调用 decrypt_data8，循环从 block 1 开始（跳过 block 0），每个 16 字节块 XOR 修改 1 字节。

### 双密钥公式

不同版本的 CrackProof 使用不同的密钥公式：

| 公式 | 计算方式 | 适用 |
|------|----------|------|
| page+1 | `key = page_index + 1` | 较新版本（amdaemon_4, amdaemon_1_dt145）|
| 0x8000*(page+1) | `key = 0x8000 * (page_index + 1)` | 较旧版本（amdaemon_2.45_io4）|

### 自动检测机制

仅对 Layout A 样本执行（Layout B 不需要 decrypt_data8）。对三个选项（无解密 / page+1 / 0x8000*(page+1)）在 EP 所在页和 call target 所在页做测试解密，通过 EP 质量评分选择最优：

| 检查项 | 得分 |
|--------|------|
| EP 处 `48 83 EC 28 E8`（sub rsp, 0x28; call） | +10 |
| call 目标前 16 字节内有 `48 83 EC XX`（sub rsp, XX） | +20 |
| call 目标处 `48 89`（mov [rsp+...], reg） | +5 |

### 密钥公式发现过程

对比 amdaemon_3（正常）与 amdaemon_1_dt145（失败）的 .text 段：
- 339,743 字节差异，每 16 字节块恰好 1 个 → decrypt_data8 特征
- 旧公式 `key = 0x8000*(page+1)` 反而增加差异到 596,124
- 暴力搜索：page 0 正确 key = 1, page 1 = 2 → `key = page + 1`
- EP prologue 检查误判原因：小 key 的 XOR 字节不落在 EP 前 5 字节，但 call target 处代码是错的（adc 而非 sub rsp）

## PE32+ 与 PE32 差异对照

### Shell 定位与偏移

| 项目 | PE32+ (64位) | PE32 (32位) |
|------|-------------|-------------|
| Shell 定位 | anchor/fcs 扫描 | tbl 偏移表扫描 |
| PE 头恢复 | anchor+0x08/0x04 | tbl+0xBC→PE+0x80, tbl+0xC8→PE+0x88 |
| Header 校验和 | fcs+0x80, checksum_with_size_xor | tbl+0x58, crc32^size |
| SS 内部偏移 | 三零模式动态定位 | 固定: 0x964/0x968/0x96C/0xA9C |
| DP 索引 | [5]=forth [6]=fifth [8]=seven [13]=eighth | [4]=forth [5]=fifth [7]=seven [12]=eighth |
| IAT 条目大小 | 8 字节 (QWORD) | 4 字节 (DWORD) |
| PE 数据目录偏移 | pe+0x88 (136字节) | pe+0x78 (128字节) |

### SevenStage → EighthStage

| 项目 | PE32+ | PE32 |
|------|-------|------|
| customDecryptor LFSR | 后向扫描 sevenStage | 后向扫描 sevenStage（已修复） |
| EighthKey 定位 | 暴力搜索 customDecryptor 附近 | 暴力搜索 customDecryptor 附近（已修复） |

### EighthStage 内部布局

eighthStage 内部偏移因样本而异，当前使用自动检测：
- **fileLFSR**: 扫描所有 LFSR 候选，后向匹配有效 fileCS 指针
- **fileCS**: fileLFSR 前方 gap 处的指针，trial-decrypt 验证
- **compressedInfo**: 指针指向的数据 trial-decrypt 后满足压缩块格式
- **importTable**: 指针指向全零区域（IDT 未填充）
- **zeroList**: 指针指向的数据 trial-decrypt 后为有效 (addr, size) 对

### 导入表处理

| PE32+ | PE32 |
|-------|------|
| IDT 有效（老壳）: decrypt_data7 原位解密 | 使用 eighthStage importTable 指向的 IDT |
| IDT 无效（新壳）: IAT scan + 函数名识别 + IDT 重建 | ILT 优先遍历，避免双重解密 |

### 入口点

| PE32+ | PE32 |
|-------|------|
| 老壳: info[3]+0x40 读取（DecryptData5 解密） | 使用原始 PE 头 EP（CrackProof 未修改） |
| 新壳: 搜索 CRT 模式 `sub rsp,28h; call; add rsp,28h; jmp` | |

## PE32+ 老壳/新壳区分

PE32+ 样本存在两种壳版本（通过 ss_size 区分）：

| 项目 | 老壳 (ss_size=0x10C8) | 新壳 (ss_size=0x10B8/0x1158) |
|------|----------------------|------------------------------|
| 数据目录恢复 | DecryptData5 解密 info[3]+0x40, 恢复全部 16 个 | 仅恢复 Import/Resource, 清零 BaseReloc |
| EP | info[3]+0x40 读取 | CRT 模式搜索 |
| Subsystem | 2 (GUI) | 3 (CUI) |
| DllCharacteristics | 0x0060 | 0x0000 |
| IDT | 有效，原位解密 | 无效，需重建 |

## PE32 SecondStage 布局

| 偏移 | 内容 |
|------|------|
| 0x000 | ss 自身地址 |
| 0x004-0x390 | 代码区 (obfuscated x86) |
| 0x964 | forthStageKey |
| 0x968 | thirdStageKey |
| 0x96C | checksum pairs (4 对 addr+size) |
| 0xA9C | DP 基址 |
| 0xAAC | 14 个 entries (每个 16 字节) |
| 0xB8C | thirdStage pair |
| 0xBD0 | ss_size 结束 |

## PE32 ThirdStage 布局

| 偏移 | 内容 |
|------|------|
| 0x000-0x673 | 代码/数据 |
| 0x674-0x1483 | 嵌入式 PE DLL |
| 0x1484 | Slot 0: thirdStage 自身 |
| 0x14A4 | Slot 1: forthStage |
| 0x14C4 | Slot 2: fifthStage |
| 0x14E4 | Slot 3: sevenStage |
| 0x1588 | keysAddr (4 个 keyOffset) |
| 0x15E0 | infoTable |

Slot 结构 (32 字节): addr(4) + size(4) + size2(4) + comp_size(4) + decomp_size(4) + cd_size(4) + reserved(4) + checksum(4)

## 调试中发现的关键问题

### 1. decrypt_data8 密钥公式误判

**现象**: amdaemon_4、amdaemon_1_dt145 脱壳后段错误。

**原因**: 这些样本使用 `key = page + 1`（非旧公式 `0x8000*(page+1)`）。小 key 值的 XOR 不影响 EP 前 5 字节，导致 EP prologue 检查看起来正常但 call target 处代码错误。

**修复**: 三路自动检测，检查 EP prologue + call target 质量评分。

### 2. PE32 sevenStage LFSR 前向扫描选错

**现象**: chusanApp PE32 脱壳时 "could not locate file LFSR in eighthStage"。

**原因**: sevenStage 有多个 LFSR 块（如 0x673 和 0xA30），前向扫描选了第一个（反调试代码），导致 customDecryptor 错误，eighthStage 解密失败。

**修复**: 改为后向扫描（与 PE32+ 一致），取最后一个 LFSR 块。

### 3. PE32 eighthStageKey 固定偏移不通用

**现象**: 固定 `seven_dsz - 0xD0` 定位 eighthStageKey 对部分样本不适用。

**修复**: 改为暴力搜索（与 PE32+ 一致），从 customDecryptor 附近和 sevenStage 尾部搜索候选。

### 4. fileCS 循环越界

**现象**: PE32 文件数据解压产生垃圾。

**原因**: fileCS 的 size 字段必须限制循环次数，否则 decrypt_data5 越界解密相邻的 compressedInfo。

### 5. Import 表双重解密

**现象**: PE32 导入函数名乱码。

**原因**: ILT 和 IAT 共享 hint/name 条目，遍历两次会将已解密的名字重新加密。只走 ILT 即可。

### 6. ThirdStage 对位置

**现象**: PE32 stages 5-8 解密失败。

**原因**: ThirdStage 加密对在 ss+0xB8C（DP 数组后），不在 DP 内。PE32 ThirdStage 是原地解密（in_place=True）。

## 测试结果

### amdaemon (PE32+) — 全部通过

| 样本 | Layout | decrypt_data8 | 脱壳 | 运行(log) |
|------|--------|---------------|------|-----------|
| amdaemon_3 | B | none | ✓ | ✓ |
| amdaemon_4_fgo1151 | A | key=page+1 | ✓ | ✓ |
| amdaemon_2.45_io4 | A | key=0x8000*(page+1) | ✓ | ✓ |
| amdaemon_2 | B | none | ✓ | ✓ |
| amdaemon_1_dt145 | A | key=page+1 | ✓ | ✓ |

### chusanApp (PE32) — 脱壳通过，运行待验证

| 样本 | 脱壳 | 备注 |
|------|------|------|
| chusanApp_2.00_odd | ✓ | 7214 数据块, 22 DLL |
| chusanApp_2.05_odd | ✓ | |
| chusanApp_2.10_odd | ✓ | 7345 数据块, 22 DLL |
| chusanApp_2.16_odd | ✓ | |
| chusanApp_2.20_odd | ✓ | |
| chusanApp_2.25_odd | ✓ | |
| chusanApp_2.40_io4 | ✓ | |
| chusanApp_2.45_io4 | ✓ | |
| chusanApp_HJ_1.20_odd | ✓ | |

## 参考

- C# DLL 脱壳工具: `F:\SEGA\DecryptCrackproofDll64\Program.cs`
- C# EXE 脱壳工具: `F:\SEGA\sega-master\DecryptCrackproofExe64\DecryptCrackproofExe64.exe`
- C# 反编译: `F:\decompiled.cs`
- 旧版 Python 脚本: `F:\decrypt_crackproof0226-0245.py`
