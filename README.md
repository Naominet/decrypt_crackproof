# CrackProof Shell Unpacker

`decrypt_crackproof.py` 用于解包受 CrackProof 保护的 PE32 / PE32+ 可执行文件，主要覆盖 SEGA 街机相关样本，包括 amdaemon、chusanApp、Assembly-CSharp、UE5 大型 EXE 以及 SEGA System 小工具。

## 使用方法

```bash
python decrypt_crackproof.py <input.exe> [aes_tables_dir]
```

- 输出文件：`<input>.unpack.exe`
- AES 表默认路径：`F:\SEGA\DecryptCrackproofDll64\`
- 位数自动识别：`0x10B` 为 PE32，`0x20B` 为 PE32+

## 当前能力

- 支持 PE32 与 PE32+ 两条路径。
- 完成 8 层壳解密、文件数据解密、节表修复、导入表恢复、入口点修复和 PE 头清理。
- 支持 `.text` 页级 `decrypt_data8` 自动检测。
- 支持 .NET COR20 header 与 BSJB MetaData 恢复。
- 对 COR20、TLS、BaseReloc、DllCharacteristics 等常见加载崩溃源做 defensive cleanup。
- 已在 100 个 CrackProof 样本上回归通过，无已知回归。

## 脱壳流程

```text
文件尾部
  -> Stage 1: decrypt_data1 读取 info[8]
  -> Stage 2: decrypt_data2 解密 shell 到内存映像
  -> Stage 3: SecondStage 解密并提取密钥、校验和、阶段指针
  -> Stage 4: ThirdStage 解密并提取 keyOffsets / infoTable
  -> Stage 5: ForthStage 解密解压
  -> Stage 6: FifthStage 解密解压
  -> Stage 7: SevenStage 解密解压并定位 customDecryptor
  -> Stage 8: EighthStage 解密解压并提取文件数据表
  -> 文件数据解密、导入表恢复、入口点修复、PE 头清理
```

最终阶段会从 EighthStage 中提取 `compressedInfo`、`fileCS`、`fileLFSR`、`importTable` 和 `zeroList`，再按块执行 AES、LFSR 与 LZ 解压，把原始文件还原为可加载的内存映像。

## PE32 与 PE32+ 差异

| 项目 | PE32+ | PE32 |
|---|---|---|
| Shell 定位 | anchor / fcs 扫描 | `find_tbl` 偏移表扫描 |
| SecondStage 内部偏移 | 通过 `Kernel32.dll` 锚点动态定位 | 固定偏移：`0x964` / `0x968` / `0x96C` / `0xA9C` |
| DP 索引 | forth=5, fifth=6, seven=8, eighth=13 | forth=4, fifth=5, seven=7, eighth=12 |
| IAT 条目 | 8 字节 QWORD | 4 字节 DWORD |
| AES keyOffset | `keyOffsets[3]` | `keyOffsets[2]` |
| LZ keyOffset | `keyOffsets[1]` | `keyOffsets[0]` |
| 导入表 | IDT 原位解密或 IAT scan + IDT 重建 | 以 ILT 为准遍历，避免 hint/name 双重解密 |
| 入口点 | 老壳读 metadata，新壳搜索 CRT 模式 | metadata EP，失败时回退原 PE 头 EP |

## 关键实现点

### SecondStage

- PE32+：扫描 anchor / fcs，计算 header checksum 与 firstStage checksum，再用 `decrypt_data3(shift=21)` 解密。
- PE32：使用 `find_tbl()` 定位 tbl，header checksum 使用 `crc32(data, pa, ps) ^ ps`。

### ThirdStage

- 使用 `decrypt_data3(shift=19)` 解密。
- 自动扫描 `infoTable`，提取 4 组 `keyOffsets`。
- PE32 的 ThirdStage pair 位于 `ss + 0xB8C`，在 DP 数组之后，且需要原地解密。

### SevenStage / EighthStage

- SevenStage 内可能有多个 LFSR 块，必须后向扫描，取最后一个实际 customDecryptor。
- EighthStage key 不依赖固定偏移，使用候选 key trial-decrypt 方式搜索。
- EighthStage 内部表不使用固定偏移，按 LFSR、fileCS、compressedInfo、importTable、zeroList 的有效性自动检测。

### decrypt_data8

CrackProof 对部分 EXE 的 `.text` 段按页加密，每页 0x1000 字节，每 16 字节块修改 1 字节。已知密钥公式包括：

| 公式 | 适用样本 |
|---|---|
| `key = page_index + 1` | 较新版本，如 amdaemon_4、amdaemon_1_dt145、部分 chusanApp |
| `key = 0x8000 * (page_index + 1)` | 较旧版本，如 amdaemon_2.45_io4、chusanApp 2.40/2.45 |

检测策略：

- PE32+：结合 EP prologue、call target 与实际指令质量评分。
- PE32 / 特殊样本：只统计 `decrypt_data8` 实际修改位置的 `0xCC` 命中率，避免整页 `0xCC` 统计噪声误判。

### 导入表与 PE 头

- PE32+ 老壳：有效 IDT 原位解密。
- PE32+ 新壳：IAT scan、函数名识别、IDT 重建。
- PE32：优先遍历 ILT，避免 ILT/IAT 共享 hint/name 时重复解密。
- DLL 名会规范化为 lowercase，避免 CrackProof 的大小写混淆标识残留。
- 假 COR20、全零 TLS、无效 BaseReloc、异常 DllCharacteristics 会被清理，避免 loader 阶段崩溃。

## 重要修复记录

- 修复 PE32+ `decrypt_data8` 密钥公式误判，支持 `page+1` 与 `0x8000*(page+1)`。
- 修复 PE32 SevenStage LFSR 前向扫描选错问题，统一改为后向扫描。
- 修复 PE32 EighthStage key 固定偏移不通用问题，改为候选搜索。
- 修复 fileCS 循环越界导致 compressedInfo 被误解密的问题。
- 修复 PE32 导入表 hint/name 双重解密问题。
- 修复 PE32 TLS 目录全零导致 `0xC0000005` 的问题。
- 修复 PE32+ Layout A/B 启发式误判，改为 dual-decrypt 后按 EP 合法性选择。
- 修复小 image 低 RVA 指针被过滤导致 compressedInfo 找不到的问题。
- 修复 .NET 样本 COR20 header 与 BSJB MetaData 未恢复导致 DIE / CLR 识别失败的问题。
- 修复 `sevenKey` ASCII 候选被误过滤导致 sgimagemount stage 7 失败的问题。
- 修复 sgxmaster `.text` 解密启发式误判与 TLS loader 崩溃问题。

## 回归结果

- `F:\0000amdaemon\crackproof`：81 个样本全部通过。
- `C:\Windows\SEGA\System`：15 个样本全部通过。
- `L:\0001_StandardCommon_111\System\sgxmaster.exe`：脱壳与启动验证通过。
- 汇总：100 个 CrackProof 样本脱壳成功，其中 native 与 .NET 样本均覆盖。

## 参考材料

- `F:\SEGA\DecryptCrackproofDll64\Program.cs`：C# DLL 脱壳参考实现。
- `F:\SEGA\sega-master\DecryptCrackproofExe64\DecryptCrackproofExe64.exe`：C# EXE 脱壳参考工具。
- `F:\decompiled.cs`：C# EXE 工具反编译参考。
- `F:\decrypt_crackproof0226-0245.py`：旧版 Python 脚本。
