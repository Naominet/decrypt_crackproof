# decrypt_crackproof.py 修改记录

## 2025-03-10 修改：amdaemon 全样本脱壳成功 + PE32 eighthStage 修复

### 问题背景

5 个 amdaemon PE32+ 样本中，3 个能正常生成 log 文件，2 个（amdaemon_4_fgo1151、amdaemon_1_dt145）脱壳后段错误。

### 根因分析

#### 1. decrypt_data8 密钥公式存在两个版本

通过对比 amdaemon_3（正常）和 amdaemon_1_dt145（失败）的 .text 段发现：
- 两者 EP 相同（0x282820）、.text 大小相同（0x53C000）—— 是同一个基础二进制
- 339,743 字节差异，**恰好每 16 字节块 1 个差异**，0 个多差异块 —— 正是 decrypt_data8 的特征
- 使用旧公式 `key = 0x8000 * (page + 1)` 反而使差异从 339,743 **增加**到 596,124

暴力搜索发现 page 0 的正确 key = 1，page 1 的正确 key = 2... 即：

```
新公式: key = page + 1        （amdaemon_4、amdaemon_1_dt145）
旧公式: key = 0x8000 * (page + 1)  （amdaemon_2.45_io4）
```

#### 2. 为什么原来的 EP prologue 检查会误判

对于 `key = page + 1`（小值），decrypt_data8 的 XOR 字节不会落在 EP 的前 5 字节（sub rsp, 0x28; call），所以 EP prologue 看起来始终有效，原代码跳过了 decrypt_data8。但 EP call 目标处的代码是错的（adc 而非 sub rsp），导致运行时段错误。

### 修复方案

#### decrypt_data8 三路自动检测（PE32+ 路径）

替换原来的单一 EP prologue 检查，改为对三个选项评分：

| 选项 | 密钥公式 | 适用版本 |
|------|----------|----------|
| none | 不执行 decrypt_data8 | Layout B 样本 |
| page+1 | `key = page + 1` | 较新的 Layout A |
| 0x8000*(page+1) | `key = 0x8000 * (page + 1)` | 较旧的 Layout A |

评分逻辑（`check_ep_quality`）：
1. EP 处检查 `48 83 EC 28 E8` (sub rsp, 0x28; call rel32) → +10 分
2. 计算 call 目标地址，检查前 16 字节内是否有 `48 83 EC XX` (sub rsp, XX) → +20 分
3. call 目标处 `48 89` (mov [rsp+...]) 模式 → +5 分

优化：只在 EP 所在页和 call target 所在页执行测试解密，选得分最高的公式后应用到整个 .text 段。

#### PE32 sevenStage LFSR 扫描方向修复

PE32 路径原来对 sevenStage 使用**前向扫描**（找第一个 LFSR 块），但 sevenStage 中有多个 LFSR 块：
- 0x673: 反调试代码中的 LFSR（不是 customDecryptor）
- 0xA30: 实际的 customDecryptor LFSR

改为**后向扫描**（找最后一个 LFSR 块），与 PE32+ 路径一致：
```python
scan_start = max(0, seven_dsz // 2)
custom_dec_off = find_lfsr_block(data, seven_start_actual, seven_dsz, scan_start, scan_backward=True)
```

#### PE32 eighthStageKey 暴力搜索

PE32 路径原来使用固定偏移 `seven_dsz - 0xD0` 定位 eighthStageKey，对部分样本可能不适用。改为与 PE32+ 路径相同的暴力搜索策略：
1. 从 customDecryptor 位置向前搜索多个 gap（0x70, 0xD0, 0x28, ...）
2. 从 sevenStage 尾部向前搜索多个 gap（0xD0, 0xC0, 0xE0, ...）
3. 扫描 customDecryptor 前 0x100 范围内的非零/非字符串值
4. 逐个尝试 decrypt_and_decompress，找到能成功解压的即为正确 key

### 测试结果

| 样本 | Layout | decrypt_data8 | 脱壳 | 运行(log) |
|------|--------|---------------|------|-----------|
| amdaemon_3 | B | none | ✓ | ✓ |
| amdaemon_4_fgo1151 | A | key=page+1 | ✓ | ✓ |
| amdaemon_2.45_io4 | A | key=0x8000*(page+1) | ✓ | ✓ |
| amdaemon_2 | B | none | ✓ | ✓ |
| amdaemon_1_dt145 | A | key=page+1 | ✓ | ✓ |

**全部 5 个 amdaemon 样本均成功脱壳并生成 log 文件。**

### 验证数据

amdaemon_1_dt145 修复验证：
- 修复前: .text 段与正常样本有 339,743 字节差异（每 16 字节块 1 字节）
- 使用 key=page+1 后: 差异降至 222 字节（残余差异来自其他加密层）
- EP call target 字节: 修复前 `10 20`（adc 指令），修复后 `EC 20`（sub rsp, 0x20）✓

---

## 2025-03-09 修改：PE32+ 老壳/新壳区分

针对 PE32+ (64-bit) 老壳 amdaemon 脱壳后无法运行的问题，参考 C# 工具 `DecryptCrackproofExe64.exe` 的实现进行了修复。

### 修改内容

#### 1. decrypt_data8 (.text 段解密) — 区分老壳/新壳

- **老壳 (ss_size=0x10C8)**：按 C# 参考方式调用 — `key = 页号`，处理所有 block（包括 block 0）
- **新壳 (ss_size=0x10B8/0x1158) 及 PE32**：保持原有方式 — `key = 0x8000 * (page+1)`，跳过 block 0

#### 2. PE32+ 数据目录恢复 — 区分老壳/新壳

- **老壳**：按 C# 参考，`DecryptData5(info[3]+0x40, 144)` 解密后，从 `info[3]+0x50` 复制 128 字节到 `pe+0x88`，恢复全部 16 个数据目录（Import、Resource、Exception、BaseReloc、Debug 等）
- **新壳**：保持原有方式，仅恢复 Import/Resource 目录，清零 BaseReloc

#### 3. PE32+ 入口点 (EP) — 区分老壳/新壳

- **老壳**：EP 从 `info[3]+0x40` 读取（由 DecryptData5 解密），与 C# 工具一致
- **新壳**：通过 pattern 搜索 `sub rsp,28h; call; add rsp,28h; jmp` 定位 CRT 入口

#### 4. PE32+ Subsystem / DllCharacteristics

- **老壳**：由数据目录恢复自动设置（Subsystem=2 GUI, DllChar=0x0060）
- **新壳**：手动设置 Subsystem=3 Console, DllChar=0x0000

#### 5. PE32+ 导入表重建 — 双路径

- **IDT 有效时（老壳）**：在原位用 DecryptData7 解密 DLL 名和函数名，保留原始 DLL 名大小写
- **IDT 无效时（新壳）**：IAT scan + 函数名识别 + IDT 重建，含 hint/name 重叠检测自动重定位

### 测试结果

| 样本 | 脱壳 | 运行(生成log) | 备注 |
|------|------|---------------|------|
| chusanApp_2.00_odd | ✓ | — | PE32 |
| chusanApp_2.05_odd | ✓ | — | PE32 |
| chusanApp_2.10_odd | ✓ | — | PE32 |
| chusanApp_2.16_odd | ✓ | — | PE32 |
| chusanApp_2.20_odd | ✓ | — | PE32 |
| chusanApp_2.25_odd | ✓ | — | PE32 |
| chusanApp_2.40_io4 | ✓ | — | PE32 |
| chusanApp_2.45_io4 | ✓ | — | PE32 |
| chusanApp_HJ_1.20_odd | ✓ | — | PE32 |
| amdaemon_2.10_odd | ✓ | ✓ | PE32+ 老壳, C# 参考验证一致 |
| amdaemon_2.20_odd | ✓ | ✓ | PE32+ 老壳, C# 参考验证一致 |
| amdaemon_2.45_io4 | ✓ | ✓ | PE32+ 新壳 |
| amdaemon_3 | ✓ | ✗ | PE32+ 老壳, 无 C# 参考, EP 可能有问题 |
| amdaemon_2 | ✓ | ✗ | PE32+ ss_size=0x10B8, 无 C# 参考 |

## 参考

- C# 工具: `F:\SEGA\sega-master\DecryptCrackproofExe64\DecryptCrackproofExe64.exe`
- C# 反编译: `F:\decompiled.cs` — `DecryptData8` (行 658), `DecryptData5` + 数据目录恢复 (行 341-347)
- 旧 Python 脚本: `F:\decrypt_crackproof0226-0245.py`
- C# DLL 脱壳参考: `F:\SEGA\DecryptCrackproofDll64\Program.cs`
