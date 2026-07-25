# snapfuzz

**LLM 引導的快照模糊測試 · LLM-guided snapshot fuzzing for x86-64 binaries**

給一個 **沒有原始碼** 的 x86-64 Windows 執行檔，自動化整條流程：Ghidra 反編譯 →
LLM 選 fuzz entry → LLM 推導輸入格式與 harness → 產生 C++ wtf 模組 → 擷取快照 →
分散式模糊測試 → crash 去重／分類／重放 → 五訊號 LLM triage → GHSA 報告。

Given an x86-64 Windows binary and **no source**, this automates the whole chain:
Ghidra decompilation → LLM entry selection → LLM-derived input format and harness →
generated C++ wtf module → snapshot acquisition → distributed fuzzing → crash
dedup/classification/replay → five-signal LLM triage → GHSA advisory.

執行引擎是 [**wtf**](docs/README.wtf-upstream.md)。**Ghidra 是必要條件，不是選項** —
harness 是從它的 pseudo-C 推導出來的。

[繁體中文](#繁體中文) · [English](#english)

> 上游 wtf 的 README 保留在 [`docs/README.wtf-upstream.md`](docs/README.wtf-upstream.md)。
> 它是 wtf API 行為的權威參考（CLAUDE.md RULE 2 / §13），沒有刪除。
>
> wtf's own README is preserved at
> [`docs/README.wtf-upstream.md`](docs/README.wtf-upstream.md) — it is the
> authoritative reference for wtf's behaviour and was not deleted.

---

# 繁體中文

- [三步上手](#三步上手)
- [為什麼 Ghidra 是必要的](#為什麼-ghidra-是必要的)
- [準備 Windows 客體 VM](#準備-windows-客體-vm)
- [這是什麼](#這是什麼)
- [逐階段手動用法](#逐階段手動用法)
- [實測結果](#實測結果)
- [目前狀態與誠實的限制](#目前狀態與誠實的限制)
- [倉庫結構](#倉庫結構)
- [設計上不可妥協的四條規則](#設計上不可妥協的四條規則)

## 三步上手

### 第 1 步 — 一個指令裝好環境

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m tools.bootstrap
```

`tools.bootstrap` 會：

- 檢查 Python 套件與 **JDK 21+**（Ghidra 12 的需求；更舊的版本會用一個看起來像
  安裝損毀的 class-version 錯誤失敗）；
- **找不到 Ghidra 就自動下載**（釘死 12.1.2、驗 sha256、解壓到 `third_party/`）；
- 把 Ghidra、`symbolizer-rs`、`kd.exe`、`snapshot.dll` 的路徑**寫進 config**；
- 回報 Hyper-V 與客體 VM 的狀態；
- 用 exit code 區分「不能跑」與「能跑但不能自己擷取快照」。

輸出長這樣：

```
  [  ok   ] Python packages    8 present
  [  ok   ] JDK                java 21 at C:\Program Files\Eclipse Adoptium\jdk-21...
  [  ok   ] Ghidra             D:\tools\ghidra_12.1.2_PUBLIC
  [  ok   ] wtf                D:\wtf-llm\src\build\wtf.exe
  [  ok   ] LLM API key        SNAPFUZZ_LLM_API_KEY in .env
  [  ok   ] symbolizer-rs      D:\tools\symbolizer-rs\symbolizer-rs.exe
  [  ok   ] kd.exe             C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
  [  ok   ] 0vercl0k/snapshot  D:\tools\snapshot\snapshot.dll
  [absent ] Hyper-V guest      Hyper-V 有裝，但這個 shell 查不到（權限不足）

Ready to fuzz an EXISTING snapshot. Not ready to take a new one:
  - Hyper-V guest: ...
```

**Ghidra 為什麼是下載而不是包在 repo 裡**：zip 546 MB、解開 872 MB，而且對所有人
位元完全相同、官方已經在託管。包進 git 會讓每一次 clone 都變成 550 MB 下載，而
bootstrap 一樣達成「不用手動設定」這個目的（有驗 sha256）。真的需要離線機器的話，
`git add third_party/ghidra_*` 就自己 commit 進去 —— `.gitignore` 只是預設不追蹤。

**API key 只放 `.env`**（已 gitignore）。放進 `config/llm.yaml` 會有一個 gate
測試直接失敗：

```powershell
"SNAPFUZZ_LLM_API_KEY=sk-..." | Out-File -Append -Encoding utf8 .env
```

### 第 2 步 — 建置

```powershell
.\.venv\Scripts\python.exe -m fuzzer.build
```

需要 Visual Studio 的 C++ 工具鏈（`fuzzer.build` 自己會找 `vcvars`）。它會把我們的
模組 stage 進 wtf 的 source tree、建 `src/build/wtf.exe`，並驗證 target 有註冊成功。

### 第 3 步 — 跑

**情況 A：已經有快照**（`targets/<name>/state/` 裡有 `mem.dmp` + `regs.json`）

```powershell
.\.venv\Scripts\python.exe -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --workers 2 --minutes 15
```

**情況 B：只有 binary，讓工具自己擷取快照**（需要客體 VM，見下一節）

```powershell
.\.venv\Scripts\python.exe -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --kd-pipe \\.\pipe\snapfuzz `
    --kd-stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --workers 2 --minutes 15
```

兩者的差別只有 `--kd-pipe`：給了就**多出 stage 07a**，用 KD 自己去擷取快照；
沒給就要求 `state/` 已經存在。**不給 `--entry-symbol` 也可以** —— entry 由
stage 03 的 LLM 選，後面的階段用 `<ENTRY>` 佔位符，跑到時才代換。

十三（或十四）個階段：

```
01-pseudoc    Ghidra 在 module 範圍反編譯 → A2 dump
02-a2         A2 dump → SQLite 快取
03-entry      [LLM] 選 fuzz entry
04-blocks     Ghidra 列舉基本區塊 → A3
05-covfile    A3 → wtf 的 .cov 斷點檔
06-datasyms   Ghidra 全域資料符號 → A6
07a-acquire   用 KD 擷取快照（只在給了 --kd-pipe 時出現）
07-snapshot   匯入 state/ → A1
08-inputspec  [LLM] 推導輸入結構 → InputSpec
09-codegen    InputSpec → C++ 標頭（無 LLM）
10-build      建置 wtf + 我們的模組
11-fuzz       [LLM] 活動：master + workers + 慢時鐘
12-analysis   crash 去重、分類、重放、trace（無 LLM）
13-triage     [LLM] 五訊號 triage → GHSA 報告
```

有用的旗標：

```powershell
--list              # 只列階段（含每個階段的注意事項）就結束
--dry-run           # 印出計畫，什麼都不跑
--only 03 08        # 只跑這些階段（前綴比對；打錯會報錯，不會靜默跳過）
--from 10           # 從這個階段開始
--force             # 重跑已經是最新的階段
--scope function-closure   # A2/A3/A6 縮到 entry 的呼叫閉包
```

**沒有階段會因為 exit code 0 就算完成。** 每個階段都指名它必須產出的 artifact，
artifact 才是證據 —— `analyzeHeadless` 和 `wtf` 都會在什麼都沒產出的情況下回傳 0。
另外「活動」和「建置」這種工作是時間而不是檔案，所以它們不會因為上一輪的檔案還在
就被當成最新而跳過。

## 為什麼 Ghidra 是必要的

以前 Ghidra 只負責覆蓋率斷點（A3），那個東西夠固執的人可以手寫。現在它還提供
**模型讀來推導輸入格式與 harness 的 pseudo-C** —— 沒有 Ghidra 就沒有
`InsertTestcase`，fuzzer 沒有東西可以跑。四個 LLM 階段裡有三個直接吃 A2：

| 階段 | 吃什麼 | 產出 |
|---|---|---|
| `03-entry` | 全 module 的函式簽章 + pseudo-C | `FuzzEntry`（哪個函式、哪個暫存器帶輸入／長度） |
| `08-inputspec` | entry 的 pseudo-C **加上它的 caller** | `InputSpec`（欄位、型別、位元組序、長度語意） |
| harness 推導 | entry 閉包的 pseudo-C | `HarnessSpec`（斷點、crash 條件、要打樁的呼叫） |
| `13-triage` | 錯誤位址那個函式的 pseudo-C | 五訊號中的**靜態**訊號 |

**模型不直接寫 C++。** 它填一個 pydantic 可驗證的 schema，再由
`fuzzer/codegen.py`（普通程式碼）轉成 C++。理由是自由格式的 C++ 無法用 schema
檢查，而編譯錯誤會出現在離模型很遠的地方 —— 實測過一次：模型在註解裡用了
U+2011（非斷字連字號），MSVC 在 `/WX` 下用 C4819 把整個建置打掉（D-054）。

## 準備 Windows 客體 VM

只有要**自己擷取快照**時才需要。已經有 `state/` 目錄就跳過這節。

先確認缺什麼：

```powershell
.\.venv\Scripts\python.exe -m tools.bootstrap --vm-check
```

### 1. 建 VM（在主機上，管理員 PowerShell）

```powershell
# 一顆 vCPU、4 GB —— CLAUDE.md §13.6 的要求。多顆 vCPU 會改變快照語意
New-VM -Name snapfuzz-guest -Generation 2 -MemoryStartupBytes 4GB `
       -NewVHDPath D:\vm\snapfuzz-guest.vhdx -NewVHDSizeBytes 64GB
Set-VMProcessor -VMName snapfuzz-guest -Count 1
Set-VMMemory  -VMName snapfuzz-guest -DynamicMemoryEnabled $false

# 掛 Windows 安裝 ISO，開機安裝
Add-VMDvdDrive -VMName snapfuzz-guest -Path D:\iso\windows.iso
Start-VM snapfuzz-guest
```

### 2. 在客體裡開核心除錯

```powershell
# 客體內，管理員
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
# bcdedit 拒絕的話（Gen2 + Secure Boot），先在主機關掉 Secure Boot：
#   Set-VMFirmware -VMName snapfuzz-guest -EnableSecureBoot Off
```

然後把目標執行檔（以及它的相依 DLL）複製進客體，關機。

### 3. 把客體的 COM1 接到主機的具名管線

```powershell
# 主機，管理員。管線名字要跟 --kd-pipe 一致
Set-VMComPort -VMName snapfuzz-guest -Number 1 -Path \\.\pipe\snapfuzz
Start-VM snapfuzz-guest
```

### 4. 在客體裡把目標跑起來

服務型目標就讓它在那邊監聽。**這一步不能自動化的部分只有一個**：得有東西讓目標
真的走到 parser。`--kd-stimulus` 就是幹這件事的，`tools/poke_tcp.py` 提供了通用版本
（可選長度前綴、會重試等服務起來），但**送什麼、送到哪個 port 沒辦法從 binary 推出來**
—— port 得自己在 Ghidra 裡找 `bind`/`htons`，或在客體裡 `netstat -ano` 看。

```powershell
# tlv_server 的一個 Allocate 指令：4 位元組 command、2 位元組 Id、2 位元組長度、body
python -m tools.poke_tcp --port 1337 --length-prefix u32le --hex 00000000 3905 0200 0102
```

### 5. 擷取

pipeline 會自己做，但也可以單獨跑：

```powershell
# 先看它到底會下什麼命令，不用 VM 也能檢查
.\.venv\Scripts\python.exe -m prep.snapshot_win acquire `
    --state targets\snapfuzz\state --pipe \\.\pipe\snapfuzz `
    --module tlv_server --break-at ProcessPacket --dry-run

# 真的擷取
.\.venv\Scripts\python.exe -m prep.snapshot_win acquire `
    --state targets\snapfuzz\state --pipe \\.\pipe\snapfuzz `
    --module tlv_server --break-at ProcessPacket `
    --stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --timeout 900
```

實際下的命令是：

```
kd.exe -k com:pipe,port=\\.\pipe\snapfuzz,resets=0,reconnect
       -c ".load D:\tools\snapshot\snapshot.dll;
           bp tlv_server!ProcessPacket \"!snapshot -k full <state>; qq\";
           g"
```

**工作掛在斷點上，不是排在 `-c` 字串裡 `g` 的後面。** KD 沒有保證 `g` 命中之後會
繼續執行那個字串剩下的部分；掛在 `bp` 上是可靠的寫法。而且斷點**本身就是**「哪個
狀態值得快照」的定義 —— 命中就是判斷完成，不需要有人在旁邊看。

32 位元目標加 `--wow64`（會在快照前先 `!wow64exts.sw` 切到 64 位元 context；
事後才切的話抓到的是 32 位元視角，wtf 用不了，而且會在很久以後才以奇怪的 wtf
錯誤爆出來）。

**沒 VM 會怎樣**：`--kd-pipe` 前置檢查在任何階段跑之前就會擋下來並說明缺什麼；
真的接不上 KD 的話會在 `--timeout` 秒後失敗，訊息直接指出最常見的原因是沒有
stimulus。它**不會**假裝成功 —— `mem.dmp` 和 `regs.json` 沒出現就是失敗，
kd 回傳 0 不算證據。

## 這是什麼

三個階段的流水線：

```
① 目標準備   二進位檔 → Ghidra 靜態分析 + 快照擷取
             ├─ A1 快照        state/  (mem.dmp, regs.json, symbol-store.json)
             ├─ A2 pseudo-C    SQLite，依 (module, static_addr) 索引
             ├─ A3 覆蓋率斷點  基本區塊 RVA → wtf 的 .cov 格式
             └─ A6 全域符號    位址、大小、與下一個符號的間距

② 模糊測試   master + N workers + 慢時鐘 sidecar（三種行程）
             ├─ 快時鐘  master 產生測試案例、worker 執行、回報覆蓋率
             └─ 慢時鐘  偵測 plateau → LLM 讀 pseudo-C 產生種子 → 注入語料庫
             ├─ A4 語料庫      outputs/ (minset)
             └─ A5 crash       crashes/

③ 安全分析   五個獨立訊號 → LLM triage → GHSA 報告
             1 去重（stack hash）2 分類（錯誤位址/暫存器）3 確定性重放
             4 符號化執行 trace（動態）  5 逆向脈絡（靜態）
```

### 兩個時鐘，這是整個設計的核心

| | 快時鐘 | 慢時鐘 |
|---|---|---|
| 是什麼 | wtf 的執行迴圈（master + workers） | LLM 的工作 |
| 尺度 | 微秒～毫秒，每秒數千次 | 秒級，事件驅動 |
| LLM | **絕對沒有** | 全部在這裡 |
| 住在哪 | `wtf master` + `wtf fuzz` 行程 | 獨立的 sidecar 行程 |

**master 也算快時鐘。** 它服務每一個 worker，在裡面呼叫 LLM 會卡住整個 worker
pool。所以慢時鐘是**獨立行程**，用檔案介面跟 master 溝通：讀 `coverage.cov`
偵測 plateau，把種子寫進 spool 目錄，master 的 `CustomMutator_t::GetNewTestcase()`
用非阻塞方式撿走。

有一個 gate 測試會 grep 快迴圈模組找 LLM client，找到就讓 gate 失敗。

## 逐階段手動用法

pipeline 只是把這些依序跑起來。除錯時單獨跑很有用。

### 目標準備

```powershell
# A3 — 基本區塊（覆蓋率斷點）
python -m prep.ghidra_headless --what blocks --binary <exe> `
    --out artifacts\a3_ghidra_blocks_module.json --scope module --entry ProcessPacket

# 轉成 wtf 吃的 .cov 格式
python -m prep.bb_to_wtf --export artifacts\a3_ghidra_blocks_module.json `
    --coverage-dir targets\snapfuzz\coverage --bp-list artifacts\a3_bp_list.json

# A6 — 全域資料符號。反編譯會把表格容量丟掉，這個把它補回來
python -m prep.ghidra_headless --what data-symbols --binary <exe> `
    --out artifacts\a6_data_symbols_module.json --scope module --entry ProcessPacket

# A2 — 批次反編譯，再載入 SQLite（兩步）
python -m prep.ghidra_headless --what pseudoc --binary <exe> `
    --out artifacts\a2_pseudoc_module.json --scope module --entry ProcessPacket
python -m prep.pseudoc_cache build --export artifacts\a2_pseudoc_module.json `
    --cache artifacts\a2_pseudoc_module.sqlite

# 查詢：依函式名或位址（位址查詢是範圍查詢，取最窄的區間）
python -m prep.pseudoc_cache query --cache artifacts\a2_pseudoc_module.sqlite --function ProcessPacket

# A1 — 匯入 state/ 目錄
python -m prep.snapshot_win ingest --state targets\snapfuzz\state `
    --module tlv_server --binary <exe> --entry-symbol ProcessPacket `
    --out artifacts\a1_snapshot.json
```

### LLM 推導（貢獻 1）

```powershell
# 選 fuzz entry
python -m prep.entry_select --cache artifacts\a2_pseudoc_module.sqlite `
    --module tlv_server --module-base 0x7ff719e50000 --ghidra-image-base 0x140000000 `
    --out artifacts\fuzz_entry_llm.json

# 推導輸入格式（entry 的 pseudo-C，以及它的 caller）
python -m prep.input_struct --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\input_spec.json

# 推導 harness 邏輯（550B 模型）
python -m prep.harness_derive --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\harness_spec.json

# schema → C++（這一層是普通程式碼，不含 LLM）
python -m fuzzer.codegen --spec artifacts\input_spec.json `
    --out fuzzer\module\generated_input.h
python -m fuzzer.codegen --module --spec artifacts\input_spec.json `
    --harness artifacts\harness_spec.json --out fuzzer\module\fuzzer_gen.cc
```

entry 選擇是兩階段：先看簽章挑 shortlist，再讀完整 pseudo-C 做決定。**位址永遠來自
A2，模型不提供位址。**

**caller 也要餵進去**，因為「這個 parser 會不會被反覆呼叫」是 caller 的性質而不是
parser 的性質。實測：只給 `ProcessPacket` 時模型答 `supports_sequence: False`
（它自己的 `while` 是 ChunkList 搜尋迴圈，不是接收迴圈）；把 `main` 的 `recv`
迴圈一起給之後就答對了。

驗證方式是拿手寫版當 ground truth 對照 **layout**（偏移、寬度、長度語意），不對照
欄位名 —— pseudo-C 沒有名字，模型自己取的，對照名字是在測它的用詞而不是理解。

### 模糊測試

```powershell
# 完整活動：master + N workers + 慢時鐘 sidecar
python -m orchestrator.scheduler --label myrun --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --module snapfuzz `
    --plateau-execs 20000 --seeds 6 --samples 3

# 不含 LLM 的基準線（ablation a）
python -m orchestrator.scheduler --label baseline --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --no-sidecar

# 慢時鐘單獨跑一輪，方便調 prompt
python -m llm.sidecar --target-dir targets\snapfuzz --module snapfuzz --once --seeds 6 --samples 3
```

`--samples N` 表示一輪發出 N 次**獨立**的 LLM 呼叫並取聯集。這個角色用高溫度換
輸入多樣性，代價是推理品質也跟著波動 —— 實測同一個 frontier，一次取樣想出要耗盡
全域表格並提出 5 個封包的序列，下一次只推理單一命令、產不出超過 1 個封包的東西。

### 安全分析

```powershell
# 去重 → 分類 → 重放 → trace → 靜態脈絡（全程無 LLM）
python -m analysis.pipeline --target-dir targets\snapfuzz --label gate8 --replays 3

# 五訊號 triage + GHSA 報告
python -m analysis.triage_run --evidence artifacts\runs\gate8 --label gate9
```

產出 `artifacts/runs/gate9/advisory.md`（只含 confirmed）與 `discarded.jsonl`
（保留給評估用，不出貨）。

### 評估

```powershell
python -m eval.build_cases                        # 建立標註過的 triage 案例集
python -m eval.triage_eval [--optimise]           # 在 held-out 分割上評分
python -m eval.baseline --minutes 5 --workers 2   # 五臂比較
python -m eval.plot_curves                        # 覆蓋率曲線圖
python -m eval.coverage_gradient --target-dir targets\snapfuzz --command 0
```

### 測試

```powershell
python -m pytest tests\gates -q
```

每個 checkpoint 一個可執行的 gate。目前 **424 passed, 12 skipped** —— skip 的是
需要額外環境變數的 live 測試（`SNAPFUZZ_LIVE_LLM`、`SNAPFUZZ_LIVE_MCP`、
`SNAPFUZZ_LIVE_CP4B`）。

## 實測結果

`tlv_server`，相同快照、相同單一劣質種子、空語料庫、`bochscpu`、2 workers、每臂 5 分鐘：

| 臂 | 執行次數 | exec/s | 語料庫 | 相異 bug | 覆蓋率 | 每個 bug 的執行次數 |
|---|---|---|---|---|---|---|
| baseline-libfuzzer | 2,269,008 | 7,914 | 28 | 2 | 9,686 | 1,134,504 |
| baseline-honggfuzz | 5,927,672 | 22,954 | 2 | 1 | 9,549 | 5,927,672 |
| **llm-guided** | 64,736 | 746 | **41** | **4** | **12,781** | **16,184** |
| ablation-no-seedgen | 80,161 | 738 | 35 | 4 | 12,761 | 20,040 |
| ablation-no-pseudoc | 101,788 | 862 | 36 | 3 | 12,751 | 33,929 |

**成立**：結構感知的 harness 靠「更慢」取勝。吞吐量只有基準線的 1/10 到 1/31，
執行次數少 35–92 倍，卻找到 4 個 bug 對 2 和 1，覆蓋率多 3,095 個 block ——
每個 bug 的執行次數比 libFuzzer **少 70 倍**、比 honggfuzz **少 366 倍**。

honggfuzz 最能說明機制：590 萬次執行、語料庫只有**兩個**檔案、1 個 bug。
byte-level 變異器產不出合法 JSON，`InsertTestcase` 在到達 parser 前就全部退掉。

**不成立**：LLM 種子生成。對照 no-seedgen ablation 是 41 vs 35 語料、**4 vs 4
buckets**、12,781 vs 12,761 覆蓋率。**是 mutator 在做事，不是 LLM 種子生成。**

crash 去重：**53 個 crash 檔（52 個相異錯誤位址）→ 4 個 bucket**，4/4 重現且
確定性重放（trace 位元組完全相同）。triage 把越界讀評為 CWE-125/info_leak、
越界寫評為 CWE-122/possible_rce。

完整數字與 caveat 見 [`docs/RESULTS.md`](docs/RESULTS.md)。

## 目前狀態與誠實的限制

| Gate | 狀態 |
|---|---|
| 0–6, 8, 9, 10, 11, 12 | **PASS** |
| **7**（plateau + LLM 種子生成） | **PARTIAL** —— 五項條件過四項 |

**GATE 7 沒過的那一項**是「注入後覆蓋率上升」。原因量化過：`tlv_server` 在隨機
變異下約 100 秒就飽和，`ProcessPacket` 38 個 block 蓋掉 33 個。剩下 5 個裡兩個是
死碼（用 454 次執行、409 個專門設計的輸入對抗性驗證過），三個需要單一 testcase
裡剛好 6 個 Allocate —— 而覆蓋率在 3→5 次配置之間**完全平坦**，到 6 才跳 +7，
所以覆蓋率導向的搜尋在那段沒有梯度可爬。

**快照擷取寫好了，但從未執行過。** 這是現在最大的一句限制。用的 1.8 GB
`mem.dmp` 來自 wtf Releases 的 `target-tlv_server.7z`，是上游作者在他自己的
Hyper-V VM 上產的。`prep/snapshot_win.py` 分三半：

| | 狀態 |
|---|---|
| `ingest_state_dir` —— 讀取／驗證 state 目錄、取出 `module_base` | 已測試，跑過真實快照 |
| `build_kd_commands` —— 印出 KD 命令給人貼 | 已測試 |
| `acquire_snapshot` —— 用 `kd -k … -c …` 自己驅動整個 session | **寫好了，從未在客體上執行** |

可檢查的部分（產出的 argv、各種拒絕條件、Windows 路徑的引號處理）有單元測試；
**編排本身沒有**，因為這台主機上沒有客體 VM。所以邊 1、6、6b、7、8 保持
`pending`，GATE 3 記為 **Scoped**。同一個依賴也擋住兩件事：GATE 7 的覆蓋率主張
需要有餘裕的目標，真正的 planted-bug 目標需要每個 binary 一份快照。

**其他限制**（詳見 `docs/RESULTS.md`）：

- **沒有 ASAN。** 二進位檔層級的 oracle 只看得到會 fault 的錯誤。不會 fault 的
  記憶體損壞**偵測不到** —— 所以「沒有發現」不等於「安全」。實測到一個具體例子：
  蓋掉 `__dyn_tls_dtor_callback` 的越界寫入發生在第 5 次配置，**本身不產生任何新
  覆蓋率**，對覆蓋率導向完全隱形。
- **每臂只跑一次。** 模糊測試是隨機的，小差距（35 vs 41 語料）在噪音範圍內。
- **只有一個目標。** `docs/RESULTS.md` 裡每個數字都來自 tlv_server。
- **pseudo-C 是有損的。** 名稱是猜的、型別是推論的、inlining 被攤平了。它讓我們
  從灰箱靠近白箱，但**不是原始碼**。
- **triage 評估的 n=4，而且負例是人工建構的**，跟 prompt 是同一個人寫的。
  precision/recall 只有指示性，不是真實世界效能的主張。
- **wtf 只支援 x86-64**，Linux 快照路徑是實驗性的（GDB、必須關掉 ASLR）。

## 倉庫結構

```
arch/         contracts.py（pydantic 資料契約）· graph.yaml（邊列表）· addr.py（位址轉換）
config/       llm.yaml（角色→模型）· fuzz.yaml（backend、plateau、工具路徑）· target.yaml
tools/        bootstrap.py（一鍵環境檢查／取得 Ghidra／寫回 config）
prep/         Ghidra headless · A2 快取 · A3 轉換 · A6 全域符號 · LLM entry 選擇
              · input_struct · harness_derive · snapshot_win（ingest + acquire）
fuzzer/       module/（C++ wtf 模組）· codegen（schema→C++）· build · run · master · workers · corpus
engine_bridge/coverage（master 統計解析）· plateau（frontier 計算）· crash_watch
llm/          client（角色路由）· sidecar（慢時鐘行程）· seed_gen · spool · ghidra_mcp
analysis/     dedup · classify · replay · trace · reverse · pipeline · triage · report
orchestrator/ pipeline（十三～十四階段驅動）· scheduler（master + N workers + sidecar）
eval/         cases · build_cases · triage_eval · baseline（五臂）· plot_curves · coverage_gradient
tests/gates/  每個 checkpoint 一個可執行的 gate
docs/         PROGRESS · DECISIONS · DEVIATIONS · ENVIRONMENT · RESULTS
```

## 設計上不可妥協的四條規則

1. **LLM 絕不從快迴圈呼叫**，也不從 master 呼叫。慢時鐘是獨立行程。
2. **wtf 的 API 細節一律以 cloned source 為準**，文件說的不算；不一致就記進
   `docs/DEVIATIONS.md`。
3. **每個 checkpoint 以 gate 為完成定義。** 程式能編譯不算。邊只有在對應 gate
   通過後才能標 `live` —— 有測試強制這件事。
4. **簽章沒到可以不猜就寫出來的程度，就是還沒定義完。** 每個參數都要有確定型別、
   單位與編碼要寫明、邊界情況要定義、記憶體所有權要指定。

---

# English

- [Three steps](#three-steps)
- [Why Ghidra is mandatory](#why-ghidra-is-mandatory)
- [Preparing a guest VM](#preparing-a-guest-vm)
- [What this is](#what-this-is)
- [Stage-by-stage usage](#stage-by-stage-usage)
- [Measured results](#measured-results)
- [Status and honest limitations](#status-and-honest-limitations)
- [Repository layout](#repository-layout)
- [Four non-negotiable design rules](#four-non-negotiable-design-rules)
- [Terminology](#terminology)

## Three steps

### Step 1 — one command for the environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m tools.bootstrap
```

`tools.bootstrap`:

- checks the Python packages and **JDK 21+** (Ghidra 12's requirement; anything
  older fails with a class-version error that reads like a corrupt install);
- **downloads Ghidra if it is not found** — pinned to 12.1.2, sha256 verified,
  extracted into `third_party/`;
- **records** the paths of Ghidra, `symbolizer-rs`, `kd.exe` and `snapshot.dll`
  into the config files;
- reports the state of Hyper-V and of any guest VM;
- distinguishes, by exit code, "cannot run at all" from "can fuzz an existing
  snapshot but cannot take a new one".

**Why Ghidra is fetched rather than committed.** It is 546 MB zipped, 872 MB
extracted, byte-identical for everyone, and already hosted. Vendoring it would make
every clone of this repo a 550 MB download, and the bootstrap achieves the same
"never configure anything" outcome with a digest check. If an offline machine needs
it, `git add third_party/ghidra_*` — `.gitignore` only declines to track it by
default.

**The API key lives in `.env` only** (gitignored). Putting it in `config/llm.yaml`
fails a gate test:

```powershell
"SNAPFUZZ_LLM_API_KEY=sk-..." | Out-File -Append -Encoding utf8 .env
```

### Step 2 — build

```powershell
.\.venv\Scripts\python.exe -m fuzzer.build
```

Needs Visual Studio's C++ toolchain; `fuzzer.build` locates `vcvars` itself. It
stages our module into wtf's source tree, builds `src/build/wtf.exe`, and verifies
the target registered.

### Step 3 — run

**Case A: you already have a snapshot** (`mem.dmp` + `regs.json` under
`targets/<name>/state/`)

```powershell
.\.venv\Scripts\python.exe -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --workers 2 --minutes 15
```

**Case B: you have only the binary, and want the tool to take the snapshot**
(needs a guest VM — see the next section)

```powershell
.\.venv\Scripts\python.exe -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --kd-pipe \\.\pipe\snapfuzz `
    --kd-stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --workers 2 --minutes 15
```

The only difference is `--kd-pipe`: supplying it **adds stage 07a**, which drives KD
to take the snapshot; without it, `state/` must already exist. **`--entry-symbol` is
optional** — the entry is chosen by the LLM in stage 03, and later stages carry an
`<ENTRY>` placeholder that is substituted when they run.

The thirteen (or fourteen) stages:

```
01-pseudoc    Ghidra: decompile at MODULE scope -> A2 dump
02-a2         A2 dump -> SQLite cache
03-entry      [LLM] choose the fuzz entry
04-blocks     Ghidra: enumerate basic blocks -> A3
05-covfile    A3 -> wtf .cov breakpoint file
06-datasyms   Ghidra: global data symbols -> A6
07a-acquire   take the snapshot via KD (present only with --kd-pipe)
07-snapshot   ingest state/ -> A1
08-inputspec  [LLM] derive the input structure -> InputSpec
09-codegen    InputSpec -> C++ header (no LLM)
10-build      build wtf + our module
11-fuzz       [LLM] campaign: master + workers + slow clock
12-analysis   crash dedup, classify, replay, trace (no LLM)
13-triage     [LLM] five-signal triage -> GHSA advisory
```

Useful flags:

```powershell
--list              # list the stages, with each stage's caveats, and exit
--dry-run           # print the plan, run nothing
--only 03 08        # run only these stages (prefix match; a typo is an error,
                    # never a silent no-op)
--from 10           # start at this stage
--force             # re-run stages that are up to date
--scope function-closure   # narrow A2/A3/A6 to the entry's call closure
```

**No stage is marked done because its command exited 0.** Every stage names the
artifact it must produce, and the artifact is the evidence — `analyzeHeadless` and
`wtf` both exit 0 having produced nothing. Stages whose work is *time* rather than a
file (the build, the campaign) are additionally never skipped as "up to date"
because a previous run's output still exists.

## Why Ghidra is mandatory

Ghidra used to supply only coverage breakpoints (A3), which a determined person
could hand-write. It now also supplies **the pseudo-C the model reads to derive the
input format and the harness** — without Ghidra there is no `InsertTestcase`, and
the fuzzer has nothing to run. Three of the four LLM stages consume A2 directly:

| Stage | Reads | Produces |
|---|---|---|
| `03-entry` | function signatures + pseudo-C, whole module | `FuzzEntry` (which function; which register carries the input and the length) |
| `08-inputspec` | the entry's pseudo-C **and its callers** | `InputSpec` (fields, types, endianness, length semantics) |
| harness derivation | pseudo-C of the entry's closure | `HarnessSpec` (breakpoints, crash conditions, calls to stub) |
| `13-triage` | pseudo-C of the faulting function | the **static** one of the five signals |

**The model never writes C++.** It fills a pydantic-validated schema, and
`fuzzer/codegen.py` — ordinary code — renders the C++. Free-form C++ cannot be
schema-checked, and a compile error surfaces a long way from the model that caused
it. That is not hypothetical: the model once used U+2011 (a non-breaking hyphen) in
a comment and MSVC killed the whole build with C4819 under `/WX` (D-054).

## Preparing a guest VM

Only needed if you want the tool to **take** a snapshot. Skip this if you already
have a `state/` directory.

First, see what is missing:

```powershell
.\.venv\Scripts\python.exe -m tools.bootstrap --vm-check
```

### 1. Create the VM (on the host, elevated PowerShell)

```powershell
# ONE vCPU and 4 GB -- CLAUDE.md section 13.6. More than one vCPU changes what a
# snapshot means.
New-VM -Name snapfuzz-guest -Generation 2 -MemoryStartupBytes 4GB `
       -NewVHDPath D:\vm\snapfuzz-guest.vhdx -NewVHDSizeBytes 64GB
Set-VMProcessor -VMName snapfuzz-guest -Count 1
Set-VMMemory  -VMName snapfuzz-guest -DynamicMemoryEnabled $false

Add-VMDvdDrive -VMName snapfuzz-guest -Path D:\iso\windows.iso
Start-VM snapfuzz-guest
```

### 2. Turn on kernel debugging inside the guest

```powershell
# In the guest, elevated
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
# If bcdedit refuses (Gen2 with Secure Boot), turn Secure Boot off on the host:
#   Set-VMFirmware -VMName snapfuzz-guest -EnableSecureBoot Off
```

Then copy the target binary (and its dependent DLLs) into the guest and shut down.

### 3. Wire the guest's COM1 to a host named pipe

```powershell
# Host, elevated. The pipe name must match --kd-pipe.
Set-VMComPort -VMName snapfuzz-guest -Number 1 -Path \\.\pipe\snapfuzz
Start-VM snapfuzz-guest
```

### 4. Get the target running in the guest

For a service, leave it listening. **This is the one step that cannot be
automated**: something must drive the target to its parser. `--kd-stimulus` exists
for that, and `tools/poke_tcp.py` is a generic implementation (optional length
prefix, retries while the service comes up) -- but **what to send, and on which
port, cannot be derived from the binary**. Find the port in Ghidra (look for
`bind`/`htons`) or with `netstat -ano` inside the guest.

```powershell
# One Allocate command for tlv_server: 4-byte command, 2-byte Id, 2-byte length, body
python -m tools.poke_tcp --port 1337 --length-prefix u32le --hex 00000000 3905 0200 0102
```

### 5. Acquire

The pipeline does this for you, but it also runs standalone:

```powershell
# Inspect the exact command first -- checkable with no VM at all
.\.venv\Scripts\python.exe -m prep.snapshot_win acquire `
    --state targets\snapfuzz\state --pipe \\.\pipe\snapfuzz `
    --module tlv_server --break-at ProcessPacket --dry-run

# Actually take it
.\.venv\Scripts\python.exe -m prep.snapshot_win acquire `
    --state targets\snapfuzz\state --pipe \\.\pipe\snapfuzz `
    --module tlv_server --break-at ProcessPacket `
    --stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --timeout 900
```

The command issued is:

```
kd.exe -k com:pipe,port=\\.\pipe\snapfuzz,resets=0,reconnect
       -c ".load D:\tools\snapshot\snapshot.dll;
           bp tlv_server!ProcessPacket \"!snapshot -k full <state>; qq\";
           g"
```

**The work hangs off the breakpoint, not off the `-c` string after `g`.** KD does
not promise to keep executing that string once the break fires; attaching the
command list to `bp` is the reliable idiom. And the breakpoint **is** the definition
of "the state worth snapshotting" — hitting it is the judgement, so nobody has to
watch.

For a 32-bit target add `--wow64`, which issues `!wow64exts.sw` *before* snapshotting
(afterwards you capture the 32-bit view, which wtf cannot use, and it surfaces much
later as a puzzling wtf error).

**What happens with no VM.** The `--kd-pipe` prerequisite check refuses before any
stage runs and says what is missing. If KD genuinely cannot connect, acquisition
fails after `--timeout` seconds with a message naming the usual cause (no stimulus).
It does **not** report success: if `mem.dmp` and `regs.json` do not appear, that is
a failure — kd exiting 0 is not evidence.

## What this is

Three stages:

```
(1) TARGET PREP   binary -> Ghidra static analysis + snapshot acquisition
                  A1 snapshot    state/ (mem.dmp, regs.json, symbol-store.json)
                  A2 pseudo-C    SQLite, keyed by (module, static_addr)
                  A3 coverage BPs basic-block RVAs -> wtf's .cov format
                  A6 globals     address, size, gap to the next symbol

(2) FUZZING       master + N workers + slow-clock sidecar (three kinds of process)
                  fast clock  master generates test-cases; workers execute
                  slow clock  plateau -> LLM reads pseudo-C -> seeds -> corpus
                  A4 corpus      outputs/ (minset)
                  A5 crashes     crashes/

(3) ANALYSIS      five independent signals -> LLM triage -> GHSA advisory
                  1 dedup (stack hash)  2 classification  3 deterministic replay
                  4 symbolized execution trace (dynamic)  5 reverse context (static)
```

### Two clocks, and this is the whole design

| | fast clock | slow clock |
|---|---|---|
| What | wtf's execution loop (master + workers) | the LLM's work |
| Scale | microseconds to milliseconds, thousands/s | seconds, event-driven |
| LLM | **never** | all of it |
| Lives in | `wtf master` + `wtf fuzz` processes | a separate sidecar process |

**The master counts as fast clock.** It serves every worker, so an LLM call inside
it stalls the whole pool. The slow clock is therefore a **separate process** talking
to the master through files: it watches `coverage.cov` for plateau and writes seeds
into a spool that the master's `CustomMutator_t::GetNewTestcase()` picks up
non-blockingly.

A gate test greps the fast-loop modules for the LLM client and fails if it finds one.

## Stage-by-stage usage

The pipeline just runs these in order. Running them individually is useful when
debugging.

### Target preparation

```powershell
# A3 -- basic blocks for coverage breakpoints
python -m prep.ghidra_headless --what blocks --binary <exe> `
    --out artifacts\a3_ghidra_blocks_module.json --scope module --entry ProcessPacket

# Convert to the .cov format wtf loads
python -m prep.bb_to_wtf --export artifacts\a3_ghidra_blocks_module.json `
    --coverage-dir targets\snapfuzz\coverage --bp-list artifacts\a3_bp_list.json

# A6 -- global data symbols. Decompilation drops a table's capacity; this recovers it.
python -m prep.ghidra_headless --what data-symbols --binary <exe> `
    --out artifacts\a6_data_symbols_module.json --scope module --entry ProcessPacket

# A2 -- batch-decompile, then load into SQLite (two steps)
python -m prep.ghidra_headless --what pseudoc --binary <exe> `
    --out artifacts\a2_pseudoc_module.json --scope module --entry ProcessPacket
python -m prep.pseudoc_cache build --export artifacts\a2_pseudoc_module.json `
    --cache artifacts\a2_pseudoc_module.sqlite

# Query by function name or address (address lookup is a RANGE query, tightest wins)
python -m prep.pseudoc_cache query --cache artifacts\a2_pseudoc_module.sqlite --function ProcessPacket

# A1 -- ingest a state/ directory
python -m prep.snapshot_win ingest --state targets\snapfuzz\state `
    --module tlv_server --binary <exe> --entry-symbol ProcessPacket `
    --out artifacts\a1_snapshot.json
```

### LLM derivation (contribution 1)

```powershell
# Choose the fuzz entry
python -m prep.entry_select --cache artifacts\a2_pseudoc_module.sqlite `
    --module tlv_server --module-base 0x7ff719e50000 --ghidra-image-base 0x140000000 `
    --out artifacts\fuzz_entry_llm.json

# Derive the wire format from the entry's pseudo-C AND its callers
python -m prep.input_struct --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\input_spec.json

# Derive the harness logic (550B model)
python -m prep.harness_derive --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\harness_spec.json

# schema -> C++ (this layer is ordinary code, no LLM)
python -m fuzzer.codegen --spec artifacts\input_spec.json `
    --out fuzzer\module\generated_input.h
python -m fuzzer.codegen --module --spec artifacts\input_spec.json `
    --harness artifacts\harness_spec.json --out fuzzer\module\fuzzer_gen.cc
```

Entry selection is two-phase: shortlist from signatures, then decide from full
pseudo-C. **Addresses always come from A2; the model never supplies one.**

**The callers are fed in too**, because "is this parser called repeatedly" is a
property of the caller, not of the parser. Measured: given only `ProcessPacket` the
model answered `supports_sequence: False` (its own `while` is a ChunkList search
loop, not a receive loop); given `main`'s `recv` loop as well, it answered correctly.

Validation compares **layout** (offsets, widths, length semantics) against the
hand-written module as ground truth, not field names — pseudo-C has no names, so the
model invents them, and comparing names tests its word choice rather than its
understanding.

### Fuzzing

```powershell
# Full campaign: master + N workers + slow-clock sidecar
python -m orchestrator.scheduler --label myrun --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --module snapfuzz `
    --plateau-execs 20000 --seeds 6 --samples 3

# No-LLM baseline (ablation a)
python -m orchestrator.scheduler --label baseline --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --no-sidecar

# One slow-clock round on its own, for prompt iteration
python -m llm.sidecar --target-dir targets\snapfuzz --module snapfuzz --once --seeds 6 --samples 3
```

`--samples N` issues N **independent** LLM calls per round and takes the union. The
role runs at a high temperature to buy input diversity, and the cost is that
reasoning quality varies with it — on the same frontier, one sample worked out that
the global table had to be exhausted and proposed a 5-packet sequence; the next
reasoned about a single command and could not produce more than one packet.

### Security analysis

```powershell
# dedup -> classify -> replay -> trace -> static context (no LLM anywhere)
python -m analysis.pipeline --target-dir targets\snapfuzz --label gate8 --replays 3

# five-signal triage + GHSA report
python -m analysis.triage_run --evidence artifacts\runs\gate8 --label gate9
```

Writes `artifacts/runs/gate9/advisory.md` (confirmed only) and `discarded.jsonl`
(kept for evaluation, not shipped).

### Evaluation

```powershell
python -m eval.build_cases                        # build the labelled triage case set
python -m eval.triage_eval [--optimise]           # score on the held-out split
python -m eval.baseline --minutes 5 --workers 2   # the five-arm comparison
python -m eval.plot_curves                        # coverage curves
python -m eval.coverage_gradient --target-dir targets\snapfuzz --command 0
```

### Testing

```powershell
python -m pytest tests\gates -q
```

One executable gate per checkpoint. Currently **424 passed, 12 skipped** — the
skips are live-endpoint tests behind `SNAPFUZZ_LIVE_LLM`, `SNAPFUZZ_LIVE_MCP` and
`SNAPFUZZ_LIVE_CP4B`.

## Measured results

`tlv_server`, same snapshot, same single poor seed, empty corpus, `bochscpu`,
2 workers, 5 minutes per arm:

| Arm | Executions | exec/s | Corpus | Distinct bugs | Coverage | Executions per bug |
|---|---|---|---|---|---|---|
| baseline-libfuzzer | 2,269,008 | 7,914 | 28 | 2 | 9,686 | 1,134,504 |
| baseline-honggfuzz | 5,927,672 | 22,954 | 2 | 1 | 9,549 | 5,927,672 |
| **llm-guided** | 64,736 | 746 | **41** | **4** | **12,781** | **16,184** |
| ablation-no-seedgen | 80,161 | 738 | 35 | 4 | 12,761 | 20,040 |
| ablation-no-pseudoc | 101,788 | 862 | 36 | 3 | 12,751 | 33,929 |

**Supported:** the structure-aware harness wins by being *slower*. At 1/10 to 1/31
the throughput and 35–92× fewer executions, it found 4 distinct bugs against 2 and
1, and 3,095 more covered blocks — **70× fewer executions per bug** than libFuzzer
and **366× fewer** than honggfuzz.

honggfuzz shows the mechanism most clearly: 5.9M executions, a corpus of **two**
files, 1 bug. A byte-level mutator cannot produce valid JSON, so `InsertTestcase`
rejects everything before the parser is reached.

**Not supported:** LLM seed generation. Against the no-seedgen ablation it is 41 vs
35 corpus files, **4 vs 4 buckets**, 12,781 vs 12,761 coverage. **The mutator is
doing the work, not LLM seed generation.**

Crash dedup: **53 crash files (52 distinct fault addresses) → 4 buckets**, 4/4
reproduced and deterministic on replay (byte-identical traces). Triage rated the
out-of-bounds read CWE-125/info_leak and the out-of-bounds write
CWE-122/possible_rce.

Full numbers and caveats in [`docs/RESULTS.md`](docs/RESULTS.md).

## Status and honest limitations

| Gate | Status |
|---|---|
| 0–6, 8, 9, 10, 11, 12 | **PASS** |
| **7** (plateau + LLM seed generation) | **PARTIAL** — four of five conditions |

**The condition GATE 7 misses** is "coverage increases after injection". The reason
is quantified: `tlv_server` saturates in about 100 seconds under random mutation,
covering 33 of `ProcessPacket`'s 38 blocks. Of the remaining 5, two are dead code
(verified adversarially over 454 executions with 409 purpose-built inputs), and
three need exactly 6 allocations in one test-case — and coverage is **flat** from 3
through 5 allocations, jumping +7 only at 6. Coverage-guided search has no gradient
to climb there.

**Snapshot acquisition is written but has never run.** This is the largest single
limitation. The 1.8 GB `mem.dmp` in use came from `target-tlv_server.7z` in wtf's
Releases, produced by wtf's author on his own Hyper-V VM. `prep/snapshot_win.py` is
in three parts:

| | Status |
|---|---|
| `ingest_state_dir` — read/validate a state dir, recover `module_base` | tested, run against a real snapshot |
| `build_kd_commands` — print the KD commands for a human | tested |
| `acquire_snapshot` — drive the whole session with `kd -k … -c …` | **written, never run against a guest** |

The checkable parts — the argv it produces, each refusal, Windows quoting — are unit
tested; **the orchestration is not**, because this host has no guest VM. So edges 1,
6, 6b, 7 and 8 remain `pending` and GATE 3 is recorded as **Scoped**. The same
dependency blocks two other things: GATE 7's coverage claim needs a target with
headroom, and real planted-bug targets need one snapshot per binary.

**Other limitations** (see `docs/RESULTS.md`):

- **No ASAN.** A binary-only oracle sees only faults. Memory corruption that does
  not fault is **undetectable** — so "nothing found" does not mean "safe". A
  concrete measured case: the out-of-bounds write that overwrites
  `__dyn_tls_dtor_callback` happens on the 5th allocation and **produces no new
  coverage of its own**, making it invisible to coverage guidance.
- **One run per arm.** Fuzzing is stochastic; small gaps (35 vs 41 corpus files)
  are within noise.
- **One target.** Every number in `docs/RESULTS.md` comes from tlv_server.
- **Pseudo-C is lossy.** Names are guessed, types inferred, inlining flattened. It
  moves us from grey-box toward white-box but is **not source**.
- **The triage evaluation is n=4 with hand-built negatives**, written by the same
  person who wrote the prompt. Precision/recall is indicative, not a claim about
  real-world performance.
- **wtf is x86-64 only**, and the Linux snapshot path is experimental (GDB, ASLR
  must be off).

## Repository layout

```
arch/         contracts.py (pydantic contracts) · graph.yaml (edge list) · addr.py
config/       llm.yaml (role -> model) · fuzz.yaml (backend, plateau, tool paths) · target.yaml
tools/        bootstrap.py (one-command check / fetch Ghidra / record paths)
prep/         Ghidra headless · A2 cache · A3 conversion · A6 globals · LLM entry selection
              · input_struct · harness_derive · snapshot_win (ingest + acquire)
fuzzer/       module/ (C++ wtf module) · codegen (schema -> C++) · build · run · master · workers · corpus
engine_bridge/coverage (master stats) · plateau (frontier) · crash_watch
llm/          client (role routing) · sidecar (slow-clock process) · seed_gen · spool · ghidra_mcp
analysis/     dedup · classify · replay · trace · reverse · pipeline · triage · report
orchestrator/ pipeline (the 13/14-stage driver) · scheduler (master + N workers + sidecar)
eval/         cases · build_cases · triage_eval · baseline (five arms) · plot_curves · coverage_gradient
tests/gates/  one executable gate per checkpoint
docs/         PROGRESS · DECISIONS · DEVIATIONS · ENVIRONMENT · RESULTS
```

## Four non-negotiable design rules

1. **The LLM is never called from the fast loop**, nor from the master. The slow
   clock is a separate process.
2. **Every wtf API detail is verified against the cloned source**, which wins over
   any document; discrepancies go into `docs/DEVIATIONS.md`.
3. **A checkpoint is done when its gate passes.** Compiling is not done. An edge
   may be marked `live` only after the corresponding gate passes — a test enforces
   it.
4. **A signature is not specified until it can be written without guessing.** Every
   parameter has a definite type, units and encoding are stated, boundary cases are
   defined, memory ownership is assigned.

## Terminology

Used precisely, because two of these are load-bearing:

| Term | Meaning |
|---|---|
| **fast clock** | wtf's execution loop. No LLM. Microsecond–millisecond scale. |
| **slow clock** | LLM work: seed generation, crash triage. Seconds. Event-driven. |
| **triage** | Deciding whether a crash is a real, interesting bug. What the LLM does to crashes. |
| **verification** | A *different* problem (adjudicating a static finding with source + PoC). **Not part of this project** — do not call triage "verification". |
| **plateau** | Coverage has stopped growing for N consecutive slow-clock ticks. Triggers LLM seed generation. |
| **grey-box** | We have the binary and can instrument it (snapshot + breakpoints), but no source. |

This project is **discovery** (fuzzing), not **verification** (targeted PoC). They
are complementary halves of the same line, and conflating them is the one framing
error this codebase actively guards against.

## Credits

- [**wtf**](https://github.com/0vercl0k/wtf) — the snapshot fuzzing engine, by
  Axel Souchet (0vercl0k). Its README is preserved at
  [`docs/README.wtf-upstream.md`](docs/README.wtf-upstream.md).
- [**0vercl0k/snapshot**](https://github.com/0vercl0k/snapshot) — the WinDbg
  extension that writes `mem.dmp` and `regs.json`.
- [**symbolizer-rs**](https://github.com/0vercl0k/symbolizer-rs) — trace
  symbolization.
- [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra) — the
  static-analysis backbone (Apache-2.0).
- [**GhidraMCP**](https://github.com/LaurieWired/GhidraMCP) — on-demand
  decompilation for the LLM.
- LLM inference: NCHC / AIS3 endpoint (see `config/llm.yaml`; the key lives in
  `.env`).
