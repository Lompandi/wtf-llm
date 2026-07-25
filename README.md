# snapfuzz

**LLM 引導的快照模糊測試系統 · LLM-guided snapshot fuzzing for x86-64 binaries**

以 [**wtf**](docs/README.wtf-upstream.md) 為執行引擎、**Ghidra** 為靜態分析骨幹、
**LLM 慢時鐘**負責種子生成與 crash 分類的自動化模糊測試系統。針對 **沒有原始碼**
的 x86-64 Windows 應用程式二進位檔。

Automated fuzzing for x86-64 application binaries **without source**, using wtf as
the execution engine, Ghidra as the static-analysis backbone, and an **LLM slow
clock** for seed generation and crash triage.

[繁體中文](#繁體中文) · [English](#english)

> 上游 wtf 的 README 保留在 [`docs/README.wtf-upstream.md`](docs/README.wtf-upstream.md)。
> 它是 wtf API 行為的權威參考（CLAUDE.md RULE 2 / §13），沒有刪除。
>
> wtf's own README is preserved at
> [`docs/README.wtf-upstream.md`](docs/README.wtf-upstream.md) — it is the
> authoritative reference for wtf's behaviour and was not deleted.

---

# 繁體中文

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
             └─ A5 crashes     crashes/

③ 安全分析   crash 去重 → 分類 → 確定性重放 → 執行軌跡 → 靜態脈絡
             → 五訊號 LLM triage (DSPy) → GHSA 格式報告
```

### 兩個時鐘，這是整個設計的核心

| | 快時鐘 fast clock | 慢時鐘 slow clock |
|---|---|---|
| 是什麼 | wtf 的執行迴圈：語料庫 → 變異 → 還原快照 → 注入 → 執行 → 讀覆蓋率 | LLM 工作：種子生成、crash 分類 |
| 時間尺度 | 微秒到毫秒，每秒數千次迭代 | 秒級以上，事件驅動 |
| 有 LLM 嗎 | **絕對沒有** | 有 |

**LLM 永遠不會從快迴圈裡被呼叫**，master 也算快時鐘 —— 它為每個 worker 提供測試
案例，在裡面呼叫 LLM 會讓整個 worker pool 停擺。慢時鐘是**獨立的行程**，透過檔案
介面與 scheduler 通訊。

實測證據：一輪 72.8 秒的 LLM 呼叫期間，模糊測試吞吐量維持平均 774 exec/s 未受影響。

## 環境需求

| 需求 | 說明 |
|---|---|
| Windows 11 x86-64 | wtf 的 Windows 路徑才是成熟的 |
| Visual Studio + C++ 工具鏈 | 需含 CMake 與 Ninja（VS 18 的元件即可） |
| Python 3.12 | 依賴見下 |
| Ghidra 12.x | 需 `analyzeHeadless` 可用，設 `GHIDRA_INSTALL_DIR` |
| `symbolizer-rs` | [0vercl0k/symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs)，寫進 `config/fuzz.yaml` 的 `tools.symbolizer_rs` |
| `_NT_SYMBOL_PATH` | **必要**。wtf 透過 dbgeng 用符號名稱解析斷點，自己不設符號路徑 |
| GhidraMCP（選用） | 只在 triage 時遇到 A2 沒快取的位址才需要 |

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install pydantic pyyaml httpx openai dspy pytest `
    loguru jinja2 capstone pefile matplotlib fastapi uvicorn
```

LLM 端點設定寫在 `config/llm.yaml`（角色 → 模型的映射）。**API key 絕不寫在裡面**，
只從環境變數或被 gitignore 的 `.env` 讀取：

```
SNAPFUZZ_LLM_API_KEY=<你的 token>
```

> 有一個 gate 測試會斷言 `config/llm.yaml` 裡的 `api_key` 保持 `null`。

## 快速開始

### 0. 建置

```powershell
$env:GHIDRA_INSTALL_DIR = "D:\tools\ghidra_12.1.2_PUBLIC"
.\.venv\Scripts\python.exe -m fuzzer.build
```

會把我們的模組 stage 進 wtf 的 source tree、建置 `src/build/wtf.exe`，並驗證
`snapfuzz` 這個 target 有被註冊。

### 1. 目標準備

```powershell
# A3 — 基本區塊（覆蓋率斷點）。預設用 fuzz entry 的呼叫閉包，可改 --scope=module
python -m prep.ghidra_headless --what blocks --binary targets\tlv_server\target\tlv_server.exe `
    --out artifacts\a3_ghidra_blocks_module.json --scope module --entry ProcessPacket

# 轉成 wtf 吃的 .cov 格式，放進 targets/<name>/coverage/
python -m prep.bb_to_wtf --export artifacts\a3_ghidra_blocks_module.json `
    --coverage-dir targets\snapfuzz\coverage --bp-list artifacts\a3_bp_list.json

# A6 — 全域資料符號。反編譯會把表格容量丟掉，這個把它補回來
python -m prep.ghidra_headless --what data-symbols --binary targets\tlv_server\target\tlv_server.exe `
    --out artifacts\a6_data_symbols.json --scope module --entry ProcessPacket

# A2 — 批次反編譯成 pseudo-C，再載入 SQLite（兩步）
python -m prep.ghidra_headless --what pseudoc --binary targets\tlv_server\target\tlv_server.exe `
    --out artifacts\a2_pseudoc_module.json --scope module --entry ProcessPacket

python -m prep.pseudoc_cache build --export artifacts\a2_pseudoc_module.json `
    --cache artifacts\a2_pseudoc_module.sqlite

# 查詢：依函式名或位址（位址查詢是範圍查詢，取最窄的區間）
python -m prep.pseudoc_cache query --cache artifacts\a2_pseudoc_module.sqlite --function ProcessPacket

# A1 — 匯入既有的 state/ 目錄（快照本身不是 wtf 產的，見下方限制）
python -m prep.snapshot_win ingest --state targets\tlv_server\state `
    --module tlv_server --binary targets\tlv_server\target\tlv_server.exe `
    --entry-symbol ProcessPacket --out artifacts\a1_snapshot.json
```

**LLM 選擇 fuzz entry**（貢獻 1 的前半 —— 自動化原本需要逆向工程專家的決定）：

```powershell
python -m prep.entry_select --cache artifacts\a2_pseudoc_module.sqlite `
    --module tlv_server --module-base 0x7ff719e50000 --ghidra-image-base 0x140000000 `
    --out artifacts\fuzz_entry.json
```

兩階段流程：先看函式簽章挑出 shortlist，再讀完整 pseudo-C 做決定。**位址永遠來自
A2，模型不提供位址。**

**LLM 推導輸入結構**（貢獻 1 的後半 —— 邊 12/14）：

```powershell
# 從 fuzz entry 的 pseudo-C（以及它的 caller）推出輸入格式
python -m prep.input_struct --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\input_spec.json

# InputSpec -> C++ 標頭（這一層是普通程式碼，不含 LLM）
python -m fuzzer.codegen --spec artifacts\input_spec.json `
    --out fuzzer\module\generated_input.h
```

**模型不直接寫 C++。** 它產出一個 pydantic 可驗證的 `InputSpec`（欄位、型別、
位元組序、哪個欄位是長度且以位元組或元素為單位、magic value），再由 `codegen`
轉成 C++。理由是：讓模型直接吐 C++ 的話，編譯錯誤會出現在 C++ 工具鏈裡、離模型
的錯誤很遠；自由格式的 C++ 無法用 schema 檢查；而 RULE 4 要求的「單位與編碼要
寫明」在 prose 裡無法強制。

**caller 也要餵給模型**，因為「這個 parser 是否被反覆呼叫」是 caller 的性質而不是
parser 的性質。實測：只給 `ProcessPacket` 時模型答 `supports_sequence: False`
（它自己的 `while` 是 ChunkList 搜尋迴圈，不是接收迴圈）；把 `main` 的
`recv` 迴圈一起給之後就答對了。

驗證方式是拿 tlv_server 的手寫版當 ground truth 對照 **layout**（偏移、寬度、
長度語意），不對照欄位名 —— pseudo-C 沒有名字，模型自己取的，對照名字是在測
它的用詞而不是理解。

### 2. 模糊測試

```powershell
# 完整活動：master + N workers + 慢時鐘 sidecar
python -m orchestrator.scheduler --label myrun --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --plateau-execs 20000 --seeds 6 --samples 3

# 不含 LLM 的基準線（ablation a）
python -m orchestrator.scheduler --label baseline --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --no-sidecar
```

慢時鐘也可以單獨跑一輪，方便調 prompt：

```powershell
python -m llm.sidecar --target-dir targets\snapfuzz --module snapfuzz --once --seeds 6 --samples 3
```

`--samples N` 表示一輪發出 N 次**獨立**的 LLM 呼叫並取聯集。這個角色用高溫度取得
輸入多樣性，代價是推理品質也跟著波動 —— 實測同一個 frontier，一次取樣想出要耗盡
全域表格並提出 5 個封包的序列，下一次只推理單一命令、產不出超過 1 個封包的東西。

### 3. 安全分析

```powershell
# 去重 → 分類 → 重放 → trace → 靜態脈絡（全程無 LLM）
python -m analysis.pipeline --target-dir targets\snapfuzz --label gate8 --replays 3

# 五訊號 triage + GHSA 報告
python -m analysis.triage_run --evidence artifacts\runs\gate8 --label gate9
```

產出 `artifacts/runs/gate9/advisory.md`（只含 confirmed）與 `discarded.jsonl`
（保留給評估用，不出貨）。

### 4. 評估

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

每個 checkpoint 都有一個可執行的 gate。目前 **318 passed, 10 skipped** —— skip 的
是需要另外開環境變數的 live 端點測試（`SNAPFUZZ_LIVE_LLM`、`SNAPFUZZ_LIVE_MCP`、
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
| 0–6, 8, 9, 10 | **PASS** |
| **7**（plateau + LLM 種子生成） | **PARTIAL** —— 五項條件過四項 |

**GATE 7 沒過的那一項**是「注入後覆蓋率上升」。原因量化過：`tlv_server` 在隨機
變異下約 100 秒就飽和，`ProcessPacket` 38 個 block 蓋掉 33 個。剩下 5 個裡兩個是
死碼（用 454 次執行、409 個專門設計的輸入對抗性驗證過），三個需要單一 testcase
裡剛好 6 個 Allocate —— 而覆蓋率在 3→5 次配置之間**完全平坦**，到 6 才跳 +7，
所以覆蓋率導向的搜尋在那段沒有梯度可爬。

**快照擷取路徑從未執行過。** 用的 1.8 GB `mem.dmp` 來自 wtf Releases 的
`target-tlv_server.7z`，是上游作者在他自己的 Hyper-V VM 上產的。`prep/snapshot_win.py`
分兩半：

| | 狀態 |
|---|---|
| `ingest_state_dir` —— 讀取/驗證 state 目錄、取出 `module_base` | 已測試，跑過真實快照 |
| `build_kd_commands` —— 驅動 KD 的 `.load` + `!snapshot` | **寫好了，從未執行** |

所以邊 1、6、6b、7、8 都保持 `pending`，GATE 3 記為 **Scoped**。同樣的依賴也擋住
了兩件事：GATE 7 的覆蓋率主張需要有餘裕的目標，真正的 planted-bug 目標需要每個
binary 一份快照。

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

## 倉庫結構

```
arch/         contracts.py（pydantic 資料契約）· graph.yaml（55 條邊：50 條文件邊 + 5 條衍生邊）· addr.py（位址轉換）
config/       llm.yaml（角色→模型）· fuzz.yaml（backend、plateau、符號路徑）· target.yaml
prep/         Ghidra headless · A2 快取 · A3 轉換 · A6 全域符號 · LLM entry 選擇 · 快照
fuzzer/       module/（C++ wtf 模組）· build · run · master · workers · corpus
engine_bridge/coverage（master 統計解析）· plateau（frontier 計算）· crash_watch
llm/          client（角色路由）· sidecar（慢時鐘行程）· seed_gen · spool · ghidra_mcp
analysis/     dedup · classify · replay · trace · reverse · pipeline · triage · report
orchestrator/ scheduler（master + N workers + sidecar）
eval/         cases · build_cases · triage_eval · baseline（五臂）· plot_curves · coverage_gradient
tests/gates/  每個 checkpoint 一個可執行的 gate
docs/         PROGRESS · DECISIONS · DEVIATIONS（D-000..D-053）· ENVIRONMENT · RESULTS
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

## What this is

A three-stage pipeline:

```
① TARGET PREP    binary → Ghidra static analysis + snapshot acquisition
                 ├─ A1 snapshot      state/  (mem.dmp, regs.json, symbol-store.json)
                 ├─ A2 pseudo-C      SQLite, keyed by (module, static_addr)
                 ├─ A3 coverage BPs  basic-block RVAs → wtf's .cov format
                 └─ A6 data symbols  addresses, sizes, span to next symbol

② FUZZING        master + N workers + slow-clock sidecar (three kinds of process)
                 ├─ fast clock  master generates testcases, workers execute
                 └─ slow clock  plateau → LLM reads pseudo-C → seeds → corpus
                 ├─ A4 corpus        outputs/ (minset)
                 └─ A5 crashes       crashes/

③ ANALYSIS       dedup → classify → deterministic replay → trace → static context
                 → five-signal LLM triage (DSPy) → GHSA-format report
```

### Two clocks, and this is the whole design

| | fast clock | slow clock |
|---|---|---|
| What | wtf's loop: corpus → mutate → restore → inject → execute → read coverage | LLM work: seed generation, crash triage |
| Timescale | microseconds to milliseconds, thousands of iterations/second | seconds+, event-driven |
| LLM? | **never** | yes |

**The LLM is never called from the fast loop**, and the master counts as fast
clock — it serves testcases to every worker, so an LLM call inside it stalls the
entire pool. The slow clock is a **separate process** talking to the scheduler
through a file interface.

Measured: throughput held at a mean of 774 exec/s across a round containing 72.8 s
of LLM time.

## Prerequisites

| Requirement | Note |
|---|---|
| Windows 11 x86-64 | wtf's Windows path is the mature one |
| Visual Studio + C++ toolset | needs CMake and Ninja (VS 18's components work) |
| Python 3.12 | dependencies below |
| Ghidra 12.x | `analyzeHeadless` must work; set `GHIDRA_INSTALL_DIR` |
| `symbolizer-rs` | [0vercl0k/symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs), recorded in `config/fuzz.yaml` as `tools.symbolizer_rs` |
| `_NT_SYMBOL_PATH` | **required** — wtf resolves breakpoints by symbol name through dbgeng and sets no symbol path itself |
| GhidraMCP (optional) | only needed when triage hits an address A2 has not cached |

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install pydantic pyyaml httpx openai dspy pytest `
    loguru jinja2 capstone pefile matplotlib fastapi uvicorn
```

The LLM endpoint lives in `config/llm.yaml` as a role→model map. **The API key
never goes in it** — only the environment or a gitignored `.env`:

```
SNAPFUZZ_LLM_API_KEY=<your token>
```

> A gate test asserts `api_key` in `config/llm.yaml` stays `null`.

## Quick start

### 0. Build

```powershell
$env:GHIDRA_INSTALL_DIR = "D:\tools\ghidra_12.1.2_PUBLIC"
.\.venv\Scripts\python.exe -m fuzzer.build
```

Stages our module into wtf's source tree, builds `src/build/wtf.exe`, and verifies
the `snapfuzz` target is registered.

### 1. Target preparation

```powershell
# A3 -- basic blocks for coverage breakpoints. Defaults to the fuzz entry's call
# closure; --scope=module enumerates everything.
python -m prep.ghidra_headless --what blocks --binary targets\tlv_server\target\tlv_server.exe `
    --out artifacts\a3_ghidra_blocks_module.json --scope module --entry ProcessPacket

# Convert to the .cov format wtf loads, into targets/<name>/coverage/
python -m prep.bb_to_wtf --export artifacts\a3_ghidra_blocks_module.json `
    --coverage-dir targets\snapfuzz\coverage --bp-list artifacts\a3_bp_list.json

# A6 -- global data symbols. Decompilation drops a table's capacity; this recovers it.
python -m prep.ghidra_headless --what data-symbols --binary targets\tlv_server\target\tlv_server.exe `
    --out artifacts\a6_data_symbols.json --scope module --entry ProcessPacket

# A2 -- batch-decompile to pseudo-C, then load it into SQLite (two steps)
python -m prep.ghidra_headless --what pseudoc --binary targets\tlv_server\target\tlv_server.exe `
    --out artifacts\a2_pseudoc_module.json --scope module --entry ProcessPacket

python -m prep.pseudoc_cache build --export artifacts\a2_pseudoc_module.json `
    --cache artifacts\a2_pseudoc_module.sqlite

# Query by function name or address (address lookup is a RANGE query, tightest span wins)
python -m prep.pseudoc_cache query --cache artifacts\a2_pseudoc_module.sqlite --function ProcessPacket

# A1 -- ingest an existing state/ directory (see Limitations: we do not take snapshots)
python -m prep.snapshot_win ingest --state targets\tlv_server\state `
    --module tlv_server --binary targets\tlv_server\target\tlv_server.exe `
    --entry-symbol ProcessPacket --out artifacts\a1_snapshot.json
```

**LLM fuzz-entry selection** (contribution 1, first half — automating the decision
that normally needs a reverse-engineering expert):

```powershell
python -m prep.entry_select --cache artifacts\a2_pseudoc_module.sqlite `
    --module tlv_server --module-base 0x7ff719e50000 --ghidra-image-base 0x140000000 `
    --out artifacts\fuzz_entry.json
```

Two stages: signatures produce a shortlist, then full pseudo-C decides. **The
address always comes from A2 — the model never supplies one.**

**LLM input-structure derivation** (contribution 1, second half — edges 12/14):

```powershell
# Derive the wire format from the fuzz entry's pseudo-C AND its callers
python -m prep.input_struct --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\input_spec.json

# InputSpec -> C++ header (this layer is ordinary code, no LLM)
python -m fuzzer.codegen --spec artifacts\input_spec.json `
    --out fuzzer\module\generated_input.h
```

**The model does not write C++.** It emits a pydantic-validated `InputSpec` —
fields, types, endianness, which field is a length and in bytes or elements, magic
values — and `codegen` renders that as C++. Asking for C++ directly fails three
ways: a compile error surfaces in the C++ toolchain far from the model's mistake;
free-form C++ cannot be schema-checked; and RULE 4's "units and encoding are
stated" is unenforceable in prose.

**Callers go in the prompt too**, because whether a parser is invoked repeatedly is
a property of the caller, not the parser. Measured: shown only `ProcessPacket` the
model answered `supports_sequence: False` — its own `while` is the chunk-table
search, not a receive loop. With `main`'s `recv` loop included it answered
correctly.

Verification compares the derived spec against the hand-written struct's **layout**
— offsets, widths, length semantics — and deliberately not its field names, since
pseudo-C has none and the model invents them.

To emit the KD commands for taking a snapshot (untested, see Limitations):

```powershell
python -m prep.snapshot_win kd-script --break-at ProcessPacket --state targets\mytarget\state
```

### 2. Fuzzing

```powershell
# Full campaign: master + N workers + slow-clock sidecar
python -m orchestrator.scheduler --label myrun --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --plateau-execs 20000 --seeds 6 --samples 3

# No-LLM baseline (ablation a)
python -m orchestrator.scheduler --label baseline --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --no-sidecar
```

The slow clock can be run for a single round, which is how prompts get iterated:

```powershell
python -m llm.sidecar --target-dir targets\snapfuzz --module snapfuzz --once --seeds 6 --samples 3
```

`--samples N` issues N **independent** LLM calls per round and unions them. The
role runs at a high temperature for input diversity, and the cost is that the
*reasoning* varies as much as the output: measured on an identical frontier, one
sample worked out that a branch needed a global table exhausted and proposed a
five-packet sequence, and the next reasoned only about single commands.

### 3. Security analysis

```powershell
# dedup → classify → replay → trace → static context (no LLM anywhere)
python -m analysis.pipeline --target-dir targets\snapfuzz --label gate8 --replays 3

# five-signal triage + GHSA report
python -m analysis.triage_run --evidence artifacts\runs\gate8 --label gate9
```

Produces `artifacts/runs/gate9/advisory.md` (confirmed findings only) and
`discarded.jsonl` (kept for evaluation, never shipped).

The five signals are handed over as **separate fields** — dedup, classification,
replay, symbolized trace (dynamic), reverse-engineering context (static). Signals
4 and 5 stay apart because one says what executed and the other what the code
says; their errors are uncorrelated, which is the point.

### 4. Evaluation

```powershell
python -m eval.build_cases                        # build the labelled triage case set
python -m eval.triage_eval [--optimise]           # score on the HELD-OUT split
python -m eval.baseline --minutes 5 --workers 2   # five-arm comparison
python -m eval.plot_curves                        # coverage curves + bug bars
python -m eval.coverage_gradient --target-dir targets\snapfuzz --command 0
```

`eval.baseline --recompute` re-derives metrics from archived master logs without
re-running any fuzzing.

### Testing

```powershell
python -m pytest tests\gates -q
```

Every checkpoint has one executable gate. Currently **318 passed, 10 skipped** —
the skips are opt-in live-endpoint tests (`SNAPFUZZ_LIVE_LLM`,
`SNAPFUZZ_LIVE_MCP`, `SNAPFUZZ_LIVE_CP4B`).

## Measured results

`tlv_server`, identical snapshot / single poor seed / empty corpus / `bochscpu` /
2 workers / 5-minute budget per arm:

| Arm | Executions | exec/s | Corpus | Distinct bugs | Coverage | Execs per bug |
|---|---|---|---|---|---|---|
| baseline-libfuzzer | 2,269,008 | 7,914 | 28 | 2 | 9,686 | 1,134,504 |
| baseline-honggfuzz | 5,927,672 | 22,954 | 2 | 1 | 9,549 | 5,927,672 |
| **llm-guided** | 64,736 | 746 | **41** | **4** | **12,781** | **16,184** |
| ablation-no-seedgen | 80,161 | 738 | 35 | 4 | 12,761 | 20,040 |
| ablation-no-pseudoc | 101,788 | 862 | 36 | 3 | 12,751 | 33,929 |

**Supported: the structure-aware harness wins by being slower.** 10–31× less
throughput and 35–92× fewer executions than the baselines, yet 4 distinct bugs to
their 2 and 1, and +3,095 more covered blocks than the best baseline — **70× fewer
executions per bug than libFuzzer and 366× fewer than honggfuzz**.

honggfuzz shows the mechanism most clearly: 5.9 million executions, a corpus of
**two**, one bug. A byte-level mutator cannot emit valid JSON, so
`InsertTestcase` rejects nearly everything before the parser sees it.

**Not supported: LLM seed generation.** Against the no-seedgen ablation it is 41
vs 35 corpus entries, **4 vs 4 buckets**, 12,781 vs 12,761 coverage. The mutator
is doing the work.

Crash dedup: **53 crash files with 52 distinct fault addresses → 4 buckets**, all
4 reproduced and deterministic with byte-identical traces. Triage rated the
out-of-bounds reads CWE-125/`info_leak` and the writes CWE-122/`possible_rce`.

Full numbers and caveats: [`docs/RESULTS.md`](docs/RESULTS.md).

## Status and honest limitations

| Gate | Status |
|---|---|
| 0–6, 8, 9, 10 | **PASS** |
| **7** (plateau + LLM seed generation) | **PARTIAL** — four of five criteria |

**The criterion GATE 7 fails** is "coverage increases after injection", and the
reason is quantified: `tlv_server` saturates under random mutation in ~100 seconds,
covering 33 of `ProcessPacket`'s 38 blocks. Of the five that remain, two are dead
code (verified adversarially over 454 executions with 409 purpose-built inputs)
and three need exactly six Allocate commands in one testcase — and coverage is
**completely flat from 3 to 5 allocations**, jumping +7 only at 6, so
coverage-guided search has no gradient across that gap.

**The snapshot-acquisition path has never been executed.** The 1.8 GB `mem.dmp` in
use comes from `target-tlv_server.7z` in wtf's Releases, taken by the upstream
author on his own Hyper-V VM. `prep/snapshot_win.py` splits in two:

| | Status |
|---|---|
| `ingest_state_dir` — read/validate a state dir, extract `module_base` | tested, ran on the real snapshot |
| `build_kd_commands` — drive KD's `.load` + `!snapshot` | **written, never executed** |

So edges 1, 6, 6b, 7 and 8 stay `pending` and GATE 3 is recorded as **Scoped**.
The same dependency blocks two things: GATE 7's coverage claim needs a target with
headroom, and real planted-bug targets need a snapshot per binary.

**Other limitations** (see `docs/RESULTS.md`):

- **There is no ASAN.** The binary-only oracle sees faults the platform reports.
  Memory corruption that does not fault is **not detected**, so the absence of a
  finding is not evidence of safety. A measured example: the out-of-bounds write
  over `__dyn_tls_dtor_callback` happens at the 5th allocation and **covers
  nothing new**, making it invisible to coverage guidance entirely.
- **One run per arm.** Fuzzing is stochastic, so small gaps (35 vs 41 corpus
  entries) are within plausible noise.
- **One target.** Every number in `docs/RESULTS.md` comes from tlv_server.
- **Pseudo-C is lossy.** Names are invented, types inferred, inlining flattened.
  It moves us from grey-box toward white-box but it is **not source**.
- **Triage evaluation is n=4 with synthetic negatives**, written by the same
  person as the prompt. Precision/recall is indicative, not a claim about
  real-world performance.

## Repository layout

```
arch/         contracts.py (pydantic contracts) · graph.yaml (55 edges: 50 from the spec + 5 derived) · addr.py
config/       llm.yaml (role→model) · fuzz.yaml (backend, plateau, symbols) · target.yaml
prep/         Ghidra headless · A2 cache · A3 conversion · A6 symbols · entry select · snapshot
fuzzer/       module/ (the C++ wtf module) · build · run · master · workers · corpus
engine_bridge/coverage (master stat parsing) · plateau (frontier) · crash_watch
llm/          client (role routing) · sidecar (slow-clock process) · seed_gen · spool · ghidra_mcp
analysis/     dedup · classify · replay · trace · reverse · pipeline · triage · report
orchestrator/ scheduler (master + N workers + sidecar)
eval/         cases · build_cases · triage_eval · baseline (5 arms) · plot_curves · coverage_gradient
tests/gates/  one executable gate per checkpoint
docs/         PROGRESS · DECISIONS · DEVIATIONS (D-000..D-053) · ENVIRONMENT · RESULTS
```

## Four non-negotiable design rules

1. **The LLM is never called from the fast loop**, nor from the master. The slow
   clock is a separate process.
2. **Every wtf API detail is verified against the cloned source**, which wins over
   any document; discrepancies go in `docs/DEVIATIONS.md`.
3. **The gate is the definition of done.** Code that compiles is not a gate, and an
   edge only goes `live` once its gate has passed — a test enforces that.
4. **A signature is not specified until you can write it without guessing.** Every
   parameter typed, units and encoding stated, boundary cases defined, memory
   ownership assigned.

## Terminology

Discovery, not verification. This project is **fuzzing**, and the LLM stage that
looks at crashes is **triage** — deciding whether a crash is a real, interesting
bug. It is deliberately *not* called verification, which is a different problem
(adjudicating a static finding with source and a PoC) and is out of scope.

## Credits

Built on [**wtf**](https://github.com/0vercl0k/wtf) by Axel Souchet
(@0vercl0k) — snapshot fuzzing engine, and the `tlv_server` example target and its
snapshot. [`symbolizer-rs`](https://github.com/0vercl0k/symbolizer-rs) and
[`snapshot`](https://github.com/0vercl0k/snapshot) are also his.
Static analysis by [Ghidra](https://ghidra-sre.org/) (NSA).
LLM inference via the NCHC / AIS3 2026 allocation.
