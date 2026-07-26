# snapfuzz

LLM 引導的快照模糊測試，目標是 x86-64 執行檔，不需要原始碼。Windows 是主要支援的
路徑，Linux 可以跑但比較粗糙。

丟一個執行檔進去。它用 Ghidra 反編譯、讓 LLM 選 fuzz entry 並推導輸入格式與 harness、
產生 C++ [wtf](https://github.com/0vercl0k/wtf) 模組、擷取快照、用一個 master 加 N 個
worker 跑，最後把 crash 去重、重放、triage 成 GHSA 報告。

[English](README.md)

---

## 安裝

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m tools.bootstrap    # 檢查工具、抓 Ghidra、把路徑寫進 config
.\.venv\Scripts\python.exe -m fuzzer.build       # 需要 VS 的 C++ 工具鏈
```

`bootstrap` 找不到 Ghidra 會自動下載（版本釘死、驗 sha256），並把每個工具的路徑寫進
`config/`。`--check` 只回報不改東西。

```
  [  ok   ] Python packages    8 present
  [  ok   ] JDK                java 21 at C:\Program Files\Eclipse Adoptium\jdk-21...
  [  ok   ] Ghidra             D:\tools\ghidra_12.1.2_PUBLIC
  [  ok   ] wtf                D:\wtf-llm\src\build\wtf.exe
  [  ok   ] LLM API key        SNAPFUZZ_LLM_API_KEY in .env
  [  ok   ] symbolizer-rs      D:\tools\symbolizer-rs\symbolizer-rs.exe
  [  ok   ] kd.exe             C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
  [  ok   ] 0vercl0k/snapshot  D:\tools\snapshot\snapshot.dll
  [absent ] Hyper-V guest      Hyper-V IS installed, but this shell cannot query it
                               -> run as administrator, or join 'Hyper-V Administrators'

Ready to fuzz an EXISTING snapshot. Not ready to take a new one:
  - Hyper-V guest: ...
```

LLM key 放 `.env`，已 gitignore：

```
SNAPFUZZ_LLM_API_KEY=sk-...
```

需求：Python 3.11+、JDK 21+、C++ 工具鏈、一個 OpenAI-compatible 的 LLM endpoint。
Ghidra 不是選項 —— harness 是從它的 pseudo-C 推導出來的。要自己擷取快照還需要
Hyper-V、Windows SDK 的 `kd.exe`、
[0vercl0k/snapshot](https://github.com/0vercl0k/snapshot) 和一台客體 VM
（[docs/GUEST-VM.md](docs/GUEST-VM.md)）。

## 用法

`state/` 裡已經有快照（`mem.dmp`、`regs.json`）：

```powershell
python -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --workers 2 --minutes 15
```

只有 binary，順便擷取快照：

```powershell
python -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --kd-pipe \\.\pipe\snapfuzz `
    --kd-stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --workers 2 --minutes 15
```

`--kd-pipe` 會多出擷取階段，差別只有這個。`--entry-symbol` 可以不給 —— entry 由
stage 03 的 LLM 選。

輸出：

```
target    : snapfuzz (D:\wtf-llm\targets\snapfuzz)
binary    : D:\wtf-llm\targets\tlv_server\target\tlv_server.exe
entry     : (late-bound from stage 03)
module    : snapfuzz   scope: module
campaign  : 2 worker(s), 15 min
prerequisites: ok

==========================================================================
[1/13] 01-pseudoc: Ghidra: decompile at MODULE scope -> A2 dump
==========================================================================
  $ prep.ghidra_headless --what pseudoc --binary ... --scope module
  OK in 41s
...
==========================================================================
PIPELINE SUMMARY
==========================================================================
  ran                    41s  01-pseudoc: Ghidra: decompile at MODULE scope -> A2 dump
  ran                     2s  02-a2: A2 dump -> SQLite cache
  ...
  ran                    96s  13-triage: LLM: five-signal triage -> GHSA advisory

  13 ran, 0 skipped, 0 blocked, 0 failed, of 13 stage(s)
  all stages accounted for
```

### 旗標

| 旗標 | 作用 |
|---|---|
| `--list` | 列出階段後結束 |
| `--dry-run` | 印出計畫，什麼都不跑 |
| `--only 03 08` | 只跑這些階段 |
| `--from 10` | 從這裡開始 |
| `--force` | 重跑已經是最新的階段 |
| `--scope function-closure` | 分析範圍縮到 entry 的呼叫閉包 |
| `--workers N` | worker 數量 |
| `--minutes N` | 活動時間 |

### 階段

```
01-pseudoc    Ghidra 在 module 範圍反編譯       -> A2
02-a2         A2 -> SQLite 快取
03-entry      LLM 選 fuzz entry                 -> FuzzEntry
04-blocks     Ghidra 列舉基本區塊               -> A3
05-covfile    A3 -> wtf 的 .cov 斷點檔
06-datasyms   Ghidra 全域資料符號               -> A6
07a-acquire   驅動 KD 擷取快照                  （只在給 --kd-pipe 時出現）
07-snapshot   匯入 state/                       -> A1
08-inputspec  LLM 推導輸入結構                  -> InputSpec
09-codegen    InputSpec -> C++（無 LLM）
10-build      建置 wtf + 模組
11-fuzz       活動：master + workers + 慢時鐘
12-analysis   去重、分類、重放、trace（無 LLM）
13-triage     LLM 五訊號 triage                 -> advisory.md
```

每個階段都指名一個必須產出的 artifact，那個 artifact 才算完成 —— `analyzeHeadless`
和 `wtf` 都會在什麼都沒寫的情況下回傳 0。工作是時間而不是檔案的階段，不會因為舊的
輸出還在就被跳過。

各階段也可以單獨跑：[docs/STAGES.md](docs/STAGES.md)。

## Linux 目標

Ghidra 和分析那半跟 OS 無關，ELF 輸入可以用。難的是擷取快照：wtf 的 Linux 模式是
GDB 對整台 QEMU VM，不是使用者模式行程。

```bash
# 客體裡，先做這個
sysctl -w kernel.randomize_va_space=0
```

然後照 wtf 自己的 `linux_mode/` 流程（`qemu_snapshot/setup.sh`、`gdb_server.sh`、
`gdb_client.sh`、一個繼承 `gdb_fuzzbkpt.py` 的 `bkpt.py`，最後在 GDB 裡下 `cpu`），
再手動 ingest：

```bash
python -m prep.snapshot_linux ingest --state targets/mytarget/state \
    --module mytarget --module-base 0x555555554000 --ghidra-image-base 0x100000 \
    --entry-runtime-addr 0x5555555551a9 --randomize-va-space 0 \
    --out artifacts/a1_snapshot.json
```

ASLR 沒關的話 ingest 會拒絕 —— 開著的話 `module_base` 在快照和重放之間會不一樣，
位址轉換會安靜地算出垃圾。`state/symbol-store.json` 在 Linux 上是必要的，而且不能在
Linux 產生，要從 Windows 的執行搬過來。pipeline 的快照階段只支援 Windows，所以
Linux 上自己跑 stage 07，其他用 `--from 08`。`python -m prep.snapshot_linux notes`
會印出流程。

## 運作方式

```
binary ──┬─> Ghidra ──> A2 pseudo-C ──> [LLM] entry、輸入格式、harness
         │              A3 基本區塊 ──> 覆蓋率斷點
         │              A6 全域符號
         └─> KD + !snapshot ──> A1 快照

               ┌──────────── 快時鐘 ────────────┐   ┌──── 慢時鐘 ────┐
               │ wtf master  ──>  N wtf workers │   │ 獨立行程        │
               │ 持有語料庫       執行並回報     │<──│ plateau -> 種子 │
               └────────────────────────────────┘   └────────────────┘

crashes ──> 去重 ──> 分類 ──> 重放 ──> trace ──┐
                              A2 pseudo-C ────┴──> [LLM] triage ──> GHSA
```

- 快時鐘裡任何地方都沒有 LLM，master 也沒有 —— master 服務每一個 worker，在那裡呼叫
  一次就卡住整個 pool。慢時鐘是獨立行程，監看整體覆蓋率，把種子丟進一個 spool，由
  master 的 mutator 非阻塞撿走。有 gate 測試會 grep 快迴圈模組找 LLM client。
- LLM 只填經過 pydantic 驗證的 schema（`InputSpec`、`HarnessSpec`），C++ 由
  `fuzzer/codegen.py` 產生。
- triage 吃五個獨立訊號：去重 bucket、錯誤分類、確定性重放、符號化 trace、pseudo-C。
  後兩個刻意分開 —— 一個講執行了什麼，一個講程式碼是什麼。

## 實測結果

`tlv_server`，相同快照、相同單一劣質種子、空語料庫、bochscpu、2 workers、每臂 5 分鐘：

| 臂 | 執行次數 | exec/s | 語料庫 | bug | 覆蓋率 | 每 bug 執行次數 |
|---|---|---|---|---|---|---|
| baseline-libfuzzer | 2,269,008 | 7,914 | 28 | 2 | 9,686 | 1,134,504 |
| baseline-honggfuzz | 5,927,672 | 22,954 | 2 | 1 | 9,549 | 5,927,672 |
| snapfuzz | 64,736 | 746 | 41 | 4 | 12,781 | 16,184 |
| ablation：無種子生成 | 80,161 | 738 | 35 | 4 | 12,761 | 20,040 |
| ablation：無 pseudo-C | 101,788 | 862 | 36 | 3 | 12,751 | 33,929 |

每個 bug 的執行次數比 libFuzzer 少 70 倍、比 honggfuzz 少 366 倍，而吞吐量只有它們的
十分之一到三十分之一。LLM 種子生成沒有被這組數據支持：4 個 bucket 對無種子生成
ablation 的 4 個。

去重把 53 個 crash 檔（52 個相異錯誤位址）收成 4 個 bucket，四個都確定性重現。
Caveat 和完整數字：[docs/RESULTS.md](docs/RESULTS.md)。

## 倉庫結構

```
arch/          pydantic 契約 · graph.yaml（邊列表）· 位址轉換
config/        llm.yaml（角色→模型）· fuzz.yaml · target.yaml
tools/         bootstrap.py · poke_tcp.py
prep/          Ghidra headless · A2 快取 · A3/A6 · entry_select · input_struct
               harness_derive · snapshot_win · snapshot_linux
fuzzer/        module/（C++）· codegen · build · master · workers · corpus
engine_bridge/ coverage · plateau · crash_watch
llm/           client（角色路由）· sidecar（慢時鐘）· seed_gen · spool
analysis/      dedup · classify · replay · trace · reverse · triage · report
orchestrator/  pipeline（階段驅動）· scheduler（master + workers + sidecar）
eval/          baseline（五臂）· triage_eval · plot_curves
tests/gates/   每個 checkpoint 一個可執行的 gate
```

## 測試

```powershell
python -m pytest tests\gates -q
```

```
424 passed, 12 skipped
```

skip 的是需要 `SNAPFUZZ_LIVE_LLM`、`SNAPFUZZ_LIVE_MCP`、`SNAPFUZZ_LIVE_CP4B` 的
live endpoint 測試。

## 致謝

建立在 Axel Souchet 的 [wtf](https://github.com/0vercl0k/wtf) 之上，並使用
[0vercl0k/snapshot](https://github.com/0vercl0k/snapshot)、
[symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs)、
[Ghidra](https://github.com/NationalSecurityAgency/ghidra)、
[GhidraMCP](https://github.com/LaurieWired/GhidraMCP)。wtf 原本的 README 在
[docs/README.wtf-upstream.md](docs/README.wtf-upstream.md)。

設計筆記：[CLAUDE.md](CLAUDE.md)、[docs/DECISIONS.md](docs/DECISIONS.md)、
[docs/DEVIATIONS.md](docs/DEVIATIONS.md)。
