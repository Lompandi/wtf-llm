# snapfuzz

LLM 引導的快照模糊測試，目標是 x86-64 執行檔，不需要原始碼。支援 Windows PE 和
Linux ELF。執行引擎是 [wtf](https://github.com/0vercl0k/wtf)，靜態分析用 Ghidra。

丟一個執行檔進去。它會反編譯、讓 LLM 選 fuzz entry 並推導輸入格式與 harness、產生
C++ wtf 模組、擷取快照、用一個 master 加 N 個 worker 跑，最後把 crash 去重、重放、
triage 成 GHSA 報告。

[English](README.md)

---

## 安裝

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m tools.bootstrap
```

`bootstrap` 會檢查每個工具、找不到 Ghidra 就下載、並把路徑寫進 `config/`。`--check`
只回報不改東西；`--vm-check` 只看快照擷取需要什麼。

需要 Python 3.11+、JDK 21+、Visual Studio 的 C++ 工具鏈，以及一把 LLM provider key。

## 設 API key

你設哪家的 key 就用哪家。放在 `.env`：

```
ANTHROPIC_API_KEY=sk-ant-...      # Claude，走官方 SDK
OPENAI_API_KEY=sk-...             # OpenAI
SNAPFUZZ_LLM_API_KEY=sk-...       # 任何 OpenAI-compatible endpoint
```

設了多個由 `config/llm.yaml` 的順序決定。要單次指定：

```powershell
$env:SNAPFUZZ_LLM_PROVIDER="anthropic"
```

## 建置

```powershell
.\.venv\Scripts\python.exe -m fuzzer.build
```

## 用現有快照跑

`state/` 裡已經有 `mem.dmp` 和 `regs.json`：

```powershell
python -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --workers 2 --minutes 15
```

`--entry-symbol` 可以不給，entry 由 stage 03 的 LLM 選。

## 跑自己的 binary

需要 binary，以及一份停在它 parser 的快照。在 `inputs/` 放一個 seed——你的目標會接受的
單一輸入，原封不動的 bytes——其餘四個 per-target 目錄會自動建立。

```powershell
mkdir targets\mytarget\inputs
copy <一份範例輸入> targets\mytarget\inputs\seed.bin

python -m orchestrator.pipeline `
    --binary C:\path\to\mytarget.exe `
    --state-dir targets\mytarget\state `
    --target-name mytarget `
    --workers 2 --minutes 15
```

有三件事會自動發生，值得知道：

- **harness 由你的 binary 產生。** Ghidra 的 pseudo-C 給模型，模型導出輸入結構與 harness
  spec，`fuzzer/codegen.py` 產生 C++，stage 10 編譯。倉庫裡那份手寫 harness parse 的是開發
  目標的格式，所以換成別的 binary 時預設改用產生的那份。要強制指定用
  `--generated-harness` / `--handwritten-harness`。
- **fuzz entry 由 stage 03 選**，不是從 `config/target.yaml` 讀。
- **artifact 會蓋上 target 與 binary hash 的印記。** 換 target 時分析階段會重跑，而不是沿用
  上一個 target 的，並且會印出重跑哪個 artifact、為什麼。

`--module` 是 wtf 的 `--name`，也就是編進 `wtf.exe` 的 harness。它不是你目標的 module
名稱（那個由 `--binary` 決定），也不是 target 目錄（那個是 `--target-name`）。執行時的標頭
會把三個都印出來。

## 從 binary 開始 —— Windows

需要 Hyper-V、Windows SDK 的 `kd.exe`、
[0vercl0k/snapshot](https://github.com/0vercl0k/snapshot)，以及一台客體 VM
（[docs/GUEST-VM.md](docs/GUEST-VM.md)）。

```powershell
python -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --kd-pipe \.\pipe\snapfuzz `
    --kd-stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --workers 2 --minutes 15
```

`--kd-pipe` 會多出擷取階段。32 位元目標加 `--wow64`。

## 從 binary 開始 —— Linux

需要一台有 KVM 的 Linux 主機。客體建一次就好：

```bash
cd linux_mode/qemu_snapshot && ./setup.sh
```

然後：

```bash
python -m prep.snapshot_linux check-host

python -m prep.snapshot_linux prepare \
    --target-name mytarget --binary ./mytarget --break-at parse_packet \
    --stimulus '/root/mytarget &'
```

`prepare` 會寫出 gdb 要 source 的 `bkpt.py`、把 ELF 放到 `nm` 和 `readelf` 讀得到的
位置，然後印出剩下的步驟 —— 包含一個沒辦法自動化的：快照做到一半 gdb 會要你在 QEMU
那個 tab 按 Ctrl+C 然後下 `cpu`。`--dry-run` 會印出計畫但不動任何東西。

三個 artifact 都出現後：

```bash
python -m prep.snapshot_linux verify --target-name mytarget

python -m prep.snapshot_linux ingest --state targets/mytarget/state \
    --module mytarget --module-base 0x555555554000 --ghidra-image-base 0x100000 \
    --entry-runtime-addr 0x5555555551a9 --randomize-va-space 0 \
    --out artifacts/a1_snapshot.json

python -m orchestrator.pipeline --binary ./mytarget \
    --state-dir targets/mytarget/state --target-name mytarget \
    --from 08 --workers 2 --minutes 15
```

抓快照前在客體裡設 `kernel.randomize_va_space=0` —— 沒關的話 ingest 會拒絕。

## 階段

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
08b-harness   LLM 推導中斷點與輸入暫存器        -> HarnessSpec
09-codegen    InputSpec + HarnessSpec -> C++（無 LLM）
10-build      建置 wtf + 模組
11-fuzz       活動：master + workers + 慢時鐘
12-analysis   去重、分類、重放、trace（無 LLM）
13-triage     LLM 五訊號 triage                 -> advisory.md
```

單獨跑某一個階段：[docs/STAGES.md](docs/STAGES.md)。

## 旗標

| 旗標 | 作用 |
|---|---|
| `--list` | 列出階段後結束 |
| `--dry-run` | 印出計畫，什麼都不跑 |
| `--only 03 08` | 只跑這些階段 |
| `--from 10` | 從這裡開始 |
| `--force` | 重跑已經是最新的階段 |
| `--scope function-closure` | 分析範圍縮到 entry 的呼叫閉包 |
| `--generated-harness` | 從這個 binary 的 pseudo-C 導出並編譯 harness |
| `--handwritten-harness` | 改用倉庫裡的 `fuzzer_snapfuzz.cc` |
| `--workers N` | worker 數量 |
| `--minutes N` | 活動時間 |
| `--label NAME` | `artifacts/runs/` 下的輸出目錄，預設是 target 名稱 |
| `--kd-pipe`、`--kd-stimulus`、`--wow64` | Windows 快照擷取 |

## 產出

```
targets/<name>/outputs/                        最小化後的語料庫
targets/<name>/crashes/                        原始 crash
targets/<name>/coverage/                       .cov 斷點檔
artifacts/a1_snapshot.json                     快照參照
artifacts/runs/<label>-analysis/buckets.json   去重後的 crash
artifacts/runs/<label>-triage/advisory.md      GHSA 報告，只含 confirmed
artifacts/runs/<label>-triage/discarded.jsonl  false positive，不出貨
```

## 測試

```powershell
pytest -q
python -m tools.gates run          # 逐條對照 checkpoint gate 條件
python -m tools.evidence verify    # 記錄的 artifact 還在不在
```
