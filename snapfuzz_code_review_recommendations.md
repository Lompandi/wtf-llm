# Snapfuzz 架構與程式碼 Review 建議

## 1. Review 結論

整體架構設計約七至八成與 `CLAUDE.md` 吻合，但目前這份交付物仍無法獨立證明文件中宣稱的大多數 checkpoint 已真正完成。

主要問題集中在以下幾點：

1. `docs/PROGRESS.md` 宣稱多個 checkpoint 已 PASS，但交付包未附對應 artifacts、target state 與執行證據。
2. CP3、CP4b 等 checkpoint 被標示為 PASS，同時關鍵 edge 仍為 pending，或 acquisition 根本沒有實際執行。
3. 專案沒有可靠的一鍵 gate 驗證入口，直接執行 `pytest` 會收集上游測試並失敗。
4. CP7 明確沒有通過，但 CP8 之後仍被標為 PASS，違反 checkpoint sequencing。
5. 架構中的 LLM-generated input struct 尚未真正接進 fuzzer bus。

---

## 2. 重大問題

### 2.1 `PROGRESS.md` 的 PASS 狀態無法由目前交付包重現

`docs/PROGRESS.md` 宣稱曾完成：

- CP1：150 秒 fuzzing
- CP4：663 秒 campaign
- CP4b：4 workers
- CP5：live endpoint call
- CP6：live GhidraMCP 與 LLM
- CP8：53 crashes
- CP9：真實 triage 結果
- CP10：五組實驗結果

但目前交付包中缺少：

- `artifacts/`
- 實際 target state
- `mem.dmp`
- `regs.json`
- coverage summaries
- crash corpus
- trace output
- evaluation result artifacts

因此目前只能確認有測試程式與文件，不能確認這些 gate 在本交付包中真的通過。

這與 Rule 3 不吻合：checkpoint 必須以具體 artifacts 與 assertion 證明 interface 實際接通。

#### 建議

至少保留一份可稽核的 evidence bundle：

```text
artifacts/runs/gate4/run_metadata.json
artifacts/runs/gate4/coverage_summaries.jsonl
artifacts/runs/gate4/master.log
artifacts/runs/gate4b/run_metadata.json
artifacts/a1_snapshot.json
artifacts/a3_bp_list.json
artifacts/traces-symbolized/
artifacts/gates/gate-results.json
```

大型 `mem.dmp` 可以不進 Git，但應提供：

- SHA-256
- 產生方式
- 外部儲存位置或重新產生指令
- target binary hash

---

### 2.2 CP3 被標為 PASS，但 snapshot acquisition 未完成

目前狀態同時顯示：

- CP3 PASS
- acquisition path 尚未執行
- edge 1 pending
- edges 6、7、8 pending

但 CP3 原始 gate 要求：

- 實際執行 snapshot acquisition
- 產生 A1
- wtf 成功載入 snapshot
- 至少執行一個 iteration

因此 CP3 更合理的狀態應為：

```text
PARTIAL / IMPLEMENTED_NOT_EXECUTED
```

#### 建議

可以拆成：

```text
CP3a — Existing snapshot validation
CP3b — Snapshot acquisition
```

或者維持 CP3，但在 acquisition edges 真正執行前，不應標為 PASS。

---

### 2.3 CP7 未通過，但後續 checkpoint 仍繼續標 PASS

`docs/PROGRESS.md` 已明確記錄 CP7 為 PARTIAL，且 coverage-increase criterion 未達成。

但後續卻宣稱：

- CP8 PASS
- CP9 PASS
- CP10 PASS
- CP11 PASS
- CP12 PASS

這直接違反：

> Do not start checkpoint N+1 until checkpoint N's gate passes.

#### 建議

若維持嚴格 checkpoint 規則：

```text
CP7 = BLOCKING
CP8+ = IMPLEMENTED / VALIDATED_IN_ISOLATION
```

不要標 PASS。

另一種方式是修改 `CLAUDE.md`，明確允許：

```text
Checkpoints may be implemented out of order,
but release readiness remains blocked by the earliest failing gate.
```

目前文件與實際開發流程互相矛盾。

---

### 2.4 Edge 14 尚未接通

Edge 14：

```text
fuzzer_module.llm_input_struct → fuzzer_module.bus
```

目前只能確認：

- LLM 可以產生 structure spec
- codegen 可以產生 header
- 但實際 fuzzer module 使用的 bus 尚未由此產物驅動

因此目前的 LLM-generated input struct 比較像離線 code-generation proof，尚未形成完整 pipeline。

#### 影響

這會削弱核心貢獻：

> automating the fuzz-entry and injection decisions

因為最終 injection layout 仍可能依賴手工版本。

#### 建議 gate

新增真正的 integration gate：

1. 重新執行 input-structure generation。
2. 產生新的 header。
3. 重新 build fuzzer module。
4. 確認 generated header 是 build dependency。
5. 用已知 testcase 驗證 guest memory layout。
6. 改變 generated field offset 後，測試必須失敗，證明不是 dead artifact。

---

### 2.5 Edge 22 尚未驗證

Edge 22：

```text
fuzz_target.bp_list → worker.execute
```

目前使用 bochscpu 時不會走 breakpoint coverage file，因此技術上合理，但這不代表 WHV／KVM 的 A3 BP list wiring 已完成。

#### 建議

將狀態拆分為：

```text
CP4-bochscpu: PASS
CP4b-distributed-bochscpu: PASS
CP4c-breakpoint-backend: PENDING
```

否則架構圖容易讓人誤以為 interface 3 已在多 worker 環境中驗證。

---

## 3. 測試與 Gate 問題

### 3.1 專案沒有可直接使用的 pytest 設定

直接執行：

```bash
pytest -q
```

會收集：

```text
src/libs/kdmp-parser/src/python/tests/
```

並因缺少 `kdmp_parser` 而 collection error。

目前也沒有：

- `pytest.ini`
- `pyproject.toml` pytest config
- `setup.cfg` pytest config

此外環境缺少 `capstone` 時，CP8、CP9 也可能在 collection 階段失敗。

#### 建議

新增：

```ini
# pytest.ini
[pytest]
testpaths =
    tests
norecursedirs =
    src
    .git
    artifacts
markers =
    integration: requires external tools or runtime artifacts
    live: requires a live external service
    campaign: requires a fuzzing campaign
```

並提供明確入口：

```bash
pytest tests -q
pytest tests/gates/test_cp0.py -q
python tools/run_gates.py --through cp4
```

---

### 3.2 Gate 使用 skip，可能造成假性通過

部分 gate 在缺少 artifacts 時會使用 `pytest.mark.skipif`。

這適合一般開發測試，但不適合正式 checkpoint gate，因為：

- 關鍵 integration assertion 被 skip
- pytest 仍可能 exit 0
- 使用者容易誤認為 gate 已 PASS

#### 建議

區分兩種模式：

```text
普通 unit test：
缺 artifact 可 skip

正式 gate：
缺 artifact 必須 fail
```

例如：

```python
STRICT_GATE = os.getenv("SNAPFUZZ_STRICT_GATE") == "1"

if STRICT_GATE and not COVERAGE_JSONL.exists():
    pytest.fail("GATE 4 evidence missing")
```

更理想的做法是建立獨立 runner：

```bash
python -m tools.gates run cp4
```

---

### 3.3 Unit、integration、live 與 campaign test 沒有清楚區分

目前 `tests/gates/test_cpN.py` 可能混合：

- parser unit tests
- AST static checks
- artifact validation
- external tool tests
- live LLM endpoint
- 長時間 fuzz campaign

因此單純顯示「tests passed」不等於 gate 已完成。

#### 建議結果格式

```json
{
  "gate": "cp4",
  "status": "pass",
  "required_assertions": 6,
  "passed_assertions": 6,
  "skipped_required_assertions": 0,
  "target_sha256": "...",
  "wtf_commit": "...",
  "timestamp": "...",
  "evidence": []
}
```

任何 required assertion 被 skip，gate status 必須是 `incomplete`。

---

## 4. Markdown 與 Code 不一致

### 4.1 專案名稱是 `cp0-cp4`，內容卻宣稱完成 CP12

交付包名稱顯示只涵蓋 CP0～CP4，但內容包含：

- CP5～CP12 程式
- CP5～CP12 tests
- `PROGRESS.md` 宣稱 CP12 PASS

#### 建議

重新命名為：

```text
snapfuzz-full-prototype-cp12.zip
```

或只保留 CP0～CP4 內容與宣告。

---

### 4.2 `CLAUDE.md` 沒有 CP11、CP12，但程式自行新增

新增 checkpoint 本身沒有問題，但主規格沒有同步更新，造成：

- checkpoint numbering 不再是單一真相來源
- edge 12／14 原本沒有正式 gate
- pipeline driver 沒有正式 definition of done

#### 建議

把以下內容正式加入 `CLAUDE.md`：

```text
CP11 — LLM-derived input structure
CP12 — End-to-end pipeline driver
```

並把 gate、edges、artifacts 一併加入 §8。

---

### 4.3 CP9 存在四訊號／五訊號矛盾

部分 contract 註解寫：

```text
must name all four when available
```

但實際架構清楚定義五個 signals：

1. dedup
2. classification
3. replay
4. dynamic trace
5. static reverse context

程式使用五個是正確的，Markdown 應同步修正。

---

### 4.4 `CoverageSummary.total_edges` 命名可能不準確

目前：

```python
total_edges: int
```

但不同 backend 的 coverage 語意不同：

- bochscpu：edge coverage
- WHV／KVM：basic-block breakpoint coverage
- master log 的 `cov` 可能是 engine-native coverage unit

因此不應全部稱為 edges。

#### 建議

```python
coverage_units: int
coverage_kind: Literal[
    "edge",
    "basic_block_breakpoint",
    "engine_native"
]
```

至少應記錄 backend 與 coverage mode，避免 CP10 跨 backend 比較失真。

---

### 4.5 `fault_static_addr = 0` 不適合作為 sentinel

目前用：

```python
fault_static_addr: int
# 0 means not attributable to our module
```

較好的設計是：

```python
fault_static_addr: int | None
fault_module: str | None
address_normalized: bool
```

避免：

- 所有外部 faults 被 dedup 到地址 0
- pseudo-C lookup 誤查地址 0
- downstream 忘記處理 sentinel

---

### 4.6 `symbol-store.json` 的 Windows／Linux語意應寫得更清楚

目前 contract 的邏輯合理：

- Linux 必須有 `symbol_store_json`
- Windows 可由 runtime 重新產生

但 repo layout 文字容易讓人理解成兩者都固定必須存在。

#### 建議文件明確寫成：

```text
Windows: optional / regenerated at runtime
Linux: mandatory input
```

---

## 5. 目前做得好的部分

### 5.1 Fast clock／slow clock 分離

已有測試禁止 fast-path module import：

- `llm`
- `openai`
- `httpx`
- `anthropic`
- `dspy`

這符合 Rule 1。

### 5.2 Master／worker 職責有正確建模

專案已包含：

```text
fuzzer/master.py
fuzzer/workers.py
orchestrator/scheduler.py
llm/sidecar.py
llm/spool.py
```

沒有把 wtf 錯誤簡化成單 process。

### 5.3 Address normalization 有獨立模組

已有：

```text
arch/addr.py
tests/test_addr.py
```

符合 static/runtime address 應集中處理的要求。

### 5.4 五訊號 triage 保持分離

dynamic trace 與 static pseudo-C 沒有被合併，與 edges 38～41b 一致。

### 5.5 Binary JSON serialization 有額外處理

`SeedRecord` 與 `CrashRecord` 對 bytes 做了 JSON encoding，適合 stage-by-stage artifact 傳遞。

### 5.6 文件有誠實記錄尚未完成項目

文件有承認：

- acquisition 未執行
- edge 14 未接線
- edge 22 未驗證
- LLM seed generation 尚未證明 coverage improvement

問題主要在於 checkpoint status 沒有完全反映這些限制。

---

## 6. 建議修正優先順序

### P0：影響可信度

1. 將 CP3 改成 PARTIAL。
2. 將 CP8～CP12 改為 `implemented/validated independently`，或修改 Rule 3。
3. 正式完成 CP7，或將整體 pipeline 標示為 blocked at CP7。
4. 提供 evidence bundle。
5. 建立 strict gate runner。
6. 新增 pytest config，避免收集 `src/libs`。

### P1：架構接線

7. 完成 edge 14。
8. 在 WHV 或 KVM 驗證 edge 22。
9. 真正執行 Windows snapshot acquisition。
10. 將 CP11、CP12 加入正式規格。

### P2：資料模型與命名

11. 將 `fault_static_addr` 改成 optional。
12. coverage 欄位加入 coverage kind／backend。
13. 修正四訊號／五訊號矛盾。
14. 清楚標示 Windows／Linux 的 `symbol-store.json` 差異。

---

## 7. 最終判定

| 面向 | 判定 |
|---|---|
| 目錄架構 | 大致吻合 |
| fast／slow clock | 吻合 |
| master／worker topology | 大致吻合 |
| contracts | 大致吻合，有合理擴充 |
| checkpoint gate 原則 | 不完全吻合 |
| CP3 snapshot acquisition | 未完成 |
| CP7 LLM seed effectiveness | 未通過 |
| LLM input struct integration | 未接通 |
| BP list → workers | 尚未在適用 backend 驗證 |
| PASS 可重現性 | 目前不足 |
| 一鍵測試 | 目前不可用 |

最精確的專案狀態描述為：

> 多數模組與 isolated tests 已完成，bochscpu fuzzing、distributed topology、triage 與 evaluation 據文件曾被執行；但此交付包缺少重現 evidence，snapshot acquisition、breakpoint-backend wiring、LLM-derived input integration，以及 CP7 coverage improvement 仍未完整通過，因此尚不能稱為全架構 end-to-end 完成。
