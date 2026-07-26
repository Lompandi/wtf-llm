# Guest VM setup for snapshot acquisition

Only needed if you want snapfuzz to take a snapshot. Skip this if you already have
a `state/` directory with `mem.dmp` and `regs.json`.

> Never exercised. The acquisition code is written and unit tested (argv,
> refusals, quoting) but has not been run against a real guest. Expect to debug it.

Check what is missing first:

```powershell
python -m tools.bootstrap --vm-check
```

## 1. Create the VM

Elevated PowerShell on the host. One vCPU and 4 GB — more than one vCPU changes
what a snapshot means.

```powershell
New-VM -Name snapfuzz-guest -Generation 2 -MemoryStartupBytes 4GB `
       -NewVHDPath D:\vm\snapfuzz-guest.vhdx -NewVHDSizeBytes 64GB
Set-VMProcessor -VMName snapfuzz-guest -Count 1
Set-VMMemory    -VMName snapfuzz-guest -DynamicMemoryEnabled $false

Add-VMDvdDrive -VMName snapfuzz-guest -Path D:\iso\windows.iso
Start-VM snapfuzz-guest
```

Install Windows, then copy the target binary and its dependent DLLs into the guest.

## 2. Enable kernel debugging in the guest

```powershell
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

If `bcdedit` refuses (Gen2 with Secure Boot), turn Secure Boot off from the host:

```powershell
Set-VMFirmware -VMName snapfuzz-guest -EnableSecureBoot Off
```

Shut the guest down.

## 3. Wire COM1 to a host named pipe

The pipe name must match `--kd-pipe`.

```powershell
Set-VMComPort -VMName snapfuzz-guest -Number 1 -Path \\.\pipe\snapfuzz
Start-VM snapfuzz-guest
```

## 4. Start the target, and know your stimulus

Leave a service listening. This is the one step that cannot be automated: something
must drive the target to its parser, or `g` never returns and acquisition times out.

`tools/poke_tcp.py` is a generic stimulus (optional length prefix, retries while the
service comes up), but *what* to send and *on which port* is not derivable from the
binary. Find the port in Ghidra (look for `bind`/`htons`) or with `netstat -ano` in the
guest.

```powershell
# one Allocate command for tlv_server: 4-byte command, 2-byte Id, 2-byte length, body
python -m tools.poke_tcp --port 1337 --length-prefix u32le --hex 00000000 3905 0200 0102
```

## 5. Acquire

The pipeline does this as stage `07a` when you pass `--kd-pipe`. Standalone:

```powershell
# inspect the exact command -- works with no VM at all
python -m prep.snapshot_win acquire `
    --state targets\snapfuzz\state --pipe \\.\pipe\snapfuzz `
    --module tlv_server --break-at ProcessPacket --dry-run

python -m prep.snapshot_win acquire `
    --state targets\snapfuzz\state --pipe \\.\pipe\snapfuzz `
    --module tlv_server --break-at ProcessPacket `
    --stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --timeout 900
```

The command it issues:

```
kd.exe -k com:pipe,port=\\.\pipe\snapfuzz,resets=0,reconnect
       -c ".load D:\tools\snapshot\snapshot.dll;
           bp tlv_server!ProcessPacket \"!snapshot -k full <state>; qq\";
           g"
```

The work hangs off the breakpoint, not off the `-c` string after `g`. KD does not
promise to keep executing that string once the break fires, so
`-c "bp ...; g; !snapshot ...; qq"` is unreliable. Attaching the command list to `bp`
is the correct idiom — and the breakpoint *is* the definition of "the state worth
snapshotting", so nobody has to decide when to act.

For a 32-bit target add `--wow64`. It issues `!wow64exts.sw` *before* snapshotting;
switching afterwards captures the 32-bit view, which wtf cannot use and which fails
much later as a confusing wtf error.

## Troubleshooting

| Symptom | Cause |
|---|---|
| times out at `--timeout` | nothing drove the target to the parser — check the stimulus, port and framing |
| `mem.dmp`/`regs.json` missing, kd exited 0 | the extension did not load, or `!snapshot` failed; check `--log` |
| refuses to start | `state/` already holds a snapshot; move it aside |
| breakpoint never binds | symbol not resolvable — pass `--symbol-path`, or use `--break-at 0xADDR` |
| wtf later rejects the snapshot | 32-bit target without `--wow64`, or more than one vCPU |

---

# 客體 VM 設定（快照擷取）只有要讓 snapfuzz 自己擷取快照時才需要。已經有含 `mem.dmp` 和 `regs.json` 的
`state/` 目錄就跳過。

> 從未實際執行過。擷取的程式碼寫好了、也有單元測試（argv、拒絕條件、引號），
> 但沒有對真實客體跑過，預期會需要 debug。先看缺什麼：`python -m tools.bootstrap --vm-check`

## 1. 建 VM

主機上用管理員 PowerShell。一顆 vCPU、4 GB —— 多顆 vCPU 會改變快照的語意。```powershell
New-VM -Name snapfuzz-guest -Generation 2 -MemoryStartupBytes 4GB `
       -NewVHDPath D:\vm\snapfuzz-guest.vhdx -NewVHDSizeBytes 64GB
Set-VMProcessor -VMName snapfuzz-guest -Count 1
Set-VMMemory    -VMName snapfuzz-guest -DynamicMemoryEnabled $false

Add-VMDvdDrive -VMName snapfuzz-guest -Path D:\iso\windows.iso
Start-VM snapfuzz-guest
```

裝好 Windows，把目標執行檔和它的相依 DLL 複製進客體。

## 2. 在客體裡開核心除錯

```powershell
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

`bcdedit` 拒絕的話（Gen2 + Secure Boot），從主機關掉 Secure Boot：```powershell
Set-VMFirmware -VMName snapfuzz-guest -EnableSecureBoot Off
```

然後關機。

## 3. 把 COM1 接到主機具名管線

管線名字要跟 `--kd-pipe` 一致。```powershell
Set-VMComPort -VMName snapfuzz-guest -Number 1 -Path \\.\pipe\snapfuzz
Start-VM snapfuzz-guest
```

## 4. 把目標跑起來，並想清楚 stimulus

服務型目標就讓它監聽。這一步不能自動化：得有東西讓目標走到 parser，否則 `g`
永遠不回來，擷取就會 timeout。`tools/poke_tcp.py` 是通用的 stimulus（可選長度前綴、會重試等服務起來），但送什麼、送到哪個 port 沒辦法從 binary 推出來。port 在 Ghidra 裡找 `bind`/`htons`，或在客體
裡 `netstat -ano`。```powershell
# tlv_server 的一個 Allocate 指令：4 位元組 command、2 位元組 Id、2 位元組長度、body
python -m tools.poke_tcp --port 1337 --length-prefix u32le --hex 00000000 3905 0200 0102
```

## 5. 擷取

給 `--kd-pipe` 時 pipeline 會當成 stage `07a` 自己做。單獨跑：```powershell
# 先看它到底會下什麼命令 —— 完全不需要 VM
python -m prep.snapshot_win acquire `
    --state targets\snapfuzz\state --pipe \\.\pipe\snapfuzz `
    --module tlv_server --break-at ProcessPacket --dry-run
```

工作掛在斷點上，不是排在 `-c` 字串裡 `g` 的後面。KD 沒有保證 `g` 命中後會繼續
執行那個字串剩下的部分，所以 `-c "bp ...; g; !snapshot ...; qq"` 不可靠。掛在 `bp`
上才是正確寫法 —— 而斷點本身就是「哪個狀態值得快照」的定義，不需要有人判斷時機。

32 位元目標加 `--wow64`，它會在快照前下 `!wow64exts.sw`；事後才切會抓到 32 位元
視角，wtf 用不了，而且會在很久以後才以奇怪的 wtf 錯誤爆出來。

## 疑難排解

| 症狀 | 原因 |
|---|---|
| `--timeout` 到了才失敗 | 沒有東西讓目標走到 parser —— 檢查 stimulus、port、framing |
| `mem.dmp`/`regs.json` 沒出現但 kd 回傳 0 | 擴充沒載入或 `!snapshot` 失敗，看 `--log` |
| 一開始就拒絕 | `state/` 已經有快照了，先移開 |
| 斷點綁不上去 | 符號解不出來 —— 給 `--symbol-path`，或用 `--break-at 0xADDR` |
| wtf 之後拒絕這個快照 | 32 位元目標沒加 `--wow64`，或 vCPU 超過一顆 |
