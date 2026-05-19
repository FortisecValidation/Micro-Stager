# FORTiSEC Micro-Stager (PoC)
**Framework ADEF v2.0 - Public Release**

## Overview
This repository contains the official Proof of Concept (PoC) for the **Micro-Stager**, an advanced offensive engineering technique developed by FORTiSEC. It demonstrates a critical vulnerability in the telemetry architecture of managed environments by bypassing **Event Tracing for Windows Threat Intelligence (ETW TI)** and **AMSI** via physical CPU manipulation.

While traditional evasion techniques focus solely on initial access or memory patching, true offensive validation requires assessing the full EDR architecture across the entire MITRE ATT&CK lifecycle. This research exposes a deep architectural pain point (DOLOR) in modern security ecosystems: the blind trust in Ring 0 telemetry.

## Technical Mechanics
The `FORTiSEC_MicroStager_PoC.ps1` script bypasses the `nt!EtwTiLogSetContextThread` Kernel sensor without crashing the .NET Common Language Runtime (CLR) during P/Invoke operations. It achieves this through a 4-phase orchestrated execution:

1. **The Memory Forge:** Allocates a 2-byte Micro-Stager (`0xCC` / `0xC3`) and registers a Vectored Exception Handler (VEH).
2. **Controlled Chaos:** Triggers a software breakpoint (`INT 3`), forcing the Kernel's Exception Dispatcher to capture the thread's `CONTEXT_RECORD`.
3. **Context Hijacking:** The VEH intercepts the exception, modifies the debug registers (`Dr0`, `Dr1`, `Dr2`) targeting `NtTraceEvent`, `NtTraceControl`, and `AmsiScanBuffer`, and advances the Instruction Pointer (`RIP`).
4. **The System's Own Goal:** The Kernel natively applies the hardware changes upon receiving `EXCEPTION_CONTINUE_EXECUTION`, silently blinding the telemetry sensors without triggering ETW TI alerts.

Additionally, the PoC implements dynamic String Reversal in memory to successfully bypass the static pre-execution emulators of modern Antivirus solutions (e.g., Windows Defender).

## Usage / Demonstration
This script is a **Safe PoC**. It does not perform any malicious memory access or data exfiltration. It is designed solely to demonstrate telemetry blindness by evaluating the official Microsoft AMSI Test Sample signature inside a fully hardware-silenced PowerShell session.

1. Clone the repository.
2. Open a standard `powershell.exe` session (Version 5.1+ supported).
3. Execute the script:
   ```powershell
   .\FORTiSEC_MicroStager_PoC.ps1
4. Observe the clean evaluation of the AMSI signature and the absence of ETW TI context-injection logs in your EDR console.

## Documentation 
For a deep dive into the Windows Internals, the CLR collapse syndrome, and the theoretical foundation of this evasion, read the full technical whitepaper: **Silencing the Silicon: ETW TI Evasion in Managed Environments via Controlled Exceptions**

## Media & Video Demonstrations

To see a step-by-step visual breakdown of telemetry blinding, EDR structural integrity testing, and live bypass proof under our experimental framework, check out our official video resource:

🎥 Episode 1: The Telemetry Illusion: How We Blind Your EDR
https://www.youtube.com/@Fortisec-Validation

## Disclaimer
For Educational and Research Purposes Only. This tool is provided for security researchers, Red Teams, and Blue Teams to validate defensive postures and improve the resilience of endpoint sensors. FORTiSEC assumes no liability for the misuse of this code in unauthorized environments. Always operate strictly within controlled laboratory environments or under explicit, authorized engagement rules.
