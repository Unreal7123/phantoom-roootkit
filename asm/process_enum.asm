; ============================================================================
; PhantomScope — process_enum.asm
; Windows x64 Direct Syscall Stub for NtQuerySystemInformation
;
; Bypasses ALL user-mode hooks (AV, EDR, rootkits) placed in ntdll.dll by
; invoking the kernel directly via the syscall instruction with the raw SSN.
;
; The SSN (System Service Number) is resolved dynamically at runtime by
; syscall_wrapper.asm to remain valid across all Windows 10/11 patch versions.
;
; Build: nasm -f win64 process_enum.asm -o process_enum.obj
; ============================================================================

bits 64
default rel

section .data
    ; SSN placeholder — filled by syscall_wrapper.asm resolve at init time
    ; NtQuerySystemInformation SSN on Win10 21H2+ is typically 0x0036
    ; but MUST be resolved dynamically for portability
    ssn_NtQuerySysInfo  dd  0x0036      ; overwritten by AsmResolveSSN()
    ssn_NtOpenProcess   dd  0x0026      ; overwritten by AsmResolveSSN()
    ssn_NtClose         dd  0x000F      ; overwritten by AsmResolveSSN()

section .bss
    ; Output buffer management
    proc_buffer         resq 1          ; pointer to allocated output buffer
    proc_buffer_size    resd 1          ; current buffer size in bytes
    return_length       resd 1          ; kernel-reported required length

section .text
    global AsmQueryProcessList
    global AsmGetSSN_NtQuerySysInfo
    global AsmSetSSN_NtQuerySysInfo
    global AsmOpenProcessDirect
    global AsmCloseHandleDirect

; ============================================================================
; AsmQueryProcessList
;
; Executes NtQuerySystemInformation(SystemProcessInformation=5) via direct
; syscall, returning the full kernel process list into caller-provided buffer.
;
; Parameters (Windows x64 calling convention):
;   RCX = SystemInformationClass (ULONG) — caller passes 5
;   RDX = SystemInformation (PVOID)      — output buffer
;   R8  = SystemInformationLength (ULONG)— buffer size in bytes
;   R9  = ReturnLength (PULONG)          — bytes written / needed
;
; Returns: NTSTATUS in EAX
;   0x00000000 = STATUS_SUCCESS
;   0xC0000004 = STATUS_INFO_LENGTH_MISMATCH (buffer too small, use ReturnLength)
;
; NOTE: On first call, pass a small buffer to get required size via ReturnLength,
;       then reallocate and call again. The C++ bridge handles this logic.
; ============================================================================
AsmQueryProcessList:
    ; Windows x64 ABI: allocate 32-byte shadow space
    sub     rsp, 0x28

    ; Syscall convention: r10 = rcx (NT syscall ABI requirement)
    ; The kernel expects the first arg in r10, not rcx
    mov     r10, rcx

    ; Load the dynamically resolved SSN for NtQuerySystemInformation
    ; In production: this value is written by AsmSetSSN_NtQuerySysInfo()
    mov     eax, dword [ssn_NtQuerySysInfo]

    ; Execute direct syscall — bypasses ntdll.dll hook chain entirely
    ; Control transfers directly to nt!NtQuerySystemInformation in kernel
    syscall

    ; Restore shadow space and return
    add     rsp, 0x28
    ret

; ============================================================================
; AsmOpenProcessDirect
;
; NtOpenProcess direct syscall — opens a handle to a target process by PID.
; Bypasses AV/EDR hooks on OpenProcess/NtOpenProcess in ntdll.
;
; Parameters:
;   RCX = ProcessHandle (PHANDLE)        — output handle
;   RDX = DesiredAccess (ACCESS_MASK)    — e.g. PROCESS_QUERY_INFORMATION
;   R8  = ObjectAttributes (POBJECT_ATTRIBUTES)
;   R9  = ClientId (PCLIENT_ID)          — contains PID
;
; Returns: NTSTATUS
; ============================================================================
AsmOpenProcessDirect:
    sub     rsp, 0x28
    mov     r10, rcx
    mov     eax, dword [ssn_NtOpenProcess]
    syscall
    add     rsp, 0x28
    ret

; ============================================================================
; AsmCloseHandleDirect
;
; NtClose direct syscall — closes kernel handle without ntdll interception.
;
; Parameters:
;   RCX = Handle (HANDLE)
;
; Returns: NTSTATUS
; ============================================================================
AsmCloseHandleDirect:
    sub     rsp, 0x28
    mov     r10, rcx
    mov     eax, dword [ssn_NtClose]
    syscall
    add     rsp, 0x28
    ret

; ============================================================================
; AsmGetSSN_NtQuerySysInfo / AsmSetSSN_NtQuerySysInfo
;
; Getter/setter for the NtQuerySystemInformation SSN.
; Called by syscall_wrapper.asm after dynamic resolution.
; ============================================================================
AsmGetSSN_NtQuerySysInfo:
    mov     eax, dword [ssn_NtQuerySysInfo]
    ret

AsmSetSSN_NtQuerySysInfo:
    ; RCX = new SSN value (DWORD)
    mov     dword [ssn_NtQuerySysInfo], ecx
    ret
