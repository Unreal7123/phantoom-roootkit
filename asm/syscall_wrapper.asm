; ============================================================================
; PhantomScope — syscall_wrapper.asm
; Dynamic SSN Resolution Engine
;
; Resolves System Service Numbers (SSNs) at runtime by walking the ntdll.dll
; export table and reading the SSN from the mov eax, <SSN> instruction at
; offset +4 from each Nt function entry point.
;
; This approach is future-proof across all Windows versions because it never
; hardcodes SSN values — it reads them directly from the loaded ntdll image.
;
; Technique: "Hell's Gate" SSN resolution
;   1. Find ntdll.dll base via PEB->Ldr->InMemoryOrderModuleList
;   2. Walk export directory to find target function address
;   3. Read bytes at [func_addr + 4] — this is the SSN (mov eax, imm32)
;   4. Verify byte pattern: E9 (jmp = hooked) vs 4C 8B D1 (clean)
;
; Build: nasm -f win64 syscall_wrapper.asm -o syscall_wrapper.obj
; ============================================================================

bits 64
default rel

section .data
    ; Target function names as null-terminated ASCII strings
    ; Used to match against ntdll export name table
    str_NtQuerySysInfo  db  "NtQuerySystemInformation", 0
    str_NtOpenProcess   db  "NtOpenProcess", 0
    str_NtClose         db  "NtClose", 0
    str_NtReadFile      db  "NtReadFile", 0

    ; Resolved SSN storage — indexed by function ID
    ; Index: 0=NtQuerySysInfo, 1=NtOpenProcess, 2=NtClose, 3=NtReadFile
    resolved_ssns       times 8 dd 0xFFFFFFFF   ; 0xFFFF = unresolved sentinel

    ; ntdll base address cache
    ntdll_base          dq  0

section .bss
    ; Scratch buffer for string comparison
    cmp_buf             resb 256

section .text
    global AsmResolveAllSSNs
    global AsmGetNtdllBase
    global AsmResolveSSN
    global AsmGenericSyscall
    global AsmGetResolvedSSN

; ============================================================================
; AsmGetNtdllBase
;
; Finds ntdll.dll base address by walking:
;   PEB (GS:[0x60]) → Ldr → InMemoryOrderModuleList → ntdll entry
;
; Windows x64 PEB layout:
;   GS:[0x60] = PEB*
;   PEB+0x18  = Ldr (PEB_LDR_DATA*)
;   Ldr+0x20  = InMemoryOrderModuleList.Flink
;   Each LIST_ENTRY links LDR_DATA_TABLE_ENTRY structs
;   LDR_DATA_TABLE_ENTRY+0x50 = BaseDllName (UNICODE_STRING)
;   LDR_DATA_TABLE_ENTRY+0x30 = DllBase (module base address)
;
; Returns: ntdll base address in RAX (0 on failure)
; ============================================================================
AsmGetNtdllBase:
    sub     rsp, 0x28

    ; Check cache first
    mov     rax, qword [ntdll_base]
    test    rax, rax
    jnz     .return_cached

    ; GS:[0x60] = PEB pointer (Windows x64)
    mov     rax, qword gs:[0x60]        ; RAX = PEB*

    ; PEB->Ldr at offset 0x18
    mov     rax, qword [rax + 0x18]     ; RAX = PEB_LDR_DATA*

    ; InMemoryOrderModuleList.Flink at Ldr+0x20
    mov     rax, qword [rax + 0x20]     ; RAX = first LIST_ENTRY (exe itself)
    mov     rax, qword [rax]            ; RAX = Flink (next = ntdll in InMemoryOrder)

    ; The first module in InMemoryOrderModuleList is the main executable.
    ; The second is typically ntdll.dll.
    ; LDR_DATA_TABLE_ENTRY layout (InMemoryOrder):
    ;   +0x00 = InMemoryOrderLinks (LIST_ENTRY, 16 bytes)
    ;   +0x10 = Reserved2[2]
    ;   +0x20 = DllBase
    ;   +0x28 = EntryPoint
    ;   +0x30 = SizeOfImage
    ;   +0x38 = FullDllName (UNICODE_STRING: Length, MaxLength, Buffer)
    ;   +0x48 = BaseDllName (UNICODE_STRING)
    ;   DllBase at InMemoryOrderLinks base + 0x20

    mov     rbx, rax                    ; RBX = second module LIST_ENTRY

    ; Get DllBase of second module (ntdll)
    ; From InMemoryOrderLinks to start of LDR_DATA_TABLE_ENTRY = subtract 0x10
    ; (because InMemoryOrderLinks is at offset 0x10 in the full struct)
    ; DllBase = [struct + 0x20] = [LIST_ENTRY - 0x10 + 0x20] = [LIST_ENTRY + 0x10]
    mov     rax, qword [rbx + 0x20]     ; DllBase

    ; Cache the result
    mov     qword [ntdll_base], rax

.return_cached:
    add     rsp, 0x28
    ret

; ============================================================================
; AsmResolveSSN
;
; Resolves the SSN for a named Nt function by examining ntdll's export table.
;
; Parameters:
;   RCX = pointer to null-terminated function name string
;
; Returns:
;   EAX = SSN (System Service Number), or 0xFFFFFFFF on failure
;
; Algorithm:
;   1. Get ntdll base (AsmGetNtdllBase)
;   2. Parse IMAGE_EXPORT_DIRECTORY from PE headers
;   3. Walk AddressOfNames to find matching export name
;   4. Use ordinal to get function RVA from AddressOfFunctions
;   5. Check bytes at func_addr+4 for SSN pattern:
;      Clean stub: 4C 8B D1 (mov r10, rcx), B8 XX XX XX XX (mov eax, ssn)
;      Hooked stub: E9 (jmp to hook) — use ordinal sorting fallback
; ============================================================================
AsmResolveSSN:
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    sub     rsp, 0x28

    mov     r14, rcx                    ; R14 = function name string

    ; Step 1: Get ntdll base
    call    AsmGetNtdllBase
    test    rax, rax
    jz      .fail
    mov     r12, rax                    ; R12 = ntdll base

    ; Step 2: Parse PE headers
    ; IMAGE_DOS_HEADER.e_lfanew at offset 0x3C
    mov     eax, dword [r12 + 0x3C]     ; EAX = PE header offset
    lea     rsi, [r12 + rax]            ; RSI = IMAGE_NT_HEADERS*

    ; IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0] = ExportDirectory
    ; OptionalHeader starts at NT_HEADERS + 0x18
    ; DataDirectory[0] (export) at OptionalHeader + 0x70
    mov     eax, dword [rsi + 0x18 + 0x70]     ; Export RVA
    lea     rbx, [r12 + rax]                    ; RBX = IMAGE_EXPORT_DIRECTORY*

    ; Export directory fields:
    ;   +0x18 = NumberOfNames (DWORD)
    ;   +0x1C = AddressOfFunctions (RVA)
    ;   +0x20 = AddressOfNames (RVA)
    ;   +0x24 = AddressOfNameOrdinals (RVA)

    mov     r13d, dword [rbx + 0x18]    ; R13D = NumberOfNames
    mov     ecx, dword [rbx + 0x20]     ; ECX = AddressOfNames RVA
    lea     rsi, [r12 + rcx]            ; RSI = AddressOfNames array

    ; Step 3: Walk name table
    xor     rdi, rdi                    ; RDI = loop counter
.name_loop:
    cmp     rdi, r13
    jge     .fail

    mov     eax, dword [rsi + rdi*4]    ; EAX = name RVA
    lea     rcx, [r12 + rax]            ; RCX = function name string

    ; Compare with target function name
    push    rdi
    push    rsi
    push    rbx
    push    r12
    push    r13
    mov     rdx, r14                    ; RDX = target name
    call    AsmStrCmp
    pop     r13
    pop     r12
    pop     rbx
    pop     rsi
    pop     rdi

    test    eax, eax
    jz      .found_name

    inc     rdi
    jmp     .name_loop

.found_name:
    ; Step 4: Get function address via ordinal
    ; AddressOfNameOrdinals array at RBX+0x24
    mov     ecx, dword [rbx + 0x24]     ; AddressOfNameOrdinals RVA
    lea     rcx, [r12 + rcx]            ; ordinal array
    movzx   eax, word [rcx + rdi*2]     ; ordinal index

    ; AddressOfFunctions
    mov     ecx, dword [rbx + 0x1C]
    lea     rcx, [r12 + rcx]
    mov     eax, dword [rcx + rax*4]    ; function RVA
    lea     rcx, [r12 + rax]            ; RCX = function address

    ; Step 5: Read SSN from function prologue
    ; Clean NT stub pattern:
    ;   4C 8B D1    mov r10, rcx
    ;   B8 XX XX    mov eax, <SSN>      ← SSN at offset +4
    cmp     byte [rcx], 0x4C
    jne     .check_hooked
    cmp     byte [rcx+1], 0x8B
    jne     .check_hooked
    cmp     byte [rcx+2], 0xD1
    jne     .check_hooked

    ; Read SSN: 4 bytes at offset +4
    mov     eax, dword [rcx + 4]
    jmp     .done

.check_hooked:
    ; Function is hooked (starts with E9 jmp or other patch)
    ; Fallback: return 0xFFFFFFFF to signal fallback needed
    mov     eax, 0xFFFFFFFF
    jmp     .done

.fail:
    mov     eax, 0xFFFFFFFF

.done:
    add     rsp, 0x28
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

; ============================================================================
; AsmResolveAllSSNs
;
; Convenience function — resolves all required SSNs and stores them
; in the resolved_ssns table and also calls back into process_enum.asm
; via the setter functions to update the live values.
;
; No parameters. Returns: EAX = number of successfully resolved SSNs.
; ============================================================================
AsmResolveAllSSNs:
    push    rbx
    sub     rsp, 0x28

    ; Resolve NtQuerySystemInformation
    lea     rcx, [rel str_NtQuerySysInfo]
    call    AsmResolveSSN
    mov     dword [resolved_ssns + 0], eax

    ; Resolve NtOpenProcess
    lea     rcx, [rel str_NtOpenProcess]
    call    AsmResolveSSN
    mov     dword [resolved_ssns + 4], eax

    ; Resolve NtClose
    lea     rcx, [rel str_NtClose]
    call    AsmResolveSSN
    mov     dword [resolved_ssns + 8], eax

    ; Count successes
    xor     eax, eax
    xor     rbx, rbx
.count_loop:
    cmp     rbx, 3
    jge     .count_done
    cmp     dword [resolved_ssns + rbx*4], 0xFFFFFFFF
    je      .skip_count
    inc     eax
.skip_count:
    inc     rbx
    jmp     .count_loop
.count_done:

    add     rsp, 0x28
    pop     rbx
    ret

; ============================================================================
; AsmGenericSyscall
;
; Generic syscall stub — accepts SSN as first argument and shifts the rest.
; Used for calling arbitrary NT functions when only the SSN is known.
;
; Parameters:
;   RCX = SSN (DWORD)
;   RDX = arg1 (RCX in the NT call)
;   R8  = arg2 (RDX in the NT call)
;   R9  = arg3 (R8 in the NT call)
;   [RSP+0x28+0x08] = arg4 (R9 in the NT call)
;   ... additional args on stack
;
; Returns: NTSTATUS in EAX
; ============================================================================
AsmGenericSyscall:
    sub     rsp, 0x28

    ; Shift arguments: RCX(ssn) → EAX, RDX→R10, R8→RCX, R9→RDX
    mov     eax, ecx                    ; EAX = SSN
    mov     r10, rdx                    ; R10 = arg1 (NT syscall: r10=rcx)
    mov     rcx, r8                     ; RCX = arg2
    mov     rdx, r9                     ; RDX = arg3
    ; arg4 remains at [RSP+0x28+0x28] = [RSP+0x50]
    mov     r8, qword [rsp + 0x50]
    mov     r9, qword [rsp + 0x58]

    syscall

    add     rsp, 0x28
    ret

; ============================================================================
; AsmGetResolvedSSN
;
; Returns the resolved SSN for a given function index.
; Index: 0=NtQuerySysInfo, 1=NtOpenProcess, 2=NtClose
;
; Parameters: RCX = index (0-based)
; Returns: EAX = SSN, or 0xFFFFFFFF if not resolved
; ============================================================================
AsmGetResolvedSSN:
    cmp     ecx, 7
    jge     .invalid
    mov     eax, dword [resolved_ssns + rcx*4]
    ret
.invalid:
    mov     eax, 0xFFFFFFFF
    ret

; ============================================================================
; AsmStrCmp — internal helper
;
; Compares two null-terminated ASCII strings.
; Parameters: RCX = str1, RDX = str2
; Returns: EAX = 0 if equal, non-zero if different
; Clobbers: RAX, RCX, RDX, RSI, RDI
; ============================================================================
AsmStrCmp:
    push    rsi
    push    rdi
    mov     rsi, rcx
    mov     rdi, rdx
.cmp_loop:
    mov     al, byte [rsi]
    mov     ah, byte [rdi]
    cmp     al, ah
    jne     .not_equal
    test    al, al
    jz      .equal
    inc     rsi
    inc     rdi
    jmp     .cmp_loop
.equal:
    xor     eax, eax
    pop     rdi
    pop     rsi
    ret
.not_equal:
    movzx   eax, al
    movzx   ecx, ah
    sub     eax, ecx
    pop     rdi
    pop     rsi
    ret
