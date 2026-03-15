; ============================================================================
; PhantomScope — linux_proc.asm
; Linux Process Enumeration via sys_getdents64
;
; Enumerates all running processes by directly calling sys_getdents64 on the
; /proc virtual filesystem. This bypasses any userland tools (ps, top, pgrep)
; that could be hooked or manipulated by a rootkit-loaded kernel module.
;
; Rootkit Detection on Linux:
;   A kernel-level rootkit (e.g., Diamorphine, Reptile, Azazel) can hide
;   processes by hooking sys_getdents64 in the kernel's syscall table or
;   by filtering entries from /proc. This module provides the "ground truth"
;   view. The C++ bridge then compares this with the output of /proc/[pid]
;   stat parsing to detect discrepancies. For full rootkit detection, a
;   secondary enumeration via the /proc filesystem walk in C++ is compared
;   against a direct eBPF program (planned for v1.1) reading kernel task_struct.
;
; Syscall numbers (x86-64 Linux):
;   sys_open        = 2   (openat = 257 preferred)
;   sys_read        = 0
;   sys_close       = 3
;   sys_getdents64  = 217
;   sys_openat      = 257
;
; Build: nasm -f elf64 linux_proc.asm -o linux_proc.obj
; ============================================================================

bits 64
default rel

; Linux syscall numbers
SYS_READ        equ 0
SYS_WRITE       equ 1
SYS_OPEN        equ 2
SYS_CLOSE       equ 3
SYS_STAT        equ 4
SYS_OPENAT      equ 257
SYS_GETDENTS64  equ 217

; O_RDONLY | O_DIRECTORY flags
O_RDONLY        equ 0x0000
O_DIRECTORY     equ 0x10000

; linux_dirent64 structure offsets
; struct linux_dirent64 {
;     ino64_t  d_ino;      // +0  (8 bytes) inode number
;     off64_t  d_off;      // +8  (8 bytes) offset to next entry
;     uint16_t d_reclen;   // +16 (2 bytes) length of this record
;     uint8_t  d_type;     // +18 (1 byte)  file type
;     char     d_name[];   // +19 variable   null-terminated name
; }
DIRENT64_INO    equ 0
DIRENT64_OFF    equ 8
DIRENT64_RECLEN equ 16
DIRENT64_TYPE   equ 18
DIRENT64_NAME   equ 19

DT_DIR          equ 4                   ; directory entry type

section .data
    str_proc    db  "/proc", 0          ; /proc path
    str_status  db  "/status", 0        ; /status file suffix
    str_maps    db  "/maps", 0          ; /maps file suffix

    ; Buffer sizes
    DENTS_BUF_SIZE  equ 65536           ; 64KB for getdents64 output
    STATUS_BUF_SIZE equ 4096            ; 4KB for /proc/PID/status

section .bss
align 16
    ; getdents64 output buffer
    dents_buffer    resb DENTS_BUF_SIZE

    ; Status file read buffer
    status_buffer   resb STATUS_BUF_SIZE

    ; /proc dir file descriptor
    proc_fd         resq 1

    ; Scratch string buffer for constructing /proc/PID/status paths
    path_buf        resb 64

section .text
    global AsmLinuxEnumProcesses
    global AsmLinuxReadProcStatus
    global AsmLinuxOpenProcDir
    global AsmLinuxGetProcFd

; ============================================================================
; AsmLinuxEnumProcesses
;
; Enumerates all processes visible in /proc via sys_getdents64.
; Fills the caller-provided PID array with found process IDs.
;
; Parameters:
;   RDI = output buffer for PID array (uint32_t[])
;   RSI = output buffer capacity (max PIDs to return)
;   RDX = pointer to uint32_t to receive actual count
;
; Returns:
;   EAX = 0 on success, -errno on failure
;
; Algorithm:
;   1. Open /proc with O_RDONLY | O_DIRECTORY via sys_openat
;   2. Call sys_getdents64 repeatedly until all entries read
;   3. For each entry: check if d_name is a numeric string (PID)
;   4. Convert numeric string to integer, add to output array
;   5. Close /proc fd
; ============================================================================
AsmLinuxEnumProcesses:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    mov     r12, rdi                    ; R12 = PID output array
    mov     r13, rsi                    ; R13 = max capacity
    mov     r14, rdx                    ; R14 = count output ptr
    xor     r15, r15                    ; R15 = found count

    ; Step 1: Open /proc directory
    ; sys_openat(AT_FDCWD=-100, "/proc", O_RDONLY|O_DIRECTORY, 0)
    mov     rax, SYS_OPENAT
    mov     rdi, -100                   ; AT_FDCWD
    lea     rsi, [rel str_proc]
    mov     rdx, O_RDONLY | O_DIRECTORY
    xor     r10, r10                    ; mode = 0 (not creating)
    syscall

    test    rax, rax
    js      .open_failed                ; negative = error

    mov     rbx, rax                    ; RBX = /proc fd
    mov     qword [rel proc_fd], rax

.getdents_loop:
    ; sys_getdents64(fd, buf, bufsize)
    mov     rax, SYS_GETDENTS64
    mov     rdi, rbx
    lea     rsi, [rel dents_buffer]
    mov     rdx, DENTS_BUF_SIZE
    syscall

    test    rax, rax
    jz      .all_entries_read           ; 0 = end of directory
    js      .getdents_failed

    ; RAX = bytes returned in buffer
    mov     rbp, rax                    ; RBP = bytes_read

    ; Step 3: Walk the dirent64 entries
    lea     rsi, [rel dents_buffer]     ; RSI = current entry
    xor     rcx, rcx                    ; RCX = bytes processed

.walk_entries:
    cmp     rcx, rbp
    jge     .getdents_loop              ; processed all entries in this batch

    ; Get entry at RSI+RCX
    lea     rdi, [rsi + rcx]            ; RDI = current linux_dirent64*

    ; Get record length for advancing to next entry
    movzx   rax, word [rdi + DIRENT64_RECLEN]
    push    rax                         ; save reclen

    ; Check if d_type is DT_DIR (we only care about directories in /proc)
    movzx   r8, byte [rdi + DIRENT64_TYPE]
    cmp     r8, DT_DIR
    jne     .next_entry

    ; Check if d_name starts with a digit (0x30-0x39 = '0'-'9')
    lea     r9, [rdi + DIRENT64_NAME]   ; R9 = d_name
    movzx   r8, byte [r9]
    cmp     r8, 0x30                    ; '0'
    jl      .next_entry
    cmp     r8, 0x39                    ; '9'
    jg      .next_entry

    ; It's a numeric directory name — this is a PID
    ; Convert ASCII string to integer
    push    rcx
    push    rsi
    push    rbx
    mov     rdi, r9                     ; RDI = PID string
    call    AsmAtoiUnsigned             ; RAX = PID as integer
    pop     rbx
    pop     rsi
    pop     rcx

    ; Check capacity
    cmp     r15, r13
    jge     .next_entry                 ; output array full

    ; Store PID in output array
    mov     dword [r12 + r15*4], eax
    inc     r15

.next_entry:
    pop     rax                         ; restore reclen
    add     rcx, rax                    ; advance to next entry
    jmp     .walk_entries

.all_entries_read:
    ; Step 5: Close /proc fd
    mov     rax, SYS_CLOSE
    mov     rdi, rbx
    syscall

    ; Write count to output
    mov     dword [r14], r15d
    xor     eax, eax                    ; return success
    jmp     .done

.open_failed:
.getdents_failed:
    ; Return negative errno
    neg     eax

.done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ============================================================================
; AsmLinuxReadProcStatus
;
; Reads /proc/[pid]/status and extracts Name and State fields.
;
; Parameters:
;   RDI = PID (uint32_t)
;   RSI = output buffer for process name (up to 64 bytes)
;   RDX = output byte for state ('R','S','D','T','Z')
;
; Returns: EAX = 0 on success, -1 on failure
; ============================================================================
AsmLinuxReadProcStatus:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    sub     rsp, 0x28

    mov     r12, rdi                    ; R12 = PID
    mov     r13, rsi                    ; R13 = name output buffer
    mov     r14, rdx                    ; R14 = state output byte ptr

    ; Build path: /proc/<pid>/status
    lea     rbx, [rel path_buf]
    lea     rdi, [rel str_proc]
    mov     rsi, rbx
    call    AsmStrCopy                  ; copy "/proc"

    ; Append "/" + decimal PID
    mov     byte [rsi], '/'
    inc     rsi
    mov     rdi, rsi
    mov     rsi, r12
    call    AsmUtoaDecimal              ; write PID digits
    ; RSI = pointer past last digit

    ; Append "/status"
    lea     rdi, [rel str_status]
    call    AsmStrAppend

    ; Open /proc/<pid>/status
    mov     rax, SYS_OPENAT
    mov     rdi, -100                   ; AT_FDCWD
    lea     rsi, [rel path_buf]
    mov     rdx, O_RDONLY
    xor     r10, r10
    syscall

    test    rax, rax
    js      .fail

    mov     rbp, rax                    ; RBP = fd

    ; Read file content
    mov     rax, SYS_READ
    mov     rdi, rbp
    lea     rsi, [rel status_buffer]
    mov     rdx, STATUS_BUF_SIZE
    syscall

    push    rax                         ; save bytes_read

    ; Close fd
    mov     rax, SYS_CLOSE
    mov     rdi, rbp
    syscall

    pop     rax
    test    rax, rax
    jle     .fail

    ; Parse "Name:\t<name>\n" from status buffer
    ; Search for "Name:" pattern
    lea     rdi, [rel status_buffer]
    mov     rbp, rax                    ; RBP = bytes read
    call    AsmParseProcStatusName
    test    rax, rax
    jz      .fail
    ; RAX = pointer to name string in buffer

    ; Copy name to output (up to 63 chars)
    mov     rsi, rax
    mov     rdi, r13
    mov     rcx, 63
.copy_name:
    mov     al, byte [rsi]
    test    al, al
    jz      .name_done
    cmp     al, 0x0A                    ; newline
    je      .name_done
    mov     byte [rdi], al
    inc     rsi
    inc     rdi
    dec     rcx
    jnz     .copy_name
.name_done:
    mov     byte [rdi], 0               ; null-terminate

    xor     eax, eax
    jmp     .done

.fail:
    mov     eax, -1

.done:
    add     rsp, 0x28
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ============================================================================
; Helper functions
; ============================================================================

; AsmAtoiUnsigned: Convert ASCII decimal string to uint32
; RDI = string pointer → RAX = integer value
AsmAtoiUnsigned:
    xor     eax, eax
.atoi_loop:
    movzx   rcx, byte [rdi]
    cmp     cl, '0'
    jl      .atoi_done
    cmp     cl, '9'
    jg      .atoi_done
    imul    eax, eax, 10
    sub     ecx, '0'
    add     eax, ecx
    inc     rdi
    jmp     .atoi_loop
.atoi_done:
    ret

; AsmUtoaDecimal: Write uint64 as decimal string
; RDI = output buffer, RSI = value → returns bytes written in RAX
AsmUtoaDecimal:
    push    rbx
    push    rdi
    mov     rax, rsi
    lea     rbx, [rdi + 20]             ; temp end of buffer
    mov     byte [rbx], 0
    dec     rbx
    mov     ecx, 10
.utoa_loop:
    xor     rdx, rdx
    div     rcx
    add     dl, '0'
    mov     byte [rbx], dl
    dec     rbx
    test    rax, rax
    jnz     .utoa_loop
    inc     rbx
    ; Shift to front of buffer
    pop     rdi
    mov     rsi, rbx
.utoa_shift:
    mov     al, byte [rsi]
    mov     byte [rdi], al
    inc     rsi
    inc     rdi
    test    al, al
    jnz     .utoa_shift
    pop     rbx
    ret

; AsmStrCopy: Copy null-terminated string from RDI to RSI
; Returns: RSI = pointer to null terminator in destination
AsmStrCopy:
.copy_loop:
    mov     al, byte [rdi]
    mov     byte [rsi], al
    inc     rdi
    inc     rsi
    test    al, al
    jnz     .copy_loop
    dec     rsi                         ; back up to null
    ret

; AsmStrAppend: Append null-terminated string from RDI to end of buffer at RSI
AsmStrAppend:
.append_loop:
    mov     al, byte [rdi]
    mov     byte [rsi], al
    inc     rdi
    inc     rsi
    test    al, al
    jnz     .append_loop
    ret

; AsmParseProcStatusName: Find "Name:" in proc status buffer
; RDI = buffer, RBP = length → RAX = pointer to name value (or 0)
AsmParseProcStatusName:
    push    rbx
    push    rcx
    mov     rbx, rdi
    mov     rcx, rbp
    ; Search for "Name:" (4E 61 6D 65 3A)
.search_loop:
    cmp     rcx, 5
    jl      .not_found
    cmp     byte [rbx],   'N'
    jne     .advance
    cmp     byte [rbx+1], 'a'
    jne     .advance
    cmp     byte [rbx+2], 'm'
    jne     .advance
    cmp     byte [rbx+3], 'e'
    jne     .advance
    cmp     byte [rbx+4], ':'
    jne     .advance
    ; Found — skip "Name:\t"
    add     rbx, 5
    movzx   eax, byte [rbx]
    cmp     al, 0x09                    ; tab
    jne     .return_name
    inc     rbx
.return_name:
    mov     rax, rbx
    pop     rcx
    pop     rbx
    ret
.advance:
    inc     rbx
    dec     rcx
    jmp     .search_loop
.not_found:
    xor     rax, rax
    pop     rcx
    pop     rbx
    ret

; AsmLinuxGetProcFd: Returns cached /proc fd
AsmLinuxGetProcFd:
    mov     rax, qword [rel proc_fd]
    ret

; AsmLinuxOpenProcDir: Opens /proc and caches the fd
AsmLinuxOpenProcDir:
    mov     rax, SYS_OPENAT
    mov     rdi, -100
    lea     rsi, [rel str_proc]
    mov     rdx, O_RDONLY | O_DIRECTORY
    xor     r10, r10
    syscall
    mov     qword [rel proc_fd], rax
    ret
