include ksamd64.inc
include CallConv.inc
.686

.model flat
public _InstrumentationCallbackProxy

assume fs:nothing
extern _InstrumentationCallback:PROC

.code
_InstrumentationCallbackProxy PROC

    push    esp                         ; back-up ESP, ECX, and EAX to restore them
    push    ecx
    push    eax
    mov     eax, 1                      ; Set EAX to 1 for comparison
    cmp     fs:1b8h, eax                ; See if the recurion flag has been set
    je      resume                      ; Jump and restore the registers if it has and resume
    pop     eax
    pop     ecx
    pop     esp
    mov     fs:1b0h, ecx                ; InstrumentationCallbackPreviousPc
    mov     fs:1b4h, esp                ; InstrumentationCallbackPreviousSp
    
    pushad                              ; Push registers to stack
    pushfd                              ; Push flags to the stack
    cld                                 ; Clear direction flag
    
    push    eax                         ; Return value
    push    ecx                         ; Return address
    call    _InstrumentationCallback
    add     esp, 08h                    ; Correct stack postion

    popfd                               ; Restore stored flags
    popad                               ; Restore stored registers

    mov     esp, fs:1b4h                ; Restore ESP
    mov     ecx, fs:1b0h                ; Restore ECX
    jmp     ecx                         ; Resume execution
resume:
    pop     eax
    pop     ecx
     pop     esp
    jmp     ecx

_InstrumentationCallbackProxy ENDP

assume fs:error
end
