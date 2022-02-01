include ksamd64.inc
include CallConv.inc

extern InstrumentationCallback:proc
EXTERNDEF __imp_RtlCaptureContext:QWORD

.code
InstrumentationCallbackProxy proc
	push	rsp							; Back-up RSP, R10, and RAX to preserve them
	push	r10
	push	rax
	mov		rax, 1						; Set RAX to 1 for comparison
	cmp		gs:[2ech], rax				; See if the recursion flag has been set
	je		resume						; Jump and restore the registers if it has and resume
	pop		rax
	pop		r10
	pop		rsp
	mov     gs:[2e0h], rsp				; Win10 TEB InstrumentationCallbackPreviousSp
	mov     gs:[2d8h], r10				; Win10 TEB InstrumentationCallbackPreviousPc
	mov     r10, rcx					; Save original RCX
	sub     rsp, 4d0h					; Alloc stack space for CONTEXT structure
	and     rsp, -10h					; RSP must be 16 byte aligned before calls
	mov     rcx, rsp
	mov		rdx, 0h
	sub		rsp, 20h
	call    __imp_RtlCaptureContext		; Save the current register state. RtlCaptureContext does not require shadow space
	mov		r8, [rcx+78h]				; The value of RAX from the CONTEXT object stored at RSP
	mov		rdx, gs:[2d8h]				; The saved RIP address
	sub		rsp, 20h
	call    InstrumentationCallback		; Call main instrumentation routine
resume:
	pop		rax
	pop		r10
	pop		rsp
	jmp		r10
InstrumentationCallbackProxy endp

end