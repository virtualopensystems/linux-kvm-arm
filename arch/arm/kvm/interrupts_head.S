#define VCPU_USR_REG(_reg_nr)	(VCPU_USR_REGS + (_reg_nr * 4))
#define VCPU_USR_SP		(VCPU_USR_REG(13))
#define VCPU_USR_LR		(VCPU_USR_REG(14))
#define CP15_OFFSET(_cp15_reg_idx) (VCPU_CP15 + (_cp15_reg_idx * 4))

/* Clobbers {r2-r6} */
.macro store_vfp_state vfp_base
	@ The VFPFMRX and VFPFMXR macros are the VMRS and VMSR instructions
	VFPFMRX	r2, FPEXC
	@ Make sure VFP is enabled so we can touch the registers.
	orr	r6, r2, #FPEXC_EN
	VFPFMXR	FPEXC, r6

	VFPFMRX	r3, FPSCR
	tst	r2, #FPEXC_EX		@ Check for VFP Subarchitecture
	beq	1f
	@ If FPEXC_EX is 0, then FPINST/FPINST2 reads are upredictable, so
	@ we only need to save them if FPEXC_EX is set.
	VFPFMRX r4, FPINST
	tst	r2, #FPEXC_FP2V
	VFPFMRX r5, FPINST2, ne		@ vmrsne
	bic	r6, r2, #FPEXC_EX	@ FPEXC_EX disable
	VFPFMXR	FPEXC, r6
1:
	VFPFSTMIA \vfp_base, r6		@ Save VFP registers
	stm	\vfp_base, {r2-r5}	@ Save FPEXC, FPSCR, FPINST, FPINST2
.endm

/* Assume FPEXC_EN is on and FPEXC_EX is off, clobbers {r2-r6} */
.macro restore_vfp_state vfp_base
	VFPFLDMIA \vfp_base, r6		@ Load VFP registers
	ldm	\vfp_base, {r2-r5}	@ Load FPEXC, FPSCR, FPINST, FPINST2

	VFPFMXR FPSCR, r3
	tst	r2, #FPEXC_EX		@ Check for VFP Subarchitecture
	beq	1f
	VFPFMXR FPINST, r4
	tst	r2, #FPEXC_FP2V
	VFPFMXR FPINST2, r5, ne
1:
	VFPFMXR FPEXC, r2	@ FPEXC	(last, in case !EN)
.endm

/* These are simply for the macros to work - value don't have meaning */
.equ usr, 0
.equ svc, 1
.equ abt, 2
.equ und, 3
.equ irq, 4
.equ fiq, 5

.macro push_host_regs_mode mode
	mrs	r2, SP_\mode
	mrs	r3, LR_\mode
	mrs	r4, SPSR_\mode
	push	{r2, r3, r4}
.endm

.macro save_host_regs
	/* Hyp regs. Only ELR_hyp (SPSR_hyp already saved) */
	mrs	r2, ELR_hyp
	push	{r2}

	/* usr regs */
	push	{r4-r12}	@ r0-r3 are always clobbered
	mrs	r2, SP_usr
	mov	r3, lr
	push	{r2, r3}

	push_host_regs_mode svc
	push_host_regs_mode abt
	push_host_regs_mode und
	push_host_regs_mode irq

	/* fiq regs */
	mrs	r2, r8_fiq
	mrs	r3, r9_fiq
	mrs	r4, r10_fiq
	mrs	r5, r11_fiq
	mrs	r6, r12_fiq
	mrs	r7, SP_fiq
	mrs	r8, LR_fiq
	mrs	r9, SPSR_fiq
	push	{r2-r9}
.endm

.macro pop_host_regs_mode mode
	pop	{r2, r3, r4}
	msr	SP_\mode, r2
	msr	LR_\mode, r3
	msr	SPSR_\mode, r4
.endm

.macro restore_host_regs
	pop	{r2-r9}
	msr	r8_fiq, r2
	msr	r9_fiq, r3
	msr	r10_fiq, r4
	msr	r11_fiq, r5
	msr	r12_fiq, r6
	msr	SP_fiq, r7
	msr	LR_fiq, r8
	msr	SPSR_fiq, r9

	pop_host_regs_mode irq
	pop_host_regs_mode und
	pop_host_regs_mode abt
	pop_host_regs_mode svc

	pop	{r2, r3}
	msr	SP_usr, r2
	mov	lr, r3
	pop	{r4-r12}

	pop	{r2}
	msr	ELR_hyp, r2
.endm

/*
 * Restore SP, LR and SPSR for a given mode. offset is the offset of
 * this mode's registers from the VCPU base.
 * r0: VCPU address
 * Clobbers r1, r2, r3, r4.
 */
.macro restore_guest_regs_mode mode, offset
	add	r1, r0, \offset
	ldm	r1, {r2, r3, r4}
	msr	SP_\mode, r2
	msr	LR_\mode, r3
	msr	SPSR_\mode, r4
.endm

/*
 * Restore all guest registers.
 * r0: VCPU address
 * Clobbers *all* registers.
 */
.macro restore_guest_regs
	restore_guest_regs_mode svc, #VCPU_SVC_REGS
	restore_guest_regs_mode abt, #VCPU_ABT_REGS
	restore_guest_regs_mode und, #VCPU_UND_REGS
	restore_guest_regs_mode irq, #VCPU_IRQ_REGS

	add	r1, r0, #VCPU_FIQ_REGS
	ldm	r1, {r2-r9}
	msr	r8_fiq, r2
	msr	r9_fiq, r3
	msr	r10_fiq, r4
	msr	r11_fiq, r5
	msr	r12_fiq, r6
	msr	SP_fiq, r7
	msr	LR_fiq, r8
	msr	SPSR_fiq, r9

	@ Load return state
	ldr	r2, [r0, #VCPU_PC]
	ldr	r3, [r0, #VCPU_CPSR]
	msr	ELR_hyp, r2
	msr	SPSR_cxsf, r3

	@ Load user registers
	ldr	r2, [r0, #VCPU_USR_SP]
	ldr	r3, [r0, #VCPU_USR_LR]
	msr	SP_usr, r2
	mov	lr, r3
	add	r0, r0, #(VCPU_USR_REGS)
	ldm	r0, {r0-r12}
.endm

/*
 * Save SP, LR and SPSR for a given mode. offset is the offset of
 * this mode's registers from the VCPU base.
 * r1: VCPU address
 * Clobbers r2, r3, r4, r5.
 */
.macro save_guest_regs_mode mode, offset
	add	r2, r1, \offset
	mrs	r3, SP_\mode
	mrs	r4, LR_\mode
	mrs	r5, SPSR_\mode
	stm	r2, {r3, r4, r5}
.endm

/*
 * Save all guest registers
 * r1: VCPU address
 * Expects guest's r0, r1, r2 on the stack.
 * Clobbers r2, r3, r4, r5.
 */
.macro save_guest_regs
	@ Store usr registers
	add	r2, r1, #VCPU_USR_REG(3)
	stm	r2, {r3-r12}
	add	r2, r1, #VCPU_USR_REG(0)
	pop	{r3, r4, r5}		@ r0, r1, r2
	stm	r2, {r3, r4, r5}
	mrs	r2, SP_usr
	mov	r3, lr
	str	r2, [r1, #VCPU_USR_SP]
	str	r3, [r1, #VCPU_USR_LR]

	@ Store return state
	mrs	r2, ELR_hyp
	mrs	r3, spsr
	str	r2, [r1, #VCPU_PC]
	str	r3, [r1, #VCPU_CPSR]

	@ Store other guest registers
	save_guest_regs_mode svc, #VCPU_SVC_REGS
	save_guest_regs_mode abt, #VCPU_ABT_REGS
	save_guest_regs_mode und, #VCPU_UND_REGS
	save_guest_regs_mode irq, #VCPU_IRQ_REGS
.endm

/* Reads cp15 registers from hardware and stores them in memory
 * @vcpu:   If 0, registers are written in-order to the stack,
 * 	    otherwise to the VCPU struct pointed to by vcpup
 * @vcpup:  Register pointing to VCPU struct
 */
.macro read_cp15_state vcpu=0, vcpup
	mrc	p15, 0, r2, c1, c0, 0	@ SCTLR
	mrc	p15, 0, r3, c1, c0, 2	@ CPACR
	mrc	p15, 0, r4, c2, c0, 2	@ TTBCR
	mrc	p15, 0, r5, c3, c0, 0	@ DACR
	mrrc	p15, 0, r6, r7, c2	@ TTBR 0
	mrrc	p15, 1, r8, r9, c2	@ TTBR 1
	mrc	p15, 0, r10, c10, c2, 0	@ PRRR
	mrc	p15, 0, r11, c10, c2, 1	@ NMRR
	mrc	p15, 2, r12, c0, c0, 0	@ CSSELR

	.if \vcpu == 0
	push	{r2-r12}		@ Push CP15 registers
	.else
	str	r2, [\vcpup, #CP15_OFFSET(c1_SCTLR)]
	str	r3, [\vcpup, #CP15_OFFSET(c1_CPACR)]
	str	r4, [\vcpup, #CP15_OFFSET(c2_TTBCR)]
	str	r5, [\vcpup, #CP15_OFFSET(c3_DACR)]
	add	\vcpup, \vcpup, #CP15_OFFSET(c2_TTBR0)
	strd	r6, r7, [\vcpup]
	add	\vcpup, \vcpup, #CP15_OFFSET(c2_TTBR1) - CP15_OFFSET(c2_TTBR0)
	strd	r8, r9, [\vcpup]
	sub	\vcpup, \vcpup, #CP15_OFFSET(c2_TTBR1)
	str	r10, [\vcpup, #CP15_OFFSET(c10_PRRR)]
	str	r11, [\vcpup, #CP15_OFFSET(c10_NMRR)]
	str	r12, [\vcpup, #CP15_OFFSET(c0_CSSELR)]
	.endif

	mrc	p15, 0, r2, c13, c0, 1	@ CID
	mrc	p15, 0, r3, c13, c0, 2	@ TID_URW
	mrc	p15, 0, r4, c13, c0, 3	@ TID_URO
	mrc	p15, 0, r5, c13, c0, 4	@ TID_PRIV
	mrc	p15, 0, r6, c5, c0, 0	@ DFSR
	mrc	p15, 0, r7, c5, c0, 1	@ IFSR
	mrc	p15, 0, r8, c5, c1, 0	@ ADFSR
	mrc	p15, 0, r9, c5, c1, 1	@ AIFSR
	mrc	p15, 0, r10, c6, c0, 0	@ DFAR
	mrc	p15, 0, r11, c6, c0, 2	@ IFAR
	mrc	p15, 0, r12, c12, c0, 0	@ VBAR

	.if \vcpu == 0
	push	{r2-r12}		@ Push CP15 registers
	.else
	str	r2, [\vcpup, #CP15_OFFSET(c13_CID)]
	str	r3, [\vcpup, #CP15_OFFSET(c13_TID_URW)]
	str	r4, [\vcpup, #CP15_OFFSET(c13_TID_URO)]
	str	r5, [\vcpup, #CP15_OFFSET(c13_TID_PRIV)]
	str	r6, [\vcpup, #CP15_OFFSET(c5_DFSR)]
	str	r7, [\vcpup, #CP15_OFFSET(c5_IFSR)]
	str	r8, [\vcpup, #CP15_OFFSET(c5_ADFSR)]
	str	r9, [\vcpup, #CP15_OFFSET(c5_AIFSR)]
	str	r10, [\vcpup, #CP15_OFFSET(c6_DFAR)]
	str	r11, [\vcpup, #CP15_OFFSET(c6_IFAR)]
	str	r12, [\vcpup, #CP15_OFFSET(c12_VBAR)]
	.endif
.endm

/* Reads cp15 registers from memory and writes them to hardware
 * @vcpu:   If 0, registers are read in-order from the stack,
 * 	    otherwise from the VCPU struct pointed to by vcpup
 * @vcpup:  Register pointing to VCPU struct
 */
.macro write_cp15_state vcpu=0, vcpup
	.if \vcpu == 0
	pop	{r2-r12}
	.else
	ldr	r2, [\vcpup, #CP15_OFFSET(c13_CID)]
	ldr	r3, [\vcpup, #CP15_OFFSET(c13_TID_URW)]
	ldr	r4, [\vcpup, #CP15_OFFSET(c13_TID_URO)]
	ldr	r5, [\vcpup, #CP15_OFFSET(c13_TID_PRIV)]
	ldr	r6, [\vcpup, #CP15_OFFSET(c5_DFSR)]
	ldr	r7, [\vcpup, #CP15_OFFSET(c5_IFSR)]
	ldr	r8, [\vcpup, #CP15_OFFSET(c5_ADFSR)]
	ldr	r9, [\vcpup, #CP15_OFFSET(c5_AIFSR)]
	ldr	r10, [\vcpup, #CP15_OFFSET(c6_DFAR)]
	ldr	r11, [\vcpup, #CP15_OFFSET(c6_IFAR)]
	ldr	r12, [\vcpup, #CP15_OFFSET(c12_VBAR)]
	.endif

	mcr	p15, 0, r2, c13, c0, 1	@ CID
	mcr	p15, 0, r3, c13, c0, 2	@ TID_URW
	mcr	p15, 0, r4, c13, c0, 3	@ TID_URO
	mcr	p15, 0, r5, c13, c0, 4	@ TID_PRIV
	mcr	p15, 0, r6, c5, c0, 0	@ DFSR
	mcr	p15, 0, r7, c5, c0, 1	@ IFSR
	mcr	p15, 0, r8, c5, c1, 0	@ ADFSR
	mcr	p15, 0, r9, c5, c1, 1	@ AIFSR
	mcr	p15, 0, r10, c6, c0, 0	@ DFAR
	mcr	p15, 0, r11, c6, c0, 2	@ IFAR
	mcr	p15, 0, r12, c12, c0, 0	@ VBAR

	.if \vcpu == 0
	pop	{r2-r12}
	.else
	ldr	r2, [\vcpup, #CP15_OFFSET(c1_SCTLR)]
	ldr	r3, [\vcpup, #CP15_OFFSET(c1_CPACR)]
	ldr	r4, [\vcpup, #CP15_OFFSET(c2_TTBCR)]
	ldr	r5, [\vcpup, #CP15_OFFSET(c3_DACR)]
	add	\vcpup, \vcpup, #CP15_OFFSET(c2_TTBR0)
	ldrd	r6, r7, [\vcpup]
	add	\vcpup, \vcpup, #CP15_OFFSET(c2_TTBR1) - CP15_OFFSET(c2_TTBR0)
	ldrd	r8, r9, [\vcpup]
	sub	\vcpup, \vcpup, #CP15_OFFSET(c2_TTBR1)
	ldr	r10, [\vcpup, #CP15_OFFSET(c10_PRRR)]
	ldr	r11, [\vcpup, #CP15_OFFSET(c10_NMRR)]
	ldr	r12, [\vcpup, #CP15_OFFSET(c0_CSSELR)]
	.endif

	mcr	p15, 0, r2, c1, c0, 0	@ SCTLR
	mcr	p15, 0, r3, c1, c0, 2	@ CPACR
	mcr	p15, 0, r4, c2, c0, 2	@ TTBCR
	mcr	p15, 0, r5, c3, c0, 0	@ DACR
	mcrr	p15, 0, r6, r7, c2	@ TTBR 0
	mcrr	p15, 1, r8, r9, c2	@ TTBR 1
	mcr	p15, 0, r10, c10, c2, 0	@ PRRR
	mcr	p15, 0, r11, c10, c2, 1	@ NMRR
	mcr	p15, 2, r12, c0, c0, 0	@ CSSELR
.endm

/*
 * Save the VGIC CPU state into memory
 * @vcpup: Register pointing to VCPU struct
 */
.macro save_vgic_state	vcpup
#ifdef CONFIG_KVM_ARM_VGIC
	/* Get VGIC VCTRL base into r2 */
	ldr	r2, [\vcpup, #VCPU_KVM]
	ldr	r2, [r2, #KVM_VGIC_VCTRL]
	cmp	r2, #0
	beq	2f

	/* Compute the address of struct vgic_cpu */
	add	r11, \vcpup, #VCPU_VGIC_CPU

	/* Save all interesting registers */
	ldr	r3, [r2, #GICH_HCR]
	ldr	r4, [r2, #GICH_VMCR]
	ldr	r5, [r2, #GICH_MISR]
	ldr	r6, [r2, #GICH_EISR0]
	ldr	r7, [r2, #GICH_EISR1]
	ldr	r8, [r2, #GICH_ELRSR0]
	ldr	r9, [r2, #GICH_ELRSR1]
	ldr	r10, [r2, #GICH_APR]

	str	r3, [r11, #VGIC_CPU_HCR]
	str	r4, [r11, #VGIC_CPU_VMCR]
	str	r5, [r11, #VGIC_CPU_MISR]
	str	r6, [r11, #VGIC_CPU_EISR]
	str	r7, [r11, #(VGIC_CPU_EISR + 4)]
	str	r8, [r11, #VGIC_CPU_ELRSR]
	str	r9, [r11, #(VGIC_CPU_ELRSR + 4)]
	str	r10, [r11, #VGIC_CPU_APR]

	/* Save list registers */
	add	r2, r2, #GICH_LR0
	add	r3, r11, #VGIC_CPU_LR
	ldr	r4, [r11, #VGIC_CPU_NR_LR]
1:	ldr	r6, [r2], #4
	str	r6, [r3], #4
	subs	r4, r4, #1
	bne	1b
2:
#endif
.endm

/*
 * Restore the VGIC CPU state from memory
 * @vcpup: Register pointing to VCPU struct
 */
.macro restore_vgic_state	vcpup
#ifdef CONFIG_KVM_ARM_VGIC
	/* Get VGIC VCTRL base into r2 */
	ldr	r2, [\vcpup, #VCPU_KVM]
	ldr	r2, [r2, #KVM_VGIC_VCTRL]
	cmp	r2, #0
	beq	2f

	/* Compute the address of struct vgic_cpu */
	add	r11, \vcpup, #VCPU_VGIC_CPU

	/* We only restore a minimal set of registers */
	ldr	r3, [r11, #VGIC_CPU_HCR]
	ldr	r4, [r11, #VGIC_CPU_VMCR]
	ldr	r8, [r11, #VGIC_CPU_APR]

	str	r3, [r2, #GICH_HCR]
	str	r4, [r2, #GICH_VMCR]
	str	r8, [r2, #GICH_APR]

	/* Restore list registers */
	add	r2, r2, #GICH_LR0
	add	r3, r11, #VGIC_CPU_LR
	ldr	r4, [r11, #VGIC_CPU_NR_LR]
1:	ldr	r6, [r3], #4
	str	r6, [r2], #4
	subs	r4, r4, #1
	bne	1b
2:
#endif
.endm

#define CNTHCTL_PL1PCTEN	(1 << 0)
#define CNTHCTL_PL1PCEN		(1 << 1)

.macro save_timer_state	vcpup
#ifdef CONFIG_KVM_ARM_TIMER
	ldr	r4, [\vcpup, #VCPU_KVM]
	ldr	r2, [r4, #KVM_TIMER_ENABLED]
	cmp	r2, #0
	beq	1f

	mrc	p15, 0, r2, c14, c3, 1	@ CNTV_CTL
	and	r2, #3
	str	r2, [\vcpup, #VCPU_TIMER_CNTV_CTL]
	bic	r2, #1			@ Clear ENABLE
	mcr	p15, 0, r2, c14, c3, 1	@ CNTV_CTL
	isb

	mrrc	p15, 3, r2, r3, c14	@ CNTV_CVAL
	str	r3, [\vcpup, #VCPU_TIMER_CNTV_CVALH]
	str	r2, [\vcpup, #VCPU_TIMER_CNTV_CVALL]

1:
#endif
	@ Allow physical timer/counter access for the host
	mrc	p15, 4, r2, c14, c1, 0	@ CNTHCTL
	orr	r2, r2, #(CNTHCTL_PL1PCEN | CNTHCTL_PL1PCTEN)
	mcr	p15, 4, r2, c14, c1, 0	@ CNTHCTL
.endm

.macro restore_timer_state vcpup
	@ Disallow physical timer access for the guest
	@ Physical counter access is allowed
	mrc	p15, 4, r2, c14, c1, 0	@ CNTHCTL
	orr	r2, r2, #CNTHCTL_PL1PCTEN
	bic	r2, r2, #CNTHCTL_PL1PCEN
	mcr	p15, 4, r2, c14, c1, 0	@ CNTHCTL

#ifdef CONFIG_KVM_ARM_TIMER
	ldr	r4, [\vcpup, #VCPU_KVM]
	ldr	r2, [r4, #KVM_TIMER_ENABLED]
	cmp	r2, #0
	beq	1f

	ldr	r3, [r4, #KVM_TIMER_CNTVOFF_H]
	ldr	r2, [r4, #KVM_TIMER_CNTVOFF_L]
	mcrr	p15, 4, r2, r3, c14	@ CNTVOFF
	isb

	ldr	r3, [\vcpup, #VCPU_TIMER_CNTV_CVALH]
	ldr	r2, [\vcpup, #VCPU_TIMER_CNTV_CVALL]
	mcrr	p15, 3, r2, r3, c14	@ CNTV_CVAL

	ldr	r2, [\vcpup, #VCPU_TIMER_CNTV_CTL]
	and	r2, #3
	mcr	p15, 0, r2, c14, c3, 1	@ CNTV_CTL
	isb
1:
#endif
.endm

/* Configures the HSTR (Hyp System Trap Register) on entry/return
 * (hardware reset value is 0) */
.macro set_hstr entry
	mrc	p15, 4, r2, c1, c1, 3
	ldr	r3, =HSTR_T(15)
	.if \entry == 1
	orr	r2, r2, r3		@ Trap CR{15}
	.else
	bic	r2, r2, r3		@ Don't trap any CRx accesses
	.endif
	mcr	p15, 4, r2, c1, c1, 3
.endm

/* Configures the HCPTR (Hyp Coprocessor Trap Register) on entry/return
 * (hardware reset value is 0). Keep previous value in r2. */
.macro set_hcptr entry, mask
	mrc	p15, 4, r2, c1, c1, 2
	ldr	r3, =\mask
	.if \entry == 1
	orr	r3, r2, r3		@ Trap coproc-accesses defined in mask
	.else
	bic	r3, r2, r3		@ Don't trap defined coproc-accesses
	.endif
	mcr	p15, 4, r3, c1, c1, 2
.endm

/* Configures the HDCR (Hyp Debug Configuration Register) on entry/return
 * (hardware reset value is 0) */
.macro set_hdcr entry
	mrc	p15, 4, r2, c1, c1, 1
	ldr	r3, =(HDCR_TPM|HDCR_TPMCR)
	.if \entry == 1
	orr	r2, r2, r3		@ Trap some perfmon accesses
	.else
	bic	r2, r2, r3		@ Don't trap any perfmon accesses
	.endif
	mcr	p15, 4, r2, c1, c1, 1
.endm

/* Enable/Disable: stage-2 trans., trap interrupts, trap wfi, trap smc */
.macro configure_hyp_role entry, vcpu_ptr
	mrc	p15, 4, r2, c1, c1, 0	@ HCR
	bic	r2, r2, #HCR_VIRT_EXCP_MASK
	ldr	r3, =HCR_GUEST_MASK
	.if \entry == 1
	orr	r2, r2, r3
	ldr	r3, [\vcpu_ptr, #VCPU_IRQ_LINES]
	orr	r2, r2, r3
	.else
	bic	r2, r2, r3
	.endif
	mcr	p15, 4, r2, c1, c1, 0
.endm

.macro load_vcpu reg
	mrc	p15, 4, \reg, c13, c0, 2	@ HTPIDR
.endm
