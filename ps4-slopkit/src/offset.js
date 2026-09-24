﻿export const REQUIRED_KEYS = [
    "wk_expm1_builtin", "wk_JSFunction_m_function",
    "wk_POP_RDI_RET", "wk_POP_RSI_RET", "wk_POP_RDX_RET", "wk_POP_RCX_RET",
    "wk_POP_RAX_RET", "wk_POP_R8_RET", "wk_POP_R9_RET", "wk_LEAVE_RET",
    "wk_MOV_QWORD_PTR_RDI_RAX_RET",
    "wk_MOV_RDI_RSI_30_CALL", "wk_POP_RAX_MOV_RAX_JMP_18",
    "wk_PUSH_RBP_MOV_RBP_RSP_10", "wk_MOV_RDI_RAX_8_CALL_20",
    "wk_MOV_RDX_RAX_18_CALL_10", "wk_PUSH_RDX_POP_RSP_RET",
    "pivot_view_sp", "wk_ArrayBuffer_m_impl", "wk_ArrayBuffer_m_contents_m_data",
    "wk___imp___error", "k__error",
    "k_scan_stage1", "k_scan_stage2",
    "k_evf_cv", "k_sysent_661", "k_jmp_rsi",
];

/*
OPTIONAL_KEYS = the union of what EVERY chain may want, not what any one chain
needs. Nothing here is enforced by the table itself; each chain's own gates
decide.

NO "payload" key. The HEN blob is a USER CHOICE, not a firmware property: the
dropdown writes goldhen.bin / hen.bin into localStorage and module/assets.js
resolves it. The chains call loadPayload(options.payload) and never consult the
offset table for it.

NO "k_prison0" / "k_rootvnode" KEY -- and this one is load-bearing, see
NOTES-webkit-chain.md:184-199. Those are STATIC RVAs into the kernel image.
They are valid for a chain running under a full libkernel build, but our chains
run in the Internet Browser against libkernel_web.sprx, where the same RVAs do
NOT address those structures. Everything below the double-free therefore
derives them at runtime from the process itself instead of reading them from a
table:

    curproc   <- ioctl(pipe, FIOSETOWN, pid); f_data(+0x0) -> +0xd0 -> +0x0
    kProc     <- walk p_list_next (+0x00) from curproc until p_pid(+0xb0)==0
    prison0   <- kProc.p_ucred(+0x40).cr_prison(+0x30)
    rootvnode <- kProc.p_fd(+0x48).fd_rdir(+0x10)

Putting the static RVAs in this table would look correct and silently point
the jailbreak writes at the wrong addresses on every firmware.

Groups here:
  - k_stubs / pthread: present on 11.50+ only. 10.00-11.02 rely on the runtime
    stub SCAN (discoverStubs seeds from k_stubs when it exists, then scans
    k_scan_stage1 when it does not).
  - the k_idt_rsvd / k_oid_* / k_arg1_* / k_sysctl_handle_int block:
    relapse.js ONLY -- its kern.file oracle. lapse.js and netctrl.js read none.
*/
export const OPTIONAL_KEYS = [
    "k_stubs", "wk_pthread_create",
    "wk___imp_pthread_create", "k_pthread_create", "kpatch",
    "alias_of",
    /* relapse.js only -- the kern.file anchor + oracle table. */
    "k_idt_rsvd", "k_sysctl_handle_int",
    "k_oid_kern_file", "k_oid_maxfilesperproc", "k_oid_maxprocperuid",
    "k_oid_maxfiles",
    "k_arg1_maxfilesperproc", "k_arg1_maxprocperuid", "k_arg1_maxfiles",
];

export const PS4 = {
    "10.00": {
        wk_expm1_builtin: 0x218bb70,
        wk_JSFunction_m_function: 0x28, // JSC class-layout constant; same WebKit (Safari 15.4) gen as verified 10.00-11.02
        wk_CSSFontFace_vtable: 0x3617a38,
        wk___imp___error: 0x36d1bf0,
        k__error: 0x14f40,
        wk___imp_strerror: 0x36d1c20,
        c_strerror: 0x10d00,
        wk_POP_RDI_RET: 0x51056,
        wk_POP_RSI_RET: 0xbe86,
        wk_POP_RDX_RET: 0x1644b2,
        wk_POP_RCX_RET: 0x3a6c9,
        wk_POP_RAX_RET: 0xe882,
        wk_POP_R8_RET: 0xe881,
        wk_POP_R9_RET: 0x947b91,
        wk_LEAVE_RET: 0x2ca6c3,
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0xc037,
        wk_PUSH_RDX_POP_RSP_RET: 0x168bc7a,
        wk_MOV_RDI_RSI_30_CALL: 0x24d28f8,
        wk_POP_RAX_MOV_RAX_JMP_18: 0xaa6d13,
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0x16b91a0,
        wk_MOV_RDI_RAX_8_CALL_20: 0x1fc94a7,
        wk_MOV_RDX_RAX_18_CALL_10: 0x1005476,
        pivot_view_sp: 0x18, // G4 displacement byte, byte-gated at runtime
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk_pthread_create: 0x20c8,
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x7b5133,
        k_sysent_661: 0x110a980,
        k_jmp_rsi: 0x68b1,
        k_kl_lock: 0x45b10,
    },
    "10.50": {
        wk_expm1_builtin: 0x218dcd0,
        wk_JSFunction_m_function: 0x28,
        wk_CSSFontFace_vtable: 0x361ba28,
        wk___imp___error: 0x36d5be8,
        k__error: 0x1470,
        wk___imp_strerror: 0x36d5c18,
        c_strerror: 0x10d00,
        wk_POP_RDI_RET: 0x5b8a9,
        wk_POP_RSI_RET: 0x13b027,
        wk_POP_RDX_RET: 0x1d9eb,
        wk_POP_RCX_RET: 0x1da1c,
        wk_POP_RAX_RET: 0x2cd92,
        wk_POP_R8_RET: 0x2cd91,
        wk_POP_R9_RET: 0x58104d,
        wk_LEAVE_RET: 0x38712,
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x18b1b,
        wk_PUSH_RDX_POP_RSP_RET: 0x179186a,
        wk_MOV_RDI_RSI_30_CALL: 0x24d49c8,
        wk_POP_RAX_MOV_RAX_JMP_18: 0x410583,
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0xb1f280,
        wk_MOV_RDI_RAX_8_CALL_20: 0x10e302c,
        wk_MOV_RDX_RAX_18_CALL_10: 0x19d3844,
        pivot_view_sp: 0x18,
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk_pthread_create: 0x20d8,
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x7a7b14,
        k_sysent_661: 0x110a5b0,
        k_jmp_rsi: 0x50ded,
        k_kl_lock: 0x25e330,
    },
    "11.00": {
        wk_expm1_builtin: 0x2193f30,
        wk_JSFunction_m_function: 0x28,
        wk_CSSFontFace_vtable: 0x3627aa8,
        wk___imp___error: 0x36e1c68,
        k__error: 0x3370,
        wk___imp_strerror: 0x36e1c98,
        c_strerror: 0x10d00,
        wk_POP_RDI_RET: 0x357a0,
        wk_POP_RAX_RET: 0x4e6a9,
        wk_MOV_RDI_RSI_30_CALL: 0x24dae58,
        wk_POP_RAX_MOV_RAX_JMP_18: 0x11d5d53,
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0x2f1890,
        wk_MOV_RDI_RAX_8_CALL_20: 0x41a81,
        wk_MOV_RDX_RAX_18_CALL_10: 0x90ffe6,
        wk_PUSH_RDX_POP_RSP_RET: 0x1cc607a,
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x97db,
        wk_LEAVE_RET: 0x31f9d,
        wk_POP_RSI_RET: 0x249e2,
        wk_POP_RDX_RET: 0x10d11,
        wk_POP_RCX_RET: 0x71617,
        wk_POP_R8_RET: 0xe53a2,
        wk_POP_R9_RET: 0x6403a1,
        pivot_view_sp: 0x18,
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk_pthread_create: 0x2068,
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x7fc26f,
        k_sysent_661: 0x1109350,
        k_jmp_rsi: 0x71a21,
        k_kl_lock: 0x58f10,
    },
    "11.02": {
        wk_expm1_builtin: 0x2193f40,
        wk_JSFunction_m_function: 0x28,
        wk_CSSFontFace_vtable: 0x3627aa8,
        wk___imp___error: 0x36e1c68,
        k__error: 0x3370,
        wk___imp_strerror: 0x36e1c98,
        c_strerror: 0x10d00,
        wk_POP_RDI_RET: 0x272776,
        wk_POP_RAX_RET: 0x116d4,
        wk_MOV_RDI_RSI_30_CALL: 0x24dae68,
        wk_POP_RAX_MOV_RAX_JMP_18: 0x11d5d53,
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0x2f1890,
        wk_MOV_RDI_RAX_8_CALL_20: 0x41a81,
        wk_MOV_RDX_RAX_18_CALL_10: 0x90fff6,
        wk_PUSH_RDX_POP_RSP_RET: 0x1cc607a,
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x97db,
        wk_LEAVE_RET: 0x31f9d,
        wk_POP_RSI_RET: 0x249e2,
        wk_POP_RDX_RET: 0x10d11,
        wk_POP_RCX_RET: 0x71617,
        wk_POP_R8_RET: 0xe53a2,
        wk_POP_R9_RET: 0x6403b1,
        pivot_view_sp: 0x18,
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk_pthread_create: 0x2068,
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x7fc22f,
        k_sysent_661: 0x1109350,
        k_jmp_rsi: 0x71a21,
        k_kl_lock: 0x58f10,
    },
    "11.50": {
        wk_expm1_builtin: 0x2587bd0,
        wk_JSFunction_m_function: 0x28,
        wk_POP_RDI_RET: 0x2445241,
        wk_POP_RSI_RET: 0x2503c9e,
        wk_POP_RDX_RET: 0x24cfa22,
        wk_POP_RCX_RET: 0x24c7ebf,
        wk_POP_RAX_RET: 0x2554e3f,
        wk_POP_R8_RET: 0x23bb4bd,
        wk_POP_R9_RET: 0x1c2cda1,
        wk_LEAVE_RET: 0x23c3790,
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x2445d1a,
        wk_MOV_RDI_RSI_30_CALL: 0x29609f8,
        wk_POP_RAX_MOV_RAX_JMP_18: 0x1c8bbc3,
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0x1645270,
        wk_MOV_RDI_RAX_8_CALL_20: 0x1e3f795,
        wk_MOV_RDX_RAX_18_CALL_10: 0x1dea16a,
        wk_PUSH_RDX_POP_RSP_RET: 0x2abe00a,
        pivot_view_sp: 0x38,
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk___imp___error: 0x3cbcc98,
        k__error: 0x183c0,
        wk___imp_pthread_create: 0x3cbdbb8,
        k_pthread_create: 0xa1d0,
        k_stubs: {
            3: 0x2c170, 4: 0x2b8d0, 5: 0x2b970, 6: 0x2d620,
            20: 0x2cb70, 23: 0x2b6f0, 24: 0x2d5e0, 25: 0x2b4d0,
            30: 0x2c9d0, 54: 0x2cff0, 92: 0x2b650, 97: 0x2d050,
            98: 0x2b5f0, 105: 0x2b480, 106: 0x2d470, 118: 0x2b2e0,
            135: 0x2c270, 240: 0x2d4b0, 331: 0x2c6a0, 432: 0x2b500,
            466: 0x2cc60, 487: 0x2ba70, 488: 0x2bd00, 538: 0x2b420,
            539: 0x2b4e0, 544: 0x2bea0, 545: 0x2ca20, 632: 0x2d080,
            633: 0x2d830, 662: 0x2cca0, 663: 0x2c3d0, 664: 0x2d730,
            666: 0x2d530, 669: 0x2bde0,
        },
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x784798,
        k_sysent_661: 0x110a760,
        k_jmp_rsi: 0x47b31,
        k_kl_lock: 0xe6c20,
    },
    "12.00": {
        wk_expm1_builtin: 0x2585090,
        wk_JSFunction_m_function: 0x28,
        wk_POP_RDI_RET: 0x4902f,
        wk_POP_RSI_RET: 0x10e37,
        wk_POP_RDX_RET: 0xf7a,
        wk_POP_RCX_RET: 0x53c0b,
        wk_POP_RAX_RET: 0x22f53,
        wk_POP_R8_RET: 0x22f52,
        wk_POP_R9_RET: 0x60b6c1,
        wk_LEAVE_RET: 0x11823,
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x2b5cb,
        wk_PUSH_RDX_POP_RSP_RET: 0x2abb03a,
        wk_MOV_RDI_RSI_30_CALL: 0x295dcd8,
        wk_POP_RAX_MOV_RAX_JMP_18: 0x8e4873,
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0x285e10,
        wk_MOV_RDI_RAX_8_CALL_20: 0x6c7b0d,
        wk_MOV_RDX_RAX_18_CALL_10: 0xd37cca,
        pivot_view_sp: 0x38,
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk___imp___error: 0x3cbcc48,
        k__error: 0x299c0,
        wk___imp_pthread_create: 0x3cbdb80,
        k_pthread_create: 0x24e00,
        k_stubs: {
            3: 0x2c160, 4: 0x2b8c0, 5: 0x2b960, 6: 0x2d610,
            20: 0x2cb60, 23: 0x2b6e0, 24: 0x2d5d0, 25: 0x2b4c0,
            30: 0x2c9c0, 54: 0x2cfe0, 92: 0x2b640, 97: 0x2d040,
            98: 0x2b5e0, 104: 0x2d370, 105: 0x2b480, 106: 0x2d470,
            118: 0x2b2e0, 135: 0x2c270, 240: 0x2d4b0, 331: 0x2c6a0,
            432: 0x2b500, 466: 0x2cc60, 487: 0x2ba70, 488: 0x2bd00,
            538: 0x2b420, 539: 0x2b4e0, 544: 0x2bea0, 545: 0x2ca20,
            632: 0x2d080, 633: 0x2d830, 662: 0x2cca0, 663: 0x2c3d0,
            664: 0x2d730, 666: 0x2d530, 669: 0x2bde0,
        },
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x784798,
        k_sysent_661: 0x110a760,
        k_jmp_rsi: 0x47b31,
        k_kl_lock: 0xe6c20,
    },
    "12.50": {
        wk_expm1_builtin: 0x2585110,   // the anchor
        wk_JSFunction_m_function: 0x28,
        wk_POP_RDI_RET: 0x4902f,   // 5f c3
        wk_POP_RSI_RET: 0x10e37,   // 5e c3
        wk_POP_RDX_RET: 0x771ea,   // 5a c3
        wk_POP_RCX_RET: 0x5def9,   // 59 c3
        wk_POP_RAX_RET: 0x22f53,   // 58 c3
        wk_POP_R8_RET: 0x22f52,   // 47 58 c3
        wk_POP_R9_RET: 0x60b6c1,   // 47 59 c3
        wk_LEAVE_RET: 0x77caa,   // c9 c3
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x2b5cb,   // 48 89 07 c3
        wk_PUSH_RDX_POP_RSP_RET: 0x2abb0ba,   // 52 5c c3
        wk_MOV_RDI_RSI_30_CALL: 0x295dd58,   // 48 8b 7e 30 48 8b 07 ff 10
        wk_POP_RAX_MOV_RAX_JMP_18: 0x8e4873,   // 58 48 8b 07 ff 60 18
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0x285e10,   // 55 48 89 e5 48 8b 07 ff 50 10
        wk_MOV_RDI_RAX_8_CALL_20: 0x6c7b0d,   // 48 8b 78 08 48 8b 07 ff 50 20
        wk_MOV_RDX_RAX_18_CALL_10: 0xd37cca,   // 48 8b 50 38 48 8b 07 ff 50 10
        pivot_view_sp: 0x38,   // read off G4's displacement
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk___imp___error: 0x3cb4c48,
        k__error: 0xd9d0,
        wk___imp_pthread_create: 0x3cb5b80,
        k_pthread_create: 0x23d20,
        k_stubs: {
            3: 0x2c160, 4: 0x2b8c0, 5: 0x2b960, 6: 0x2d610,
            20: 0x2cb60, 23: 0x2b6e0, 24: 0x2d5d0, 25: 0x2b4c0,
            30: 0x2c9c0, 54: 0x2cfe0, 92: 0x2b640, 97: 0x2d040,
            98: 0x2b5e0, 104: 0x2d370, 105: 0x2b480, 106: 0x2d470,
            118: 0x2b2e0, 135: 0x2c270, 240: 0x2d4b0, 331: 0x2c6a0,
            432: 0x2b500, 466: 0x2cc60, 487: 0x2ba70, 488: 0x2bd00,
            538: 0x2b420, 539: 0x2b4e0, 544: 0x2bea0, 545: 0x2ca20,
            632: 0x2d080, 633: 0x2d830, 662: 0x2cca0, 663: 0x2c3d0,
            664: 0x2d730, 666: 0x2d530, 669: 0x2bde0,
        },
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x0, // not used by netctrl
        k_sysent_661: 0x110a760,
        k_jmp_rsi: 0x47b31,
        k_kl_lock: 0xe6c20, // kernel_base = kl_lock - this
    },
    "13.00": {
        wk_expm1_builtin: 0x2586880,
        wk_JSFunction_m_function: 0x28,
        wk_POP_RDI_RET: 0x5c480,
        wk_POP_RSI_RET: 0x6e45e,
        wk_POP_RDX_RET: 0x12c5ba,
        wk_POP_RCX_RET: 0x1bade,
        wk_POP_RAX_RET: 0x10504,
        wk_POP_R8_RET: 0x9b311,
        wk_POP_R9_RET: 0x1dcfb1,
        wk_LEAVE_RET: 0x182f7,
        wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x548b,
        wk_PUSH_RDX_POP_RSP_RET: 0x2abccaa,
        wk_MOV_RDI_RSI_30_CALL: 0x295f948,
        wk_POP_RAX_MOV_RAX_JMP_18: 0x1d989e3,
        wk_PUSH_RBP_MOV_RBP_RSP_10: 0x25bae0,
        wk_MOV_RDI_RAX_8_CALL_20: 0x4a0406,
        wk_MOV_RDX_RAX_18_CALL_10: 0x1ec3ada,
        pivot_view_sp: 0x38,
        wk_ArrayBuffer_m_impl: 0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk___imp___error: 0x3cb8cc8,
        k__error: 0x26420,
        wk___imp_pthread_create: 0x3cb9c00,
        k_pthread_create: 0x10110,
        k_stubs: {
            3: 0x2c170, 4: 0x2b8d0, 5: 0x2b970, 6: 0x2d620,
            20: 0x2cb70, 23: 0x2b6f0, 24: 0x2d5e0, 25: 0x2b4d0,
            30: 0x2c9d0, 54: 0x2cff0, 92: 0x2b650, 97: 0x2d050,
            98: 0x2b5f0, 104: 0x2d380, 105: 0x2b490, 106: 0x2d480,
            118: 0x2b2f0, 135: 0x2c280, 240: 0x2d4c0, 331: 0x2c6b0,
            432: 0x2b510, 466: 0x2cc70, 487: 0x2ba80, 488: 0x2bd10,
            538: 0x2b430, 539: 0x2b4f0, 544: 0x2beb0, 545: 0x2ca30,
            632: 0x2d090, 633: 0x2d840, 662: 0x2ccb0, 663: 0x2c3e0,
            664: 0x2d740, 666: 0x2d540, 669: 0x2bde0,
        },
        k_scan_stage1: 0x40000,
        k_scan_stage2: 0x60000,
        k_evf_cv: 0x0, // not used by netctrl
        k_sysent_661: 0x110a760,
        k_jmp_rsi: 0x47b31,
        k_kl_lock: 0xe6c20,
    },
};

/*
================================================================================
THE 13.0x / 13.5x OVERRIDES
================================================================================

These four share their WebKit + libkernel halves with 13.00 (13.02/13.04 are the
SAME modules; 13.50/13.52 load the 13.00 WebKit image but their own libkernel),
so they are Object.assign overrides of PS4["13.00"] in the same style as the
10.01 / 10.70 / 11.52 / 12.02 / 12.52 aliases above -- the identical fields are
INHERITED, not re-typed. Copy-pasting the 29 shared keys into each entry is how
the old offsets_extended.js drifted from this file in the first place.

Override ONLY the kernel half. Those RVAs are MEASURED per build (kdump5 +
tools/kderive.py against kernel_1302/1350/1352.elf), NOT derived, so they are
not interchangeable between builds the way the WebKit RVAs are:

  13.02  kernel_1302.elf -- .text moved from 13.00 (idt_rsvd 0x1c1d50)
  13.04  SAME KERNEL as 13.02 -- identical values on purpose, hence the
         deliberate duplicate; there is nothing to inherit from 13.02 because
         the two are siblings, and pointing 13.04 at 13.02 would make a future
         13.02 edit silently retarget 13.04
  13.50  kernel_1350.elf -- own build (idt_rsvd 0x1c1d60, __error 0x1a0f0)
  13.52  kernel_1352.elf -- own build, shares .data with 13.50 but not .text
         (idt_rsvd 0x1c1e00, jmp_rsi 0x4d6d0)

The k_stubs blocks below ARE identical across all four and are inherited where
they match 13.00; only k__error / k_pthread_create are re-stated on 13.50/13.52
because their libkernel is not 13.00's.
*/

PS4["13.02"] = Object.assign({}, PS4["13.00"], {
    k_idt_rsvd: 0x1c1d50,
    k_sysctl_handle_int: 0x3fa0a0,
    k_jmp_rsi: 0x47b31,
    k_kl_lock: 0xe6c20,
    k_evf_cv: 0x7849d8,
    k_sysent: 0x1102b70,
    k_sysent_661: 0x110a760,
    k_oid_kern_file: 0x1a2f8a0,
    k_oid_maxfilesperproc: 0x1a2f950,
    k_oid_maxprocperuid: 0x1a3ba88,
    k_oid_maxfiles: 0x1a2f9a8,
    k_arg1_maxfilesperproc: 0x22cc47c,
    k_arg1_maxprocperuid: 0x22cc478,
    k_arg1_maxfiles: 0x22cc474,
    /* ported from 1300.c, 18 sites +0x10; HW-PROVEN on 13.02 (KEXEC rc=0,
       pass=51). */
    kpatch: "1302.bin",
});

PS4["13.04"] = Object.assign({}, PS4["13.00"], {
    /* SAME KERNEL as 13.02 -- every value below is identical to it on purpose.
       See the header for why this is duplicated rather than chained. */
    k_idt_rsvd: 0x1c1d50,
    k_sysctl_handle_int: 0x3fa0a0,
    k_jmp_rsi: 0x47b31,
    k_kl_lock: 0xe6c20,
    k_evf_cv: 0x7849d8,
    k_sysent: 0x1102b70,
    k_sysent_661: 0x110a760,
    k_oid_kern_file: 0x1a2f8a0,
    k_oid_maxfilesperproc: 0x1a2f950,
    k_oid_maxprocperuid: 0x1a3ba88,
    k_oid_maxfiles: 0x1a2f9a8,
    k_arg1_maxfilesperproc: 0x22cc47c,
    k_arg1_maxprocperuid: 0x22cc478,
    k_arg1_maxfiles: 0x22cc474,
    /* reuses the one blob because the kernel is the same build. */
    kpatch: "1302.bin",
});

PS4["13.50"] = Object.assign({}, PS4["13.00"], {
    /* libkernel is 13.50's own, so these two differ from the 13.00 values that
       the other fields still inherit. */
    k__error: 0x1a0f0,
    k_pthread_create: 0x21790,

    /* KERNEL RVAs measured 2026-09-16 from kernel_1350.elf (kdump5
       tier0->rebase->tier1, kderive 16/16, adversarially verified 16/16 GO).
       13.50 is its own build (!= 13.52): .text moved from 13.00 by idt_rsvd
       +0x20, sysctl_handle_int +0x450, evf_cv +0x440; jmp_rsi/kl_lock/sysent
       carried; all .data identical. */
    k_idt_rsvd: 0x1c1d60,
    k_sysctl_handle_int: 0x3fa4e0,
    k_jmp_rsi: 0x47b31,
    k_kl_lock: 0xe6c20,
    k_evf_cv: 0x784e18,
    k_sysent: 0x1102b70,
    k_sysent_661: 0x110a760,
    k_oid_kern_file: 0x1a2f8a0,
    k_oid_maxfilesperproc: 0x1a2f950,
    k_oid_maxprocperuid: 0x1a3ba88,
    k_oid_maxfiles: 0x1a2f9a8,
    k_arg1_maxfilesperproc: 0x22cc47c,
    k_arg1_maxprocperuid: 0x22cc478,
    k_arg1_maxfiles: 0x22cc474,
    /* BUILT (anchored in kernel_1350.elf); kpatch.js 10/10, both neg controls
       refuse; UNTESTED on hw. */
    kpatch: "1350.bin",
});

PS4["13.52"] = Object.assign({}, PS4["13.00"], {
    k__error: 0x1a0f0,
    k_pthread_create: 0x21790,

    /* NOT the 13.50 kernel: this one is a different build. Every value differs
       from 13.50 except the .data block, which is shared. */
    k_idt_rsvd: 0x1c1e00,
    k_sysctl_handle_int: 0x3fa8e0,
    k_jmp_rsi: 0x4d6d0,
    k_kl_lock: 0xe6c60,
    k_evf_cv: 0x785228,
    k_sysent: 0x1102b70,
    k_sysent_661: 0x110a760,
    k_oid_kern_file: 0x1a2f8a0,
    k_oid_maxfilesperproc: 0x1a2f950,
    k_oid_maxprocperuid: 0x1a3ba88,
    k_oid_maxfiles: 0x1a2f9a8,
    k_arg1_maxfilesperproc: 0x22cc47c,
    k_arg1_maxprocperuid: 0x22cc478,
    k_arg1_maxfiles: 0x22cc474,
    kpatch: "1352.bin",
});

PS4["10.01"] = Object.assign({}, PS4["10.00"], {
    alias_of: "10.00",
    kpatch: "1000.bin",
});

PS4["10.70"] = Object.assign({}, PS4["10.50"], {
    alias_of: "10.50",
    kpatch: "1050.bin",
});

PS4["10.71"] = Object.assign({}, PS4["10.50"], {
    alias_of: "10.50",
    kpatch: "1050.bin",
});

PS4["11.52"] = Object.assign({}, PS4["11.50"], {
    alias_of: "11.50",
    kpatch: "1150.bin",
});

PS4["12.02"] = Object.assign({}, PS4["12.00"], {
    alias_of: "12.00",
    kpatch: "1200.bin",
});

PS4["12.52"] = Object.assign({}, PS4["12.50"], {
    alias_of: "12.50",
    kpatch: "1250.bin",
});


