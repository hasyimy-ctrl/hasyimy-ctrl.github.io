import { int64 } from "./int64.js";

export const DEFAULT_RPC_TIMEOUT_MS = 15000;

const THREAD_ATTR_MASK_SIZE = 0x10;
export const CPU_LEVEL_WHICH = 3;
export const CPU_WHICH_TID = 1;
export const RTP_LOOKUP = 0;
export const RTP_SET = 1;

const THREAD_ID_ALL = () => new int64(0xffffffff, 0xffffffff);

export function makeRpc(w, name, defaultTimeoutMs, onError) {
    const DEFAULT_TIMEOUT = defaultTimeoutMs === undefined ? 15000 : defaultTimeoutMs;
    let seq = 0;
    const pending = new Map();
    w.onmessage = function (e) {
        const d = e.data || {};
        const slot = pending.get(d.id);
        if (!slot) return;
        pending.delete(d.id);
        if (slot.timer) clearTimeout(slot.timer);
        if (d.type === "err") slot.reject(new Error(String(d.value)));
        else slot.resolve(d.value);
    };
    w.onerror = e => {
        if (onError) onError(name, (e && e.message) ? e.message : String(e));
    };

    return function call(fname, timeoutMs, ...args) {
        return new Promise(function (resolve, reject) {
            const id = seq++;
            const effective = timeoutMs === undefined ? DEFAULT_TIMEOUT : timeoutMs;
            const timer = effective > 0 ? setTimeout(function () {
                pending.delete(id);
                reject(new Error((name || "worker") + ": timeout waiting for " + fname));
            }, effective) : null;
            pending.set(id, { resolve, reject, timer });
            w.postMessage({ id: id, name: fname, args: args });
        });
    };
}

export function saveThreadAttrs(sc, sys, maskAddr, prioAddr, maskDv, prioDv) {
    const ID = THREAD_ID_ALL();
    const aff = sc(sys.cpuset_getaffinity, CPU_LEVEL_WHICH,
        CPU_WHICH_TID, ID, THREAD_ATTR_MASK_SIZE, maskAddr).i32;
    const prio = sc(sys.rtprio_thread, RTP_LOOKUP, 0, prioAddr).i32;
    if (aff !== 0 || prio !== 0) return null;
    return {
        mask: new int64(maskDv.getUint32(0, true), maskDv.getUint32(4, true)),
        prio: [prioDv.getUint16(0, true), prioDv.getUint16(2, true)],
    };
}

export function restoreMainThread(sc, sys, saved, maskAddr, prioAddr, maskDv, prioDv) {
    const ID = THREAD_ID_ALL();
    maskDv.setUint32(0, saved.mask.low, true);
    maskDv.setUint32(4, saved.mask.hi, true);
    const affinitySet = sc(sys.cpuset_setaffinity, CPU_LEVEL_WHICH,
        CPU_WHICH_TID, ID, THREAD_ATTR_MASK_SIZE, maskAddr).i32;
    prioDv.setUint16(0, saved.prio[0], true);
    prioDv.setUint16(2, saved.prio[1], true);
    const rtprioSet = sc(sys.rtprio_thread, RTP_SET, 0, prioAddr).i32;

    maskDv.setUint32(0, 0, true);
    maskDv.setUint32(4, 0, true);
    sc(sys.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, ID,
        THREAD_ATTR_MASK_SIZE, maskAddr);
    const backMask = new int64(maskDv.getUint32(0, true), maskDv.getUint32(4, true));
    prioDv.setUint16(0, 0xffff, true);
    prioDv.setUint16(2, 0xffff, true);
    sc(sys.rtprio_thread, RTP_LOOKUP, 0, prioAddr);
    const backPrio = [prioDv.getUint16(0, true), prioDv.getUint16(2, true)];
    const ok = backMask.low === saved.mask.low && backMask.hi === saved.mask.hi
        && backPrio[0] === saved.prio[0] && backPrio[1] === saved.prio[1];
    return {
        affinitySet, rtprioSet,
        mask: backMask, prio: backPrio,
        ok,
    };
}

export function pinMainThread(sc, sys, core, rtp, maskAddr, prioAddr, maskDv, prioDv) {
    const ID = THREAD_ID_ALL();
    maskDv.setUint32(0, 1 << core, true);
    prioDv.setUint16(0, rtp, true);   // rtprio.type = RTP_PRIO_REALTIME
    prioDv.setUint16(2, 0, true);     // rtprio.prio filled in by the caller
    const affinitySet = sc(sys.cpuset_setaffinity, CPU_LEVEL_WHICH,
        CPU_WHICH_TID, ID, THREAD_ATTR_MASK_SIZE, maskAddr).i32;
    const rtprioSet = sc(sys.rtprio_thread, RTP_SET, 0, prioAddr).i32;
    return { affinitySet, rtprioSet };
}
