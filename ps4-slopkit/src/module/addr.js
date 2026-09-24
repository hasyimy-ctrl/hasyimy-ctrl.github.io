// Address predicates shared by lapse.js and netctrl.js.
// Bounds differ on purpose -- do NOT unify:
//   isKernelPtr  hi >= 0xffff0000 (any kernel address)
//   isPtrish     hi 1..0xffff (JS-heap cell, 8-byte aligned)
//   isImageAddr  hi == 0xffff (kernel image only)

export function isKernelPtr(v) {
    return !!v && (v.hi >>> 0) >= 0xffff0000;
}

export function isKernelPtrAligned(v) {
    return isKernelPtr(v) && ((v.low >>> 0) & 7) === 0;
}

export function isPtrish(v) {
    return !!v && v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0;
}

export function isImageAddr(v) {
    return !!v && (v.hi >>> 0) === 0xffffffff;
}

export function isPlausibleBase(v) {
    return !!v && v.hi > 0 && (v.low & 0x3fff) === 0;
}

export function sameI64(a, b) {
    return !!a && !!b
        && (a.low >>> 0) === (b.low >>> 0)
        && (a.hi >>> 0) === (b.hi >>> 0);
}
