export function validateGadgets(p, base, definitions, hexBytes, mark, options = {}) {
    const gadgets = {};
    let fatal = false;
    let gated = 0;
    for (const [name, rva, pattern, rebasable, required] of definitions) {
        const read1 = a => Number(p.read1(a));
        const readRun = offset => {
            const got = [];
            let ok = true;
            const rexTolerant = pattern[0] >= 0x40 && pattern[0] <= 0x4f;
            for (let i = 0; i < pattern.length; ++i) {
                if (pattern[i] === null) continue;
                const byte = read1(base.add32(offset + i));
                got.push(byte);
                if (byte === pattern[i]) continue;
                const rexOk = rexTolerant && i === 0 && (byte & 0xf0) === 0x40
                    && (byte & 0x09) === (pattern[i] & 0x09);
                if (!rexOk) ok = false;
            }
            return { got, ok };
        };
        let use = rva;
        let result = readRun(rva);
        if (!result.ok && rebasable) {
            const alternate = readRun(rva - 1);
            if (alternate.ok) {
                use = rva - 1;
                result = alternate;
                mark("GADGET-REBASED", name);
            }
        }
        if (result.ok) {
            gated++;
            gadgets[name] = base.add32(use);
        } else {
            if (required !== false) fatal = true;
            mark(options.mismatchTag || "GADGET-BYTES", name + " @0x" + use.toString(16)
                + " got " + hexBytes(result.got) + " want " + hexBytes(pattern)
                + "  MISMATCH");
        }
    }
    return { gadgets, fatal, gated, total: definitions.length };
}

export function discoverStubs(p, base, offsets, syscallTable, options = {}) {
    const wanted = Object.values(syscallTable);
    /* extra is a {number: name} map of ADDITIONAL syscalls to locate (things
       not in the chain's own table -- e.g. probing thr_suspend_ucontext).
       It contributes its KEYS (the syscall numbers) to the wanted set. The
       earlier `Object.values(extra)` pushed the NAMES instead, so those
       numbers were never searched for and the probe always reported
       "none" even when the stub existed. */
    const extra = options.extra || {};
    for (const numText in extra) wanted.push(+numText);
    const stubRva = new Map();
    let seeded = 0;
    let seedBad = 0;
    if (offsets.k_stubs) {
        for (const numberText in offsets.k_stubs) {
            const number = +numberText;
            const offset = offsets.k_stubs[numberText];
            const value = p.read8(base.add32(offset));
            if ((value.low & 0x00ffffff) !== 0xc0c748 || (value.hi >>> 24) !== 0x49) {
                seedBad++;
                continue;
            }
            const found = ((value.low >>> 24) | ((value.hi & 0x00ffffff) << 8)) >>> 0;
            if (found !== number) {
                seedBad++;
                continue;
            }
            stubRva.set(number, offset);
            seeded++;
        }
    }
    const needed = new Set(wanted.filter(number => !stubRva.has(number)));
    let scanned = 0;
    for (let offset = 0; offset < offsets.k_scan_stage1 && needed.size; offset += 16) {
        const value = p.read8(base.add32(offset));
        if ((value.low & 0x00ffffff) !== 0xc0c748 || (value.hi >>> 24) !== 0x49)
            continue;
        const number = ((value.low >>> 24) | ((value.hi & 0x00ffffff) << 8)) >>> 0;
        if (needed.has(number)) {
            stubRva.set(number, offset);
            needed.delete(number);
            scanned++;
        }
    }
    const stubAddr = new Map();
    const missing = [];
    const read1 = a => Number(p.read1(a));
    for (const name in syscallTable) {
        const number = syscallTable[name];
        if (!stubRva.has(number)) {
            missing.push(name);
            continue;
        }
        const address = base.add32(stubRva.get(number));
        const plain = read1(address.add32(12)) === 0x72
            && read1(address.add32(13)) === 0x01
            && read1(address.add32(14)) === 0xc3;
        if (options.requirePlain && !plain) {
            missing.push(name + "(wrapper)");
            continue;
        }
        stubAddr.set(number, address);
    }
    const extraStatus = [];
    for (const numText in extra) {
        const number = +numText;      // key is the syscall number
        const name = extra[numText];  // value is the label
        if (!stubRva.has(number)) {
            extraStatus.push(name + "=" + number + "=none");
            continue;
        }
        const address = base.add32(stubRva.get(number));
        stubAddr.set(number, address);
        const plain = read1(address.add32(12)) === 0x72
            && read1(address.add32(13)) === 0x01
            && read1(address.add32(14)) === 0xc3;
        extraStatus.push(name + (plain ? "=stub" : "=wrapper"));
    }
    return { stubRva, stubAddr, seeded, seedBad, scanned, total: wanted.length,
        missing, extraStatus };
}
