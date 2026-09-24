export function bufferAddress(p, offsets, arrayBuffer) {
    const cell = p.leakval(arrayBuffer);
    const impl = p.read8(cell.add32(offsets.wk_ArrayBuffer_m_impl));
    return p.read8(impl.add32(offsets.wk_ArrayBuffer_m_contents_m_data));
}

export function syscallResult(frameDv) {
    const lo = frameDv.getUint32(0, true);
    const hi = frameDv.getUint32(4, true);
    return { lo, hi, i32: lo | 0 };
}
