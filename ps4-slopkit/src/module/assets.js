export function kpatchPath(firmwareKey, offsets) {
    if (offsets && offsets.kpatch)
        return "src/kpatch/" + offsets.kpatch;
    return firmwareKey ? "src/kpatch/" + firmwareKey.replace(".", "") + ".bin" : null;
}

// Sites in the kpatch blob that are a `c6 81 xx eb` (mov [rcx+imm], 0xeb)
// instruction whose final byte can be forced back to the conditional jump.
export function kpatchJmpSites(kpatch) {
    const sites = [];
    if (!kpatch) return sites;
    for (let i = 0; i + 7 <= kpatch.length; ++i) {
        if (kpatch[i] !== 0xc6 || kpatch[i + 1] !== 0x81) continue;
        if (kpatch[i + 6] !== 0xeb) continue;
        sites.push(((kpatch[i + 2]) | (kpatch[i + 3] << 8)
            | (kpatch[i + 4] << 16) | (kpatch[i + 5] << 24)) >>> 0);
    }
    return sites;
}

export async function loadBinary(path) {
    if (!path) return null;
    const response = await fetch(path);
    if (!response.ok) return null;
    return new Uint8Array(await response.arrayBuffer());
}

/*
 * PAYLOAD SELECTION LIVES HERE, AND ONLY HERE.
 *
 * The UI writes the chosen payload into localStorage["payloadName"] and
 * exposes window.getPayloadName(). Nothing above this module needs to know
 * that plumbing: kernel scripts (netctrl.js etc.) just call loadPayload()
 * with no argument, and this module resolves the selection itself.
 *
 * To add/rename a payload, change KNOWN_PAYLOADS below -- no kernel script
 * or UI wiring needs to change.
 */
const KNOWN_PAYLOADS = ["goldhen.bin", "hen.bin", "payload.bin"];
const DEFAULT_PAYLOAD = "goldhen.bin";

/* Resolve the payload filename: prefer the UI's live selection, fall back to
   the persisted one, then the default. Anything unknown is rejected to the
   default so a stale/typo'd stored value cannot silently load nothing. */
export function selectedPayload() {
    let name = null;
    try {
        if (typeof window !== "undefined" && typeof window.getPayloadName === "function")
            name = window.getPayloadName();
    } catch (e) { }
    if (!name) {
        try { name = localStorage.getItem("payloadName"); } catch (e) { }
    }
    if (!name || KNOWN_PAYLOADS.indexOf(name) < 0) name = DEFAULT_PAYLOAD;
    return name;
}

// Loads src/<selected payload>; defaults to goldhen.bin. Throws so a missing/
// empty blob fails loudly instead of mapping nothing.
export async function loadPayload(name) {
    const file = name || selectedPayload();
    const url = new URL("../" + file, import.meta.url);
    /* NO `cache: "no-store"` here. This app is served under an AppCache
       manifest (index.html has manifest="cache.manifest"), and the payload
       blobs are listed in its CACHE: section. `no-store` tells the HTTP cache
       to skip caching, which on WebKit also prevents the application cache
       from satisfying the request -- so OFFLINE the fetch fell through to the
       network and failed, while ONLINE it worked. Falling back to a plain
       fetch lets AppCache serve src/goldhen.bin (or hen.bin) with no network,
       which is the whole point of the manifest. Freshness online is still
       handled by the manifest update, not by this option. */
    let response = null;
    try {
        response = await fetch(url.href);
    } catch (e) {
        // network error offline: retry once, some engines report a transient
        // failure when the AppCache entry was just promoted
        response = await fetch(url.href);
    }
    if (!response.ok)
        throw new Error("payload fetch failed: HTTP " + response.status
            + " at " + url.href);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length === 0)
        throw new Error("payload fetch returned an empty file: " + url.href);
    return bytes;
}
