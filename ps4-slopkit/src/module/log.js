
const VERBOSE = new URLSearchParams(location.search).get("verbose") === "1";

const PROSE = [
    / -- /, /\.\s/, /;\s/,
    /,\s+(which|so|and that|because|since|as that)\s/,
    /,\s+\w+\s+of\s+which\s/,
    /\s+(because|rather than|instead of|so that|which is|which means|which the|so the|with the aim)\s/,
    /\s+so\s+[a-z]/,
    /\s+\([a-z][^)]{40,}\)/,
];

let outEl = null, stateEl = null;
let onLog = console.log, onStatus = () => {};
let postPrefix = "PS4", postRawDetail = false;
let badRe = null, warnRe = null, okRe = null;
let passCount = 0, failCount = 0;

export function initLog(options) {
    onLog = options.onLog || console.log;
    onStatus = options.onStatus || (() => {});
    postPrefix = options.postPrefix || "PS4";
    postRawDetail = !!options.postRawDetail;
    badRe = options.badRe || /FAIL|ERROR|THREW|MISMATCH|WRONG|MISSING|TIMEOUT|NOT-FOUND/i;
    warnRe = options.warnRe || /SKIP|GAP|WOULD-HAVE-WON|WARN/i;
    okRe = options.okRe || /OK|PROVEN|READY|pass|BASELINE/i;

    globalThis.mark = function(tag, detail) { onLog(tag, detail); };
    globalThis.state = function(msg, cls) { onStatus(msg, cls); };
    outEl = document.getElementById('console');
    stateEl = document.getElementById('statusText');
    if (outEl) outEl.innerHTML = "";
    lines.length = 0;
    globalThis.outEl = outEl;
    globalThis.stateEl = stateEl;

    globalThis.logLine = appendLine;
    globalThis.logToUI = function (tag, message) {
        if (!outEl) return;
        const ts = new Date().toLocaleTimeString();
        const prefix = tag ? `[${tag}] ` : '';
        appendLine(`[${ts}] ${prefix}${message == null ? '' : message}`);
        outEl.scrollTop = outEl.scrollHeight;
    };
}

export function checkCounts() { return { passCount, failCount }; }

const postQueue = [];
let postInFlight = false;

function drainPostQueue() {
    if (postInFlight || !postQueue.length) return;
    const body = postQueue.shift();
    postInFlight = true;
    let x = null;
    try {
        x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.onreadystatechange = function () {
            if (x.readyState === 4) { postInFlight = false; drainPostQueue(); }
        };
        x.onerror = function () { postInFlight = false; drainPostQueue(); };
        x.send(body);
    } catch (e) {
        postInFlight = false;
        drainPostQueue();
    }
}

export function post(tag, detail) {
    try {
        const x = new XMLHttpRequest();
        x.open("POST", "t", true);
        x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        x.send(postPrefix + "&tag=" + encodeURIComponent(tag)
             + "&detail=" + encodeURIComponent(String(detail == null ? "" : detail)));
    } catch (e) { }
}

function terse(s) {
    if (VERBOSE || s == null) return s;
    s = String(s);
    for (const re of PROSE) {
        const m = re.exec(s);
        if (m && m.index > 0) s = s.slice(0, m.index);
    }
    s = s.replace(/\s+$/, "");
    if (s.length > 140) s = s.slice(0, 140) + "...";
    return s;
}

const lines = [];

const CONSOLE_MAX = 1500;
function appendLine(l) {
    const c = badRe.test(l) ? "bad" : warnRe.test(l) ? "warn" : okRe.test(l) ? "ok" : "";
    const div = document.createElement("div");
    if (c) div.className = c;
    div.textContent = l;
    outEl.appendChild(div);
    while (outEl.childElementCount > CONSOLE_MAX) {
        const first = outEl.firstElementChild;
        if (!first) break;
        outEl.removeChild(first);
    }
}


const TRAIL_ON = new URLSearchParams(location.search).get("trail") !== "0";
const TRAIL_KEY = "ps4lab_trail";
const TRAIL_MAX = 400;
let trail = [];

const TRAIL_SAVE_MS = 250;
let trailLastSave = 0;

function trailSave() {
    try { localStorage.setItem(TRAIL_KEY, JSON.stringify(trail)); } catch (e) { }
    trailLastSave = Date.now();
}

export function trailFlush() { if (TRAIL_ON) trailSave(); }

function trailPush(tag, detail) {
    if (!TRAIL_ON) return;
    const at = Date.now();
    const parts = [String(at), String(tag)];
    if (detail != null && String(detail) !== '') parts.push(String(detail));
    const entry = parts.join('  ');
    trail.push(entry);
    if (trail.length > TRAIL_MAX) trail.splice(0, trail.length - TRAIL_MAX);
    try { console.log("[TRAIL] " + tag + (detail ? "  " + detail : "")); }
    catch (e) { }
    if (Date.now() - trailLastSave >= TRAIL_SAVE_MS) trailSave();
}

export function trailReset() {
    trail = [];
    trailLastSave = 0;
    try { localStorage.removeItem(TRAIL_KEY); } catch (e) { }
}

const TRAIL_CRITICAL = /PROOF-(FAIL|SUMMARY)|SAFE-TO-EXIT|REBOOT|PANIC|FATAL|DEAD|REFUSING/i;

export function mark(tag, detail) {
    const raw = detail;
    detail = terse(detail);
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    trailPush(tag, detail);
    if (TRAIL_ON && TRAIL_CRITICAL.test(tag)) trailSave();
    lines.push(line);
    appendLine(line);
    outEl.scrollTop = outEl.scrollHeight;
    post(tag, postRawDetail ? raw : detail);
}

export function trace(tag, detail) { if (VERBOSE) mark(tag, detail); else post(tag, detail); }

export function state(t, c) { stateEl.textContent = t; stateEl.className = c || ""; }

export function makePrimitiveProgress(maxAttempts) {
    const seenPhase = new Set();
    let lastAttempt = -1;
    let phases = 0;
    const budget = maxAttempts > 0 ? "" + maxAttempts : "?";

    return {
        onEvent: function (t, d, a) {
            const att = (a != null && a > 0) ? a : lastAttempt;
            const isRetry = /RETRY/i.test(t);

            state("primitive: attempt " + (att > 0 ? att : "?") + "/" + budget
                + " - " + t.toLowerCase() + "...", "warn");

            if (isRetry) {
                lastAttempt = att;
                mark("PRIMITIVE-RETRY", "attempt " + att + "/" + budget
                    + "" + (d ? "  " + d : ""));
                return;
            }

            const isMissOrEnd = /MISS|GIVE-UP|GIVEUP|THREW|CEILING|CANCEL/i.test(t);
            if (isMissOrEnd) {
                seenPhase.add(t);
                mark("PRIMITIVE-MISS", "[" + (att > 0 ? att : "?") + "] " + t
                    + (d ? "  " + d : ""));
                return;
            }

            if (!seenPhase.has(t) && phases < 40) {
                seenPhase.add(t);
                phases++;
                mark("PRIMITIVE-PHASE", "[" + (att > 0 ? att : "?") + "] " + t
                    + (d ? "  " + d : ""));
                return;
            }

            trace(t, (a != null ? "[" + a + "] " : "") + (d || ""));
        },
        done: function (cls) {
            state(cls === "ok" ? "primitive established"
                : "primitive failed", cls === "ok" ? "ok" : "error");
        }
    };
}

export function check(name, ok, detail) {
    if (ok) { passCount++; mark("PROOF-OK", name + (detail ? "  " + detail : "")); }
    else { failCount++; mark("PROOF-FAIL", name + (detail ? "  " + detail : "")); }
    return ok;
}

export function hx(n) { return "0x" + (n >>> 0).toString(16); }

export function hexByte(b) { return (b < 16 ? "0" : "") + (b & 0xff).toString(16); }

export function hexBytes(a) {
    let s = "";
    for (let i = 0; i < a.length; ++i) s += (i ? " " : "") + hexByte(a[i]);
    return s;
}

export async function runChain(options, runOriginal) {
    initLog(options);
    const result = await runOriginal(options || {});
    return result || { success: false, reason: "exploit did not establish success" };
}
