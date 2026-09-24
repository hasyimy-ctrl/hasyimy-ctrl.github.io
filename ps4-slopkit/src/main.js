
function load_script(src) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

/*
PS4 USER-AGENT PARSER.

The console reports its firmware as `PlayStation 4 <major>.<minor>`, where the
minor is HEX (`13.52` is 13 + 0x52). Two forms are seen in the wild:

    Mozilla/5.0 (PlayStation 4 13.52) AppleWebKit/605.1.15   <- space
    Mozilla/5.0 (PlayStation 4/13.52) AppleWebKit/605.1.15   <- slash

Three things this has to tolerate, each of which produced a "NOT PS4" badge on
a real console:

  CASE        a capitalised `(PLAYSTATION 4 13.52)` must still match. The old
              case-sensitive regex failed it outright, so the page announced
              NOT PS4 on a console that was plainly a PS4.
  NO VERSION  `(PlayStation 4)` with no firmware. Treated as a PS4 with an
              UNKNOWN version, NOT as a non-PS4 -- the caller needs to tell
              those two apart to colour the badge and word the log correctly.
  HEX MINOR   parseInt(minor, 16), and the key is zero-padded to two digits so
              `13.5` -> `13.05` and `13.50` -> `13.50` cannot collide.

Returns { key, off, isPs4, version }. `off` is null for a PS4 whose firmware is
not in the table (too old, too new, or not measured yet) -- that is an
UNSUPPORTED FIRMWARE, which is a different thing from NOT A PS4.
*/
function offsetsForIn(uaString, table) {
    const m = (uaString || '').match(/PlayStation\s+4[\/ ]?(\d+)\.(\d+)/i);
    const isPs4 = /PlayStation\s+4/i.test(uaString || '');
    if (!m) return { key: null, off: null, isPs4: isPs4, version: NaN };
    const key = m[1] + '.' + parseInt(m[2], 16).toString(16).padStart(2, '0');
    const off = (table && table[key]) || null;
    return {
        key,
        off: off && Object.keys(off).length ? off : null,
        isPs4: true,
        version: Number(key),
    };
}

/*
SINGLE PUBLISHER for the firmware resolver.

This used to be assigned in two places, and one of them wrote a bare
`offsetsFor = ...`. In a classic script that races with the window property: the
bare write creates or hits a global BINDING, and whoever loses the race leaves
`window.offsetsFor` not-a-function -- so stagePrimitive's offsetsFor() guard
fires with its misleading "offsetsFor is not installed" message even though
main.js did run. Both callers (runExploit and initializeUI) now go through this
one function, which only ever assigns the property.
*/
function publishOffsetsFor(PS4_TABLE) {
    window.offsetsFor = function (ua) { return offsetsForIn(ua, PS4_TABLE); };
    return window.offsetsFor;
}

async function runExploit(exploitName) {
    const log = (tag, message) => (window.logToUI || console.log)(tag, message);
    const status = (msg, cls) => (window.setStatus || function() {})(msg, cls);

    log('MAIN', 'Starting exploit: ' + exploitName);
    status('Initializing primitive...', 'running');

    let core, mem, offset, mod;
    try {
        core = await import('./core.js');
        mem = await import('./mem.js');
        offset = await import('./offset.js');
        mod = await import(`./${exploitName}.js`);
        const PS4_TABLE = offset.PS4;
        publishOffsetsFor(PS4_TABLE);
        if (core.establishPrimitive && mem.installWindowP && typeof mod.run === 'function') {
            log('LOAD', 'Core modules and exploit module loaded');
        } else {
            throw new Error('Missing required exports from modules');
        }
    } catch (err) {
        log('LOAD-FAILED', err.message);
        status('Failed to load core modules', 'error');
        throw err;
    }

    try {
        status(`Running ${exploitName}...`, 'running');
        const result = await mod.run({
            onLog: log,
            onStatus: status,
            verbose: true,
            applyPatch: true,
            signal: null
        });
        if (result && result.alreadyJailbroken) {
            log('MAIN', 'An existing jailbreak is already active.');
            status('Already jailbroken', 'error');
            window.alert('Already jailbroken.');
        } else if (result && result.success) {
            log('MAIN', 'Exploit completed successfully.');
            status('Done', 'ok');
        } else {
            log('MAIN', 'Exploit finished but success=false.');
            status('Partial success', 'warn');
        }
        if (result && result.rebootRequired && !result.success
            && !result.alreadyJailbroken) {
            window.alert('Reboot the console and try again.');
        }
        return result;
    } catch (err) {
        log('EXPLOIT-ERROR', err.message);
        status('Error: ' + err.message, 'error');
        throw err;
    }
}

window.doJb = async function() {
    const exploit = window.getExploitChain ? window.getExploitChain() : 'lapse';
    const btn = document.getElementById('jeilbrek');
    if (btn) btn.disabled = true;
    let alreadyJailbroken = false;
    try {
        const result = await runExploit(exploit);
        alreadyJailbroken = !!(result && result.alreadyJailbroken);
    } catch (e) {
        if (window.logToUI) window.logToUI('FATAL', e.message);
    } finally {
        if (btn) btn.disabled = alreadyJailbroken;
    }
};

let uiInitialized = false;

/*
setupUI() lives in includes/script.js, which the HTML loads AFTER this file
(index.html:170-171). So the ordering between the two is not something this
function may assume:

  - if we call initializeUI() synchronously, `await import('./offset.js')`
    yields, and whether window.setupUI exists when we resume depends on which
    of (module fetch completion, script.js execution) the engine services
    first. On the console it resolved to script.js NOT being ready yet, so the
    run fell into the else branch below and logged a startup error -- and on
    some loads the await did not resolve inside the window at all, leaving the
    page at "detecting..." with no error printed anywhere.

So WAIT for the function instead of assuming it is there: poll, bounded, then
give up with a message that says what is actually wrong. The alternative --
reordering the <script> tags -- would fix this page but not the race, since a
future lazy load or bundler would reintroduce it.
*/
async function whenSetupUIAvailable(timeoutMs) {
    const deadline = Date.now() + (timeoutMs || 3000);
    while (typeof window.setupUI !== 'function') {
        if (Date.now() > deadline) return false;
        await new Promise(function (r) { setTimeout(r, 16); });
    }
    return true;
}

async function initializeUI() {
    if (uiInitialized) return;
    uiInitialized = true;
    try {
        const ready = await whenSetupUIAvailable(3000);
        if (!ready) {
            uiInitialized = false;
            console.error('setupUI never became available - includes/script.js did'
                + ' not load or threw during evaluation');
            return;
        }
        const offset = await import('./offset.js');
        publishOffsetsFor(offset.PS4);
        window.setupUI();
    } catch (err) {
        uiInitialized = false;
        console.error('Unable to load firmware offsets', err);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeUI, { once: true });
} else {
    initializeUI();
}
