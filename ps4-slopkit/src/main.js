
function load_script(src) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

function offsetsForIn(uaString, table) {
    const m = (uaString || '').match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
    if (!m) return { key: null, off: null };
    const key = m[1] + '.' + parseInt(m[2], 16).toString(16).padStart(2, '0');
    const off = (table && table[key]) || null;
    return { key, off: off && Object.keys(off).length ? off : null };
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
async function initializeUI() {
    if (uiInitialized) return;
    uiInitialized = true;
    try {
        const offset = await import('./offset.js');
        const PS4_TABLE = offset.PS4;
        publishOffsetsFor(PS4_TABLE);
        if (typeof window.setupUI === 'function') {
            window.setupUI();
        } else {
            console.error('setupUI not defined - make sure includes/script.js is loaded');
        }
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
