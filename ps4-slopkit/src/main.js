// /src/main.js – Plain Script (no top-level imports)
// Uses dynamic import() to load dependencies, and globals from includes/script.js

// ===== Helper: load a script dynamically (if needed) =====
function load_script(src) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

// ===== Main exploit runner =====
async function runExploit(exploitName) {
    // Use globals from includes/script.js
    const log = window.logToUI || console.log;
    const status = window.setStatus || function() {};

    log('MAIN', 'Starting exploit: ' + exploitName);
    status('Initializing primitive...', 'running');

    // 1. Dynamically import core.js, mem.js, offsets.js and the exploit module
    let core, mem, offset, mod;
    try {
        core = await import('./core.js');
        mem = await import('./mem.js');
        offset = await import('./offsets.js?v=4');
        mod = await import(`./${exploitName}.js?v=4`);
        // Expose offsetsFor globally for firmware detection
        window.offsetsFor = offset.offsetsFor;
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

    // The selected exploit module owns primitive setup and teardown.
    try {
        status(`Running ${exploitName}...`, 'running');
        const result = await mod.run({
            onLog: log,
            onStatus: status,
            verbose: true,
            applyPatch: true,
            signal: null
        });
        if (result && result.success) {
            log('MAIN', 'Exploit completed successfully.');
            status('Done', 'ok');
        } else {
            log('MAIN', 'Exploit finished but success=false.');
            status('Partial success', 'warn');
        }
        if (result && result.rebootRequired && !result.success) {
            window.alert('Reboot the console and try again.');
        }
        return result;
    } catch (err) {
        log('EXPLOIT-ERROR', err.message);
        status('Error: ' + err.message, 'error');
        throw err;
    }
}

// ===== Global doJb function for the UI =====
window.doJb = async function() {
    const exploit = window.getExploitChain ? window.getExploitChain() : 'lapse';
    const btn = document.getElementById('jeilbrek');
    if (btn) btn.disabled = true;
    try {
        await runExploit(exploit);
    } catch (e) {
        if (window.logToUI) window.logToUI('FATAL', e.message);
    } finally {
        if (btn) btn.disabled = false;
    }
};

// ===== Set up UI after DOM is ready =====
let uiInitialized = false;
async function initializeUI() {
    if (uiInitialized) return;
    uiInitialized = true;
    try {
        const offset = await import('./offsets.js?v=4');
        window.offsetsFor = offset.offsetsFor;
        if (typeof window.setupUI === 'function') {
            window.setupUI();
        } else {
            console.error('setupUI not defined – make sure includes/script.js is loaded');
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

console.log('Ready for the code execution.');