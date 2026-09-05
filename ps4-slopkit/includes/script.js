// ===== DOM References =====
const consoleEl = document.getElementById('console');
const fwDisplay = document.getElementById('fwDisplay');
const jeilbrekBtn = document.getElementById('jeilbrek');
const checkbox = document.getElementById('autoJbInput');
const label = document.getElementById('autoJbLabel');
const kexForm = document.getElementById('kernel-options');
const netctrlRadio = document.getElementById('netctrl-exploit');
const lapseRadio = document.getElementById('lapse-exploit');
const statusText = document.getElementById('statusText');
const statusDot = document.getElementById('statusDot');

// ===== State =====
let timerId = null;
let exploitChain = localStorage.getItem('exploitChain') || 'lapse';
const storedAutoJb = localStorage.getItem('autoJb');
let autoJbValue = storedAutoJb !== null ? storedAutoJb === 'true' : true;

// ===== Logger =====
window.logToUI = function(tag, message) {
    if (!consoleEl) return;
    const ts = new Date().toLocaleTimeString();
    const prefix = tag ? `[${tag}] ` : '';
    consoleEl.textContent += `[${ts}] ${prefix}${message || ''}\n`;
    consoleEl.scrollTop = consoleEl.scrollHeight;
};

// ===== Status =====
window.setStatus = function(msg, cls = '') {
    if (statusText) statusText.textContent = msg;
    if (statusDot) {
        statusDot.className = 'status-dot';
        if (cls) statusDot.classList.add(cls);
    }
};

// ===== Getters =====
window.getExploitChain = function() { return exploitChain; };
window.getAutoJbValue = function() { return autoJbValue; };

// ===== Internal functions =====
function stopInterval() {
    if (timerId) { clearInterval(timerId); timerId = null; }
    if (label) label.textContent = 'Auto Jailbreak';
}

function jailbreakCountdown() {
    stopInterval();
    let countdown = 5;
    if (label) label.textContent = `Auto Jailbreaking in: ${countdown}`;
    timerId = setInterval(() => {
        countdown--;
        if (label) label.textContent = `Auto Jailbreaking in: ${countdown}`;
        if (countdown < 0) {
            clearInterval(timerId); timerId = null;
            if (label) label.textContent = 'Executing';
            window.setStatus('Auto executing...', 'running');
            if (jeilbrekBtn) jeilbrekBtn.disabled = true;
            if (typeof window.doJb === 'function') {
                window.doJb();
            } else {
                window.logToUI('ERROR', 'doJb not defined');
            }
        }
    }, 1000);
}

// ===== Cache handling =====
let lastCachePercent = -1;

function cacheProgress(e) {
    if (e.total > 0) {
        const Percent = Math.round((e.loaded / e.total) * 100);
        document.title = 'Caching: ' + Percent + '%';
        if (Percent !== lastCachePercent) {
            lastCachePercent = Percent;
        }
    } else {
        document.title = 'Caching...';
    }
}

function cacheDone() {
    displayCacheProgress();
}

function displayCacheProgress() {
    setTimeout(function() {
        document.title = '\u2713';
    }, 1000);
    setTimeout(function() {
        document.title = 'PS4 SlopKit Jailbreak';
    }, 3000);
}

function cacheError() {
    document.title = 'Cache update failed';
}

// ===== Setup UI (called by main.js) =====
window.setupUI = function() {
    // Firmware detection (global offsetsFor from main.js)
    if (fwDisplay && typeof window.offsetsFor === 'function') {
        const { key, off } = window.offsetsFor(navigator.userAgent);
        fwDisplay.textContent = key || 'UNSUPPORTED';
        if (!off) {
            jeilbrekBtn.disabled = true;
            window.logToUI('FW', 'Unsupported firmware.');
            window.setStatus('Unsupported', 'error');
        } else {
            window.logToUI('FW', 'Detected ' + key);
            window.setStatus('Ready', 'ok');
        }
    } else {
        window.logToUI('FW', 'offsetsFor not available');
    }

    // Exploit selection
    if (kexForm) {
        kexForm.addEventListener('change', function(e) {
            if (e.target.name === 'kernel') {
                localStorage.setItem('exploitChain', e.target.value);
                exploitChain = e.target.value;
                window.logToUI('UI', 'Exploit switched to: ' + exploitChain);
            }
        });
    }
    if (exploitChain === 'netctrl' && netctrlRadio) netctrlRadio.checked = true;
    else if (lapseRadio) lapseRadio.checked = true;

    // Auto-jailbreak checkbox
    if (checkbox) {
        checkbox.checked = autoJbValue;
        checkbox.addEventListener('change', function() {
            localStorage.setItem('autoJb', checkbox.checked);
            autoJbValue = checkbox.checked;
            if (checkbox.checked && !jeilbrekBtn.disabled) {
                jailbreakCountdown();
            } else {
                stopInterval();
            }
        });
    }

    // Jailbreak button
    if (jeilbrekBtn) {
        jeilbrekBtn.addEventListener('click', function() {
            jeilbrekBtn.disabled = true;
            stopInterval();
            window.setStatus('Manual start...', 'running');
            if (typeof window.doJb === 'function') {
                window.doJb();
            } else {
                window.logToUI('ERROR', 'doJb not defined');
            }
        });
    }

    // Cache events
    if (window.applicationCache) {
        const ac = window.applicationCache;
        ac.addEventListener('progress', cacheProgress, false);
        ac.addEventListener('cached', cacheDone, false);
        ac.addEventListener('updateready', function() {
            try { ac.swapCache(); } catch (_) {}
            cacheDone();
        }, false);
        ac.addEventListener('noupdate', function() {
            document.title = 'PS4 SlopKit Jailbreak';
        }, false);
        ac.addEventListener('error', cacheError, false);
    }

    // Auto-start
    if (autoJbValue && jeilbrekBtn && !jeilbrekBtn.disabled) {
        jailbreakCountdown();
    }

    window.logToUI('UI', 'Ready.');
    window.setStatus('Idle', '');
};