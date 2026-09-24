const consoleEl = document.getElementById('console');
const fwDisplay = document.getElementById('fwDisplay');
const jeilbrekBtn = document.getElementById('jeilbrek');
const checkbox = document.getElementById('autoJbInput');
const label = document.getElementById('autoJbLabel');
const kexForm = document.getElementById('kernel-options');
const netctrlRadio = document.getElementById('netctrl-exploit');
const lapseRadio = document.getElementById('lapse-exploit');
const payloadPicker = document.getElementById('payload-picker');
const payloadToggle = document.getElementById('payload-toggle');
const payloadMenu = document.getElementById('payload-menu');
const payloadCurrent = document.getElementById('payload-current');
const statusText = document.getElementById('statusText');
const statusDot = document.getElementById('statusDot');
const settingsBtn = document.getElementById('settingsBtn');
const settingsPanel = document.getElementById('settingsPanel');
const bigConsoleInput = document.getElementById('bigConsoleInput');
const consoleWrapInput = document.getElementById('consoleWrapInput');
const legacyInput = document.getElementById('legacyInput');
const legacyToggle = document.getElementById('legacyToggle');
const legacyToggleInput = document.getElementById('legacyToggleInput');

let timerId = null;
let exploitChain = localStorage.getItem('exploitChain') || 'lapse';
let payloadName = localStorage.getItem('payloadName') || 'goldhen.bin';
const storedAutoJb = localStorage.getItem('autoJb');
let autoJbValue = storedAutoJb !== null ? storedAutoJb === 'true' : false;
let bigConsole = localStorage.getItem('bigConsole') === 'true';
let consoleWrap = localStorage.getItem('consoleWrap') !== 'false';
let legacyMode = localStorage.getItem('legacyMode') === 'true';
let jbStarted = false;
function quietLogActive() { return legacyMode && !jbStarted; }
let regularLogSnapshot = null;

function applyConsolePrefs() {
    if (!consoleEl) return;
    if (document.documentElement)
        document.documentElement.classList.toggle('big-console', bigConsole);
    consoleEl.classList.toggle('big', bigConsole);
    consoleEl.classList.toggle('nowrap', !consoleWrap);
    const containerEl = consoleEl.parentElement;
    if (containerEl) containerEl.classList.toggle('big', bigConsole);
}

function applyLegacyPref() {
    if (document.body) document.body.classList.toggle('legacy', legacyMode);
    if (legacyInput) legacyInput.checked = legacyMode;
    if (legacyToggleInput) legacyToggleInput.checked = legacyMode;
    if (legacyToggle) legacyToggle.hidden = !legacyMode;
    if (document.documentElement)
        document.documentElement.classList.toggle('legacy', legacyMode);
    setRunningView(legacyMode && jailbreakStarted);
    if (!consoleEl) return;
    if (legacyMode) {
        if (!jbStarted && regularLogSnapshot === null)
            regularLogSnapshot = consoleEl.innerHTML;
        consoleEl.innerHTML = '';
    } else if (!jbStarted) {
        if (regularLogSnapshot !== null) {
            consoleEl.innerHTML = regularLogSnapshot;
        } else if (consoleEl.childElementCount === 0) {
            const d = document.createElement('div');
            d.textContent = '[System] Ready';
            consoleEl.appendChild(d);
        }
        consoleEl.scrollTop = consoleEl.scrollHeight;
    }
}

function setSettingsOpen(open) {
    if (!settingsPanel || !settingsBtn) return;
    settingsPanel.hidden = !open;
    settingsBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
}

window.addEventListener('resize', applyConsolePrefs);

function setupSettings() {
    if (bigConsoleInput) bigConsoleInput.checked = bigConsole;
    if (consoleWrapInput) consoleWrapInput.checked = consoleWrap;
    if (legacyInput) legacyInput.checked = legacyMode;
    applyConsolePrefs();
    applyLegacyPref();
    setupRunningViewDismiss();

    if (settingsBtn) {
        settingsBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            setSettingsOpen(settingsPanel.hidden);
        });
    }
    if (settingsPanel) {
        settingsPanel.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }
    document.addEventListener('click', function() {
        if (settingsPanel && !settingsPanel.hidden) setSettingsOpen(false);
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && settingsPanel && !settingsPanel.hidden) {
            setSettingsOpen(false);
        }
    });

    if (bigConsoleInput) {
        bigConsoleInput.addEventListener('change', function() {
            bigConsole = bigConsoleInput.checked;
            applyConsolePrefs();
            try { localStorage.setItem('bigConsole', String(bigConsole)); } catch (e) { }
        });
    }
    if (consoleWrapInput) {
        consoleWrapInput.addEventListener('change', function() {
            consoleWrap = consoleWrapInput.checked;
            applyConsolePrefs();
            try { localStorage.setItem('consoleWrap', String(consoleWrap)); } catch (e) { }
        });
    }
    if (legacyInput) {
        legacyInput.addEventListener('change', function() {
            legacyMode = legacyInput.checked;
            applyLegacyPref();
            try { localStorage.setItem('legacyMode', String(legacyMode)); } catch (e) { }
        });
    }
    if (legacyToggleInput) {
        legacyToggleInput.addEventListener('change', function() {
            legacyMode = legacyToggleInput.checked;
            applyLegacyPref();
            try { localStorage.setItem('legacyMode', String(legacyMode)); } catch (e) { }
        });
    }
}

window.logToUI = function(tag, message) {
    if (!consoleEl) return;
    if (quietLogActive()) return;
    const ts = new Date().toLocaleTimeString();
    const prefix = tag ? `[${tag}] ` : '';
    const line = document.createElement('div');
    line.textContent = `[${ts}] ${prefix}${message || ''}`;
    consoleEl.appendChild(line);
    consoleEl.scrollTop = consoleEl.scrollHeight;
};

let jailbreakStarted = false;

function setRunningView(on) {
    if (!document.body) return;
    if (!legacyMode) on = false;
    document.body.classList.toggle('legacy-running', !!on);
}

function setupRunningViewDismiss() {
    if (!consoleEl) return;
    consoleEl.addEventListener('click', function() {
        if (legacyMode && document.body.classList.contains('legacy-running')) {
            setRunningView(false);
        }
    });
}

window.setStatus = function(msg, cls = '') {
    if (statusText) statusText.textContent = msg;
    if (statusDot) {
        statusDot.className = 'status-dot';
        if (cls) statusDot.classList.add(cls);
    }

    if (cls === 'running') {
        jailbreakStarted = true;
        jbStarted = true;
        setRunningView(true);
    }
    if (jailbreakStarted) {
        const m = String(msg || '');
        if (/^already jailbroken/i.test(m)) document.title = '\u2713 Already jailbroken';
        else if (/^done$/i.test(m)) document.title = '\u2713 Jailbroken';
        else if (/^partial success/i.test(m)) document.title = 'Jailbreak partial';
        else if (cls === 'ok') document.title = '\u2713 Jailbroken';
        else if (cls === 'warn') document.title = 'Jailbreak partial';
        else if (cls === 'error') document.title = 'Jailbreak failed';
        else if (cls === 'running') document.title = 'Jailbreaking...';
    }
};

window.getExploitChain = function() { return exploitChain; };
window.getAutoJbValue = function() { return autoJbValue; };
window.getPayloadName = function() { return payloadName || 'goldhen.bin'; };

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
            jbStarted = true;
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

let lastCachePercent = -1;

function cacheProgress(e) {
    if (jailbreakStarted) return;
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
        if (jailbreakStarted) return;
        document.title = '\u2713 Cached';
    }, 1000);
    setTimeout(function() {
        if (jailbreakStarted) return;
        document.title = 'PS4 SlopKit Exploit';
    }, 3000);
}

window.setupUI = function() {
    setupSettings();

    if (legacyMode && consoleEl) consoleEl.innerHTML = '';

    let forceNetctrl = false;
    let firmwareSupported = false;
    if (fwDisplay && typeof window.offsetsFor === 'function') {
        const { key, off } = window.offsetsFor(navigator.userAgent);
        const onPs4 = key !== null;
        fwDisplay.textContent = key || (onPs4 ? 'UNSUPPORTED' : 'NOT PS4');
        fwDisplay.classList.remove('placeholder-text');
        const firmwareVersion = key ? Number(key) : NaN;
        const unsupportedFirmware = !off;
        firmwareSupported = !unsupportedFirmware;
        fwDisplay.classList.toggle('bad', !firmwareSupported);
        forceNetctrl = !unsupportedFirmware
            && Number.isFinite(firmwareVersion) && firmwareVersion >= 12.50;
        if (unsupportedFirmware) {
            [netctrlRadio, lapseRadio].forEach(function(radio) {
                if (radio) {
                    radio.disabled = true;
                    if (radio.parentNode) {
                        radio.parentNode.classList.add('firmware-unsupported');
                    }
                }
            });
        }
        if (forceNetctrl) {
            exploitChain = 'netctrl';
            localStorage.setItem('exploitChain', exploitChain);
            if (netctrlRadio) netctrlRadio.checked = true;
            if (lapseRadio) {
                lapseRadio.checked = false;
                lapseRadio.disabled = true;
                if (lapseRadio.parentNode) {
                    lapseRadio.parentNode.classList.add('lapse-disabled');
                }
            }
        }
        if (!off) {
            jeilbrekBtn.disabled = true;
            if (!onPs4) {
                window.logToUI('FW', 'The user required to be on PS4.');
            } else {
                window.logToUI('FW', 'Cry harder you etawen nga.');
            }
            window.setStatus('Unsupported', 'error');
        } else {
            window.logToUI('FW', 'Detected ' + key);
            window.setStatus('Ready', 'ok');
        }
    } else {
        [netctrlRadio, lapseRadio].forEach(function(radio) {
            if (radio) {
                radio.disabled = true;
                if (radio.parentNode) {
                    radio.parentNode.classList.add('firmware-unsupported');
                }
            }
        });
        if (jeilbrekBtn) jeilbrekBtn.disabled = true;
        window.logToUI('FW', 'offsetsFor not available');
        window.setStatus('Unsupported', 'error');
        if (fwDisplay) fwDisplay.classList.remove('placeholder-text');
    }

    if (kexForm) {
        kexForm.addEventListener('change', function(e) {
            if (e.target.name === 'kernel') {
                if (forceNetctrl && e.target.value === 'lapse') {
                    if (netctrlRadio) netctrlRadio.checked = true;
                    return;
                }
                localStorage.setItem('exploitChain', e.target.value);
                exploitChain = e.target.value;
                window.logToUI('UI', 'Exploit switched to: ' + exploitChain);
            }
        });

        kexForm.addEventListener('click', function(e) {
            if (!forceNetctrl) return;
            if (!e.target.closest || !e.target.closest('.radio-option')) return;
            if (!lapseRadio) return;
            if (!e.target.closest('.radio-option').contains(lapseRadio)) return;

            if (netctrlRadio) netctrlRadio.checked = true;
            exploitChain = 'netctrl';
            window.logToUI('FW', 'Firmware 12.50+ requires Netcontrol.');
        });
    }
    if (forceNetctrl) exploitChain = 'netctrl';
    if (exploitChain === 'netctrl' && netctrlRadio) netctrlRadio.checked = true;
    else if (lapseRadio) lapseRadio.checked = true;

    if (payloadName !== 'goldhen.bin' && payloadName !== 'hen.bin'
        && payloadName !== 'payload.bin')
        payloadName = 'goldhen.bin';

    function payloadLabel(value) {
        if (value === 'hen.bin') return 'HEN';
        if (value === 'payload.bin') return 'Custom';
        return 'GoldHEN';
    }
    function paintPayload() {
        if (payloadCurrent) payloadCurrent.textContent = payloadLabel(payloadName);
        if (payloadMenu) {
            var items = payloadMenu.querySelectorAll('.payload-item');
            for (var i = 0; i < items.length; ++i) {
                items[i].classList.toggle('selected',
                    items[i].getAttribute('data-value') === payloadName);
            }
        }
    }
    function setPayloadMenuOpen(open) {
        if (!payloadMenu || !payloadToggle) return;
        payloadMenu.hidden = !open;
        payloadToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    /* The Custom option is ALWAYS present in the menu (static in index.html).
       We still probe src/payload.bin once so we know whether choosing it can
       actually work: the click handler below refuses to select it when the
       file is absent, and tells the user what to add. */
    var customAvailable = false;
    (function probeCustom() {
        fetch('src/payload.bin', { method: 'HEAD', cache: 'no-store' })
            .then(function(r) {
                customAvailable = !!(r && r.ok);
                /* If Custom was the stored selection but the file is gone,
                   fall back so the UI never shows a payload that cannot load,
                   and say why. */
                if (payloadName === 'payload.bin' && !customAvailable) {
                    payloadName = 'goldhen.bin';
                    try { localStorage.setItem('payloadName', payloadName); }
                    catch (err) { }
                    window.logToUI('UI', 'Need a added custom payload.bin at '
                        + 'src/payload.bin and update the cache.manifest');
                    paintPayload();
                }
            })
            .catch(function() { });
    })();

    paintPayload();
    if (payloadToggle) {
        payloadToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            setPayloadMenuOpen(payloadMenu.hidden);
        });
    }
    if (payloadMenu) {
        payloadMenu.addEventListener('click', function(e) { e.stopPropagation(); });
        payloadMenu.addEventListener('click', function(e) {
            var btn = e.target && e.target.closest
                ? e.target.closest('.payload-item') : null;
            if (!btn) return;
            var v = btn.getAttribute('data-value');
            if (v !== 'goldhen.bin' && v !== 'hen.bin' && v !== 'payload.bin')
                return;
            if (v === 'payload.bin' && !customAvailable) {
                /* Custom is always offered, but it is only usable once the
                   user actually drops payload.bin in. Refuse the selection
                   and tell them exactly what to do. */
                window.logToUI('UI', 'Need a added custom payload.bin at '
                    + 'src/payload.bin and update the cache.manifest');
                setPayloadMenuOpen(false);
                return;
            }
            payloadName = v;
            paintPayload();
            setPayloadMenuOpen(false);
            try { localStorage.setItem('payloadName', payloadName); } catch (err) { }
            window.logToUI('UI', 'HEN payload: ' + payloadLabel(payloadName));
        });
    }
    document.addEventListener('click', function() {
        if (payloadMenu && !payloadMenu.hidden) setPayloadMenuOpen(false);
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && payloadMenu && !payloadMenu.hidden)
            setPayloadMenuOpen(false);
    });

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

    if (jeilbrekBtn) {
        jeilbrekBtn.addEventListener('click', function() {
            jeilbrekBtn.disabled = true;
            stopInterval();
            jbStarted = true;
            window.setStatus('Manual start...', 'running');
            if (typeof window.doJb === 'function') {
                window.doJb();
            } else {
                window.logToUI('ERROR', 'doJb not defined');
            }
        });
    }

    if (window.applicationCache) {
        const ac = window.applicationCache;
        ac.addEventListener('progress', cacheProgress, false);
        ac.addEventListener('cached', cacheDone, false);
        ac.addEventListener('updateready', function() {
            try { ac.swapCache(); } catch (_) {}
            cacheDone();
        }, false);
        ac.addEventListener('noupdate', function() {
            if (jailbreakStarted) return;
            document.title = 'PS4 SlopKit Exploit';
        }, false);
    }

    if (autoJbValue && jeilbrekBtn && !jeilbrekBtn.disabled) {
        jailbreakCountdown();
    }

    if (firmwareSupported) {
        window.logToUI('UI', 'Ready.');
        window.setStatus('Idle', '');
    }
};
