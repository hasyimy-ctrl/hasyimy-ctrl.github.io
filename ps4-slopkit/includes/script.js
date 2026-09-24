const consoleEl = document.getElementById('console');
const fwDisplay = document.getElementById('fwDisplay');
const jeilbrekBtn = document.getElementById('jeilbrek');
const checkbox = document.getElementById('autoJbInput');
const label = document.getElementById('autoJbLabel');
const kexForm = document.getElementById('kernel-options');
const netctrlRadio = document.getElementById('netctrl-exploit');
const lapseRadio = document.getElementById('lapse-exploit');
const relapseRadio = document.getElementById('relapse-exploit');
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

        /*
        ============================================================
        FIRMWARE -> CHAIN ELIGIBILITY
        ============================================================

        THREE independent chains, each with its OWN kernel bug and its OWN
        firmware range. They are not variants of one another:

          lapse.js    10.00 - 12.02   vfs_aio2.c  _aio_multi_delete
                                      (src/kernel_bug/lapse_bug.c) -- a double-free
                                      won by a suspend/resume race.

          netctrl.js  12.50+          bnet_netcontrol.c  netcontrol
                                      (src/kernel_bug/netctrl_bug.c) -- a
                                      netcontrol(SET/CLEAR_QUEUE) double-free.

          relapse.js  13.02, 13.04, 13.50, 13.52
                                      vfs_aio2.c  _aio_multi_wait
                                      (src/kernel_bug/sys_aio_multi_wait.c) -- a
                                      concurrency bug in the waiter list. A DIFFERENT
                                      bug from lapse's, not a port of it.

        lapseOk / netctrlOk / relapseOk are each a property test on the firmware's
        own offset block, never a firmware-string allow list, so a newly-measured
        firmware gains its chain the moment its keys land in src/offset.js.

        NEITHER the marks NOR the ranges disable a radio. A `disabled` input
        swallows the click outright -- no change event, no handler, no explanation --
        and the user is left with a dead grey option and no idea why. The radios stay
        ENABLED; the gate is enforced in radioBlocked() below, which refuses the
        selection AND says why. An option that refuses and explains beats one that
        silently does nothing.
        */
        let relapseOk = false;
        let netctrlOk = false;
        let lapseOk = false;
        let firmwareSupported = false;
        /* Why the firmware is unsupported, when it is -- set below and read by
           radioBlocked() so a click explains the same thing the badge shows. */
        let fwUnsupportedReason = '';
        /*
        ALL THREE INDICATORS GO RED WHEN NOTHING CAN RUN.

        The badge and the radio dots have to agree with each other and with the
        status line, or the page contradicts itself: a red UNSUPPORTED badge next
        to three green radio dots reads as "pick one", when in fact none of them
        can run. So the two failure cases below both mark every option.

        Note the two cases are NOT the same thing and must not share wording:
          NOT A PS4          the UA is not a PlayStation at all
          UNSUPPORTED FW     a PS4, but its firmware is not in the table
                             (too old, or newer than the highest entry)
        */
        if (fwDisplay && typeof window.offsetsFor === 'function') {
            const r = window.offsetsFor(navigator.userAgent);
            const key = r.key, off = r.off;
            /* offsetsForIn reports isPs4 directly; fall back to "the UA has a
               version in it" for an older publisher that does not set it. */
            const onPs4 = (r.isPs4 !== undefined) ? r.isPs4 : (key !== null);
            fwDisplay.textContent = key || (onPs4 ? 'UNSUPPORTED' : 'NOT PS4');
            fwDisplay.classList.remove('placeholder-text');
            const firmwareVersion = Number.isFinite(r.version)
                ? r.version : (key ? Number(key) : NaN);
            const unsupportedFirmware = !off;
            firmwareSupported = !unsupportedFirmware;
            /* RED for anything that cannot run -- both cases. This is the line
               that makes a green UNSUPPORTED/NOT PS4 impossible. */
            fwDisplay.classList.toggle('bad', !firmwareSupported);

            if (unsupportedFirmware) {
                /* Every kernel indicator red, so the form agrees with the badge
                   and with the disabled Jelbrek button. */
                [netctrlRadio, lapseRadio, relapseRadio].forEach(function(radio) {
                    if (radio && radio.parentNode)
                        radio.parentNode.classList.add('firmware-unsupported');
                });
                jeilbrekBtn.disabled = true;
                if (!onPs4) {
                    fwUnsupportedReason = 'This page only works on a PS4.';
                    window.logToUI('FW', 'The user required to be on PS4.');
                } else if (key) {
                    fwUnsupportedReason = 'Firmware ' + key
                        + ' is not supported yet (no offsets).';
                    window.logToUI('FW', fwUnsupportedReason);
                } else {
                    fwUnsupportedReason = 'Could not read the firmware version'
                        + ' from this console.';
                    window.logToUI('FW', 'Cry harder you etawen nga.');
                }
                window.setStatus('Unsupported', 'error');
            } else {
                window.logToUI('FW', 'Detected ' + key);
                window.setStatus('Ready', 'ok');

                /* Relapse's kern.file oracle needs the anchor + oid table. */
                relapseOk = off.k_idt_rsvd !== undefined
                    && off.k_oid_kern_file !== undefined
                    && off.k_oid_maxfilesperproc !== undefined;
                /* Netcontrol carries 12.50 and above. */
                netctrlOk = Number.isFinite(firmwareVersion)
                    && firmwareVersion >= 12.50;
                /* Lapse is 10.00 - 12.02. */
                lapseOk = Number.isFinite(firmwareVersion)
                    && firmwareVersion >= 10.00 && firmwareVersion <= 12.02;

                /* Red dot wherever the chain cannot run here. */
                [netctrlRadio, lapseRadio, relapseRadio].forEach(function(radio) {
                    if (radio && radio.parentNode)
                        radio.parentNode.classList.remove('firmware-unsupported');
                });
                function markBlocked(radio, blocked) {
                    if (!radio || !radio.parentNode) return;
                    radio.parentNode.classList.toggle('lapse-disabled', !!blocked);
                }
                markBlocked(relapseRadio, !relapseOk);
                markBlocked(netctrlRadio, !netctrlOk);
                markBlocked(lapseRadio, !lapseOk);

                /* Default selection: whichever chain this firmware runs. */
                const def = relapseOk ? 'relapse' : (netctrlOk ? 'netctrl'
                    : (lapseOk ? 'lapse' : null));
                if (def) {
                    exploitChain = def;
                    localStorage.setItem('exploitChain', exploitChain);
                    if (def === 'relapse' && relapseRadio) relapseRadio.checked = true;
                    else if (def === 'netctrl' && netctrlRadio) netctrlRadio.checked = true;
                    else if (lapseRadio) lapseRadio.checked = true;
                }
            }
        } else {
            [netctrlRadio, lapseRadio, relapseRadio].forEach(function(radio) {
                if (radio && radio.parentNode)
                    radio.parentNode.classList.add('firmware-unsupported');
            });
            if (jeilbrekBtn) jeilbrekBtn.disabled = true;
            fwUnsupportedReason = 'Firmware offsets failed to load.';
            if (fwDisplay) {
                fwDisplay.textContent = 'ERROR';
                fwDisplay.classList.remove('placeholder-text');
                fwDisplay.classList.add('bad');
            }
            window.logToUI('FW', 'offsetsFor not available');
            window.setStatus('Unsupported', 'error');
        }

    /*
    Why a chain cannot be selected right now, or null if it can. ONE source of
    truth for both handlers, so the refusal and its wording never depend on HOW
    the user activated the input.
    */
    function radioBlocked(chain) {
        if (!firmwareSupported)
            return fwUnsupportedReason || 'No offsets are present for this firmware.';
        if (chain === 'relapse' && !relapseOk)
            return 'Relapse required offsets not present on FW 10.00-13.00 yet.';
        if (chain === 'lapse' && !lapseOk)
            return 'Lapse supports FW 10.00-12.02 only.';
        if (chain === 'netctrl' && !netctrlOk)
            return 'Netcontrol supports FW 12.50 and above only.';
        return null;
    }

    /* The chain this firmware should be on, in preference order. */
    function defaultChain() {
        if (relapseOk) return 'relapse';
        if (netctrlOk) return 'netctrl';
        if (lapseOk) return 'lapse';
        return null;
    }

    function enforceSelection() {
        const def = defaultChain();
        if (def === 'relapse' && relapseRadio) relapseRadio.checked = true;
        else if (def === 'netctrl' && netctrlRadio) netctrlRadio.checked = true;
        else if (lapseRadio) lapseRadio.checked = true;
        return def || exploitChain;
    }

    /*
    Which radio we last explained a refusal for.

    ONE click on a blocked label produces a burst: click on the label, click on
    the input, click bubbling back to the form, plus a `change` on the input.
    All of those reach the two handlers below for a single user gesture. A
    `Date.now()` window does not reliably collapse them (the deliveries land in
    different milliseconds), so we dedupe on the ELEMENT instead: remember the
    input we just explained and stay quiet until a gesture touches a DIFFERENT
    option. That cannot swallow a genuine second click, which always changes
    the element.
    */
    let explainedFor = null;

    if (kexForm) {
        kexForm.addEventListener('change', function(e) {
            if (e.target.name !== 'kernel') return;
            const want = e.target.value;
            const why = radioBlocked(want);
            if (why) {
                if (e.target !== explainedFor) {
                    explainedFor = e.target;
                    window.logToUI('FW', why);
                }
                exploitChain = enforceSelection();
                localStorage.setItem('exploitChain', exploitChain);
                return;
            }
            explainedFor = null;
            localStorage.setItem('exploitChain', want);
            exploitChain = want;
            window.logToUI('UI', 'Exploit switched to: ' + exploitChain);
        });

        /*
        The pointer path. Only reachable because the radios are left ENABLED
        (a disabled input never fires this). It exists so clicking the label of
        an option that is ALREADY checked still explains why it will not take --
        an already-checked radio fires no `change`, so without this a click on
        it would be silent.
        */
        kexForm.addEventListener('click', function(e) {
            if (!e.target.closest || !e.target.closest('.radio-option')) return;
            const opt = e.target.closest('.radio-option');
            const radio = opt.querySelector('input[name="kernel"]');
            if (!radio) return;
            const why = radioBlocked(radio.value);
            if (!why) { explainedFor = null; return; }
            if (radio !== explainedFor) {
                explainedFor = radio;
                window.logToUI('FW', why);
            }
            enforceSelection();
        });
    }

    /*
    Final consistency pass: the STORED preference is advisory. Whatever chain
    this firmware actually runs wins, using the same preference order the
    eligibility block above applies. Reusing defaultChain() rather than a
    second, hand-written ladder is the point -- one place decides, always.
    */
    const finalChain = defaultChain();
    if (finalChain) exploitChain = finalChain;
    if (exploitChain === 'relapse' && relapseRadio) relapseRadio.checked = true;
    else if (exploitChain === 'netctrl' && netctrlRadio) netctrlRadio.checked = true;
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
                window.logToUI('UI', 'Need to add a custom payload.bin at '
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
