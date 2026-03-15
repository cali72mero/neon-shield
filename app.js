    let currentFiles = [];
    let keyfileBytes = null;

    const LEGACY_KDF = { iterations: 600000, hash: "SHA-256" };
    const MAGIC_V2 = new TextEncoder().encode("NEON2");
    const FILE_HEADER_LENGTH_BYTES = 4;
    const CLOUD_PAD_UNIT = 1024 * 1024;
    const TRUSTED_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

    const SECURITY_PROFILES = {
        balanced: {
            label: "Balanced",
            iterations: 600000,
            hash: "SHA-256",
            layers: 1,
            hint: "Schnell und stark. Gute Standardwahl fuer normale Nutzung."
        },
        hardened: {
            label: "Hardened",
            iterations: 1200000,
            hash: "SHA-512",
            layers: 1,
            hint: "Hoehere brute-force Kosten, aber merkbar langsamer bei alten Geraeten."
        },
        fortress: {
            label: "Fortress",
            iterations: 1500000,
            hash: "SHA-512",
            layers: 2,
            hint: "Maximale lokale Haerte: hohe KDF-Kosten + doppelte AES-GCM-Verschluesselung."
        }
    };

    const dropArea = document.getElementById('drop-area');
    const fileInput = document.getElementById('file-input');
    const fileInfo = document.getElementById('file-info');
    const overlay = document.getElementById('loading-overlay');
    const hostWarning = document.getElementById('host-warning');
    const passInput = document.getElementById('pass');
    const strengthFill = document.getElementById('strength-fill');
    const profileSelect = document.getElementById('security-profile');
    const profileHint = document.getElementById('profile-hint');
    const cloudModeToggle = document.getElementById('cloud-mode-toggle');
    const cloudModeHint = document.getElementById('cloud-mode-hint');
    const keyfileToggle = document.getElementById('keyfile-toggle');
    const passToggle = document.getElementById('toggle-pass');
    const lockButton = document.getElementById('lock-btn');
    const unlockButton = document.getElementById('unlock-btn');

    const keyfileDrop = document.getElementById('keyfile-drop');
    const keyfileInput = document.getElementById('keyfile-input');
    const trustState = { ok: true, reason: "" };

    function evaluateTrustedContext() {
        const protocol = window.location.protocol;
        const hostname = window.location.hostname;
        const localFile = protocol === "file:";
        const localHost = (protocol === "http:" || protocol === "https:") && TRUSTED_HOSTS.has(hostname);
        const githubPages = protocol === "https:" && hostname.endsWith(".github.io");
        if (localFile || localHost || githubPages) return { ok: true, reason: "" };
        return {
            ok: false,
            reason: "Remote-Host '" + window.location.host + "' ist nicht als lokal vertrauenswuerdig markiert."
        };
    }

    function lockDownNetworkApis() {
        const networkError = new Error("Netzwerkzugriff ist in diesem Build deaktiviert.");

        try {
            if (typeof window.fetch === "function") {
                window.fetch = async function () { throw networkError; };
            }
        } catch {}

        try {
            if (navigator && typeof navigator.sendBeacon === "function") {
                navigator.sendBeacon = function () { return false; };
            }
        } catch {}

        try {
            if (typeof window.XMLHttpRequest === "function") {
                const xhrProto = window.XMLHttpRequest.prototype;
                xhrProto.open = function () { throw networkError; };
                xhrProto.send = function () { throw networkError; };
            }
        } catch {}

        try {
            if (typeof window.WebSocket === "function") {
                window.WebSocket = function () { throw networkError; };
            }
        } catch {}

        try {
            if (typeof window.EventSource === "function") {
                window.EventSource = function () { throw networkError; };
            }
        } catch {}

        try {
            if (typeof window.RTCPeerConnection === "function") {
                window.RTCPeerConnection = function () { throw networkError; };
            }
        } catch {}
    }

    function applyRuntimeSecurityGuards() {
        lockDownNetworkApis();
        const ctx = evaluateTrustedContext();
        trustState.ok = ctx.ok;
        trustState.reason = ctx.reason;
        if (!ctx.ok) {
            hostWarning.style.display = "block";
            hostWarning.innerText = "⚠️ Unsicherer Host-Kontext erkannt: " + ctx.reason + " Erlaubt sind nur file://, localhost oder https://*.github.io.";
        }
    }

    function assertTrustedContext(logEl) {
        if (trustState.ok) return true;
        logEl.innerText = "❌ BLOCKIERT: Kryptofunktionen nur lokal/offline erlaubt. " + trustState.reason;
        logEl.style.color = "var(--warning)";
        return false;
    }

    function togglePass() {
        passInput.type = passInput.type === 'password' ? 'text' : 'password';
    }

    function calculatePasswordScore(val) {
        let score = 0;
        if (val.length > 0) score += 10;
        if (val.length >= 10) score += 30;
        if (/[A-Z]/.test(val)) score += 20;
        if (/[0-9]/.test(val)) score += 20;
        if (/[^A-Za-z0-9]/.test(val)) score += 20;
        return score;
    }

    function updatePasswordStrength() {
        const score = calculatePasswordScore(passInput.value);
        strengthFill.style.width = score + "%";
        if (score < 40) strengthFill.style.background = "var(--warning)";
        else if (score < 80) strengthFill.style.background = "var(--caution)";
        else strengthFill.style.background = "var(--success)";
    }

    function getSelectedProfileKey() {
        return SECURITY_PROFILES[profileSelect.value] ? profileSelect.value : "balanced";
    }

    function getSelectedProfile() {
        return SECURITY_PROFILES[getSelectedProfileKey()];
    }

    function getCloudModeEnabled() {
        return cloudModeToggle.checked;
    }

    function updateProfileHint() {
        const profile = getSelectedProfile();
        profileHint.innerText = profile.hint + (getCloudModeEnabled() ? " Cloud-Mode ist aktiv und nutzt Fortress fest." : "");
        cloudModeHint.innerText = getCloudModeEnabled()
            ? "Cloud-Mode aktiv: Fortress + Keyfile Pflicht + SHA-256 Hash fuer Upload-Kontrolle."
            : "Fuer Cloud-Backup ohne Klartextdaten. Empfohlen mit Keyfile.";
    }

    function toggleCloudMode() {
        if (getCloudModeEnabled()) {
            profileSelect.value = "fortress";
            profileSelect.disabled = true;
            if (!keyfileToggle.checked) {
                keyfileToggle.checked = true;
                toggleKeyfileUI();
            }
        } else {
            profileSelect.disabled = false;
        }
        updateProfileHint();
    }

    applyRuntimeSecurityGuards();

    passInput.addEventListener('input', updatePasswordStrength);
    profileSelect.addEventListener('change', updateProfileHint);
    cloudModeToggle.addEventListener('change', toggleCloudMode);
    keyfileToggle.addEventListener('change', toggleKeyfileUI);
    passToggle.addEventListener('click', togglePass);
    lockButton.addEventListener('click', () => process('lock'));
    unlockButton.addEventListener('click', () => process('unlock'));
    updatePasswordStrength();
    toggleCloudMode();

    function toggleKeyfileUI() {
        if (keyfileToggle.checked) {
            keyfileDrop.classList.add('active');
        } else {
            keyfileDrop.classList.remove('active');
            keyfileBytes = null;
            keyfileInput.value = "";
            document.getElementById('keyfile-name').innerText = "";
        }
    }

    keyfileDrop.addEventListener('click', () => keyfileInput.click());
    keyfileInput.addEventListener('change', (e) => loadKeyfile(e.target.files[0]));

    keyfileDrop.addEventListener('dragover', (e) => {
        e.preventDefault();
        keyfileDrop.style.borderColor = "#fff";
    });
    keyfileDrop.addEventListener('dragleave', () => {
        keyfileDrop.style.borderColor = "var(--neon)";
    });
    keyfileDrop.addEventListener('drop', (e) => {
        e.preventDefault();
        keyfileDrop.style.borderColor = "var(--neon)";
        loadKeyfile(e.dataTransfer.files[0]);
    });

    async function loadKeyfile(file) {
        if (!file) return;
        keyfileBytes = new Uint8Array(await file.arrayBuffer());
        document.getElementById('keyfile-name').innerText = "✅ Keyfile geladen: " + file.name;
    }

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach((e) => {
        dropArea.addEventListener(e, (evt) => {
            evt.preventDefault();
            evt.stopPropagation();
        }, false);
    });
    dropArea.addEventListener('dragover', () => dropArea.classList.add('dragover'));
    dropArea.addEventListener('dragleave', () => dropArea.classList.remove('dragover'));
    dropArea.addEventListener('drop', (e) => {
        dropArea.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });
    dropArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => handleFiles(e.target.files));

    function handleFiles(files) {
        currentFiles = Array.from(files);
        if (currentFiles.length > 0) {
            fileInfo.innerText = currentFiles.length + " Datei(en) bereit: " + currentFiles.map((f) => f.name).join(", ");
            fileInfo.style.color = "var(--neon)";
        } else {
            fileInfo.innerText = "Keine Dateien geladen.";
            fileInfo.style.color = "inherit";
        }
    }

    async function process(action) {
        const pw = passInput.value;
        const log = document.getElementById('log');
        const useKeyfile = keyfileToggle.checked;
        const cloudMode = getCloudModeEnabled();

        if (!assertTrustedContext(log)) return;

        if (!pw) {
            log.innerText = "❌ Fehler: Passwort fehlt!";
            log.style.color = "var(--warning)";
            return;
        }
        if (currentFiles.length === 0) {
            log.innerText = "❌ Fehler: Keine Dateien!";
            log.style.color = "var(--warning)";
            return;
        }
        if (useKeyfile && !keyfileBytes) {
            log.innerText = "❌ Fehler: Keyfile aktiviert, aber keine Datei gewaehlt!";
            log.style.color = "var(--warning)";
            return;
        }
        if (action === 'lock' && cloudMode && (!useKeyfile || !keyfileBytes)) {
            log.innerText = "❌ Cloud-Mode braucht zwingend eine Keyfile.";
            log.style.color = "var(--warning)";
            return;
        }

        if (action === 'lock') {
            if (pw.length < 10) {
                log.innerText = "❌ LOCK blockiert: Nutze mindestens 10 Zeichen Passwort.";
                log.style.color = "var(--warning)";
                return;
            }
            if (calculatePasswordScore(pw) < 60) {
                const proceed = window.confirm("Passwort ist eher schwach. Trotzdem fortfahren?");
                if (!proceed) {
                    log.innerText = "⚠️ Abgebrochen: Bitte staerkeres Passwort waehlen.";
                    log.style.color = "var(--caution)";
                    return;
                }
            }
        }

        overlay.style.display = 'flex';
        setTimeout(async () => {
            try {
                if (action === 'lock') {
                    await lock(pw);
                } else {
                    await unlock(pw);
                }
            } catch (e) {
                console.error(e);
                log.innerText = "❌ FEHLER / INTEGRITAETS-CHECK GESCHEITERT!\n(Falsches Passwort/Keyfile oder Datei beschaedigt)";
                log.style.color = "var(--warning)";
            } finally {
                overlay.style.display = 'none';
            }
        }, 50);
    }

    function concatUint8() {
        const parts = Array.from(arguments).map((part) => part instanceof Uint8Array ? part : new Uint8Array(part));
        const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const part of parts) {
            result.set(part, offset);
            offset += part.length;
        }
        return result;
    }

    function writeUint32LE(value) {
        const out = new Uint8Array(FILE_HEADER_LENGTH_BYTES);
        new DataView(out.buffer).setUint32(0, value, true);
        return out;
    }

    function readUint32LE(bytes, offset) {
        if (offset + FILE_HEADER_LENGTH_BYTES > bytes.length) {
            throw new Error("Defekter Datenblock: Uint32 ausserhalb der Datei.");
        }
        return new DataView(bytes.buffer, bytes.byteOffset + offset, FILE_HEADER_LENGTH_BYTES).getUint32(0, true);
    }

    function startsWithMagic(bytes) {
        if (bytes.length < MAGIC_V2.length) return false;
        for (let i = 0; i < MAGIC_V2.length; i++) {
            if (bytes[i] !== MAGIC_V2[i]) return false;
        }
        return true;
    }

    function buildPurposeSalt(salt, purpose) {
        const purposeBytes = new TextEncoder().encode("|" + purpose);
        return concatUint8(salt, purposeBytes);
    }

    function buildLayerAad(headerBytes, layerIndex) {
        return concatUint8(MAGIC_V2, writeUint32LE(layerIndex), headerBytes);
    }

    function toHex(bytes) {
        return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    function generateVaultFilename(cloudModeEnabled) {
        if (!cloudModeEnabled) return "tresor.neon";
        const ts = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
        const rand = toHex(crypto.getRandomValues(new Uint8Array(4)));
        return "vault-" + ts + "-" + rand + ".neon";
    }

    function downloadBlob(blob, filename) {
        const a = document.createElement('a');
        const url = URL.createObjectURL(blob);
        a.href = url;
        a.download = filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    function randomBytes(length) {
        const out = new Uint8Array(length);
        let offset = 0;
        while (offset < length) {
            const chunkSize = Math.min(65536, length - offset);
            const chunk = crypto.getRandomValues(new Uint8Array(chunkSize));
            out.set(chunk, offset);
            offset += chunkSize;
        }
        return out;
    }

    async function getLegacyKeyMaterial(password, keyBytes) {
        const encoder = new TextEncoder();
        let passBytes = encoder.encode(password);
        if (keyBytes) {
            const combined = new Uint8Array(passBytes.length + keyBytes.length);
            combined.set(passBytes);
            combined.set(keyBytes, passBytes.length);
            passBytes = combined;
        }
        return crypto.subtle.importKey("raw", passBytes, "PBKDF2", false, ["deriveKey"]);
    }

    async function getHardenedKeyMaterial(password, keyBytes) {
        const encoder = new TextEncoder();
        const passBytes = encoder.encode(password);
        const keyDigest = keyBytes
            ? new Uint8Array(await crypto.subtle.digest("SHA-512", keyBytes))
            : new Uint8Array(0);
        const seed = concatUint8(encoder.encode("NEON2-KM2|"), passBytes, encoder.encode("|"), keyDigest);
        const material = new Uint8Array(await crypto.subtle.digest("SHA-512", seed));
        return crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
    }

    function validateKdfConfig(kdf) {
        const isHashAllowed = kdf.hash === "SHA-256" || kdf.hash === "SHA-512";
        const isIterationSafe = Number.isInteger(kdf.iterations) && kdf.iterations >= 100000 && kdf.iterations <= 3000000;
        if (!isHashAllowed || !isIterationSafe) {
            throw new Error("Ungueltige KDF-Parameter.");
        }
    }

    async function deriveAesKey(password, keyBytes, salt, kdf, purpose, usage, keyMaterialVersion) {
        validateKdfConfig(kdf);
        const keyMaterial = keyMaterialVersion === 2
            ? await getHardenedKeyMaterial(password, keyBytes)
            : await getLegacyKeyMaterial(password, keyBytes);
        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: buildPurposeSalt(salt, purpose),
                iterations: kdf.iterations,
                hash: kdf.hash
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            [usage]
        );
    }

    async function deriveLegacyKey(password, keyBytes, salt, usage) {
        const keyMaterial = await getLegacyKeyMaterial(password, keyBytes);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: LEGACY_KDF.iterations, hash: LEGACY_KDF.hash },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            [usage]
        );
    }

    async function lock(pw) {
        const log = document.getElementById('log');
        const encoder = new TextEncoder();
        const cloudMode = getCloudModeEnabled();
        const selectedProfileKey = cloudMode ? "fortress" : getSelectedProfileKey();
        const profile = SECURITY_PROFILES[selectedProfileKey];

        const dataParts = [];
        for (const f of currentFiles) {
            const content = new Uint8Array(await f.arrayBuffer());
            const header = encoder.encode(JSON.stringify({ n: f.name, t: f.type, s: content.length }));
            dataParts.push(writeUint32LE(header.length), header, content);
        }

        let payload = new Uint8Array(await new Blob(dataParts).arrayBuffer());
        let plainPad = 0;
        if (cloudMode) {
            plainPad = (CLOUD_PAD_UNIT - (payload.length % CLOUD_PAD_UNIT)) % CLOUD_PAD_UNIT;
            if (plainPad > 0) {
                payload = concatUint8(payload, randomBytes(plainPad));
            }
        }

        const envelopeMeta = {
            v: 2,
            kdf: { iterations: profile.iterations, hash: profile.hash },
            layers: profile.layers,
            km: 2,
            aad: 1,
            padPlain: plainPad
        };
        if (cloudMode) envelopeMeta.cloud = 1;
        const envelopeHeader = encoder.encode(JSON.stringify(envelopeMeta));

        for (let layer = 1; layer <= profile.layers; layer++) {
            const salt = randomBytes(16);
            const iv = randomBytes(12);
            const key = await deriveAesKey(pw, keyfileBytes, salt, profile, "layer-" + layer, "encrypt", 2);
            const aad = buildLayerAad(envelopeHeader, layer);
            const encrypted = new Uint8Array(await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv, additionalData: aad },
                key,
                payload
            ));
            payload = concatUint8(salt, iv, encrypted);
        }

        const outBytes = concatUint8(MAGIC_V2, writeUint32LE(envelopeHeader.length), envelopeHeader, payload);
        const outName = generateVaultFilename(cloudMode);
        downloadBlob(new Blob([outBytes], { type: "application/octet-stream" }), outName);

        if (cloudMode) {
            const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", outBytes));
            const hashLine = toHex(digest) + "  " + outName + "\n";
            downloadBlob(new Blob([hashLine], { type: "text/plain" }), outName + ".sha256.txt");
            log.innerText = "✅ FERTIG: " + outName + " + SHA256 Hash exportiert (Cloud-Mode).";
        } else {
            log.innerText = "✅ FERTIG: " + outName + " gespeichert. Profil: " + profile.label + " (" + profile.layers + " Layer).";
        }
        log.style.color = "var(--success)";
    }

    function parseV2Envelope(fullData) {
        let offset = MAGIC_V2.length;
        const headerLength = readUint32LE(fullData, offset);
        offset += FILE_HEADER_LENGTH_BYTES;

        if (headerLength < 2 || offset + headerLength > fullData.length) {
            throw new Error("Defekte NEON2-Datei: Header ungueltig.");
        }

        const headerBytes = fullData.slice(offset, offset + headerLength);
        const headerRaw = new TextDecoder().decode(headerBytes);
        offset += headerLength;

        let header;
        try {
            header = JSON.parse(headerRaw);
        } catch {
            throw new Error("Defekte NEON2-Datei: Header ist kein JSON.");
        }

        if (!header || header.v !== 2) {
            throw new Error("Nicht unterstuetzte NEON-Dateiversion.");
        }
        if (!header.kdf || typeof header.kdf !== "object") {
            throw new Error("Defekte NEON2-Datei: KDF-Daten fehlen.");
        }
        if (!Number.isInteger(header.layers) || header.layers < 1 || header.layers > 2) {
            throw new Error("Defekte NEON2-Datei: Layer-Wert ist ungueltig.");
        }
        if (header.km === undefined) header.km = 1;
        if (header.km !== 1 && header.km !== 2) {
            throw new Error("Defekte NEON2-Datei: Key-Material-Version ungueltig.");
        }
        if (header.aad !== undefined && header.aad !== 0 && header.aad !== 1) {
            throw new Error("Defekte NEON2-Datei: AAD-Flag ungueltig.");
        }
        if (header.padPlain === undefined) header.padPlain = 0;
        if (!Number.isInteger(header.padPlain) || header.padPlain < 0 || header.padPlain > (32 * 1024 * 1024)) {
            throw new Error("Defekte NEON2-Datei: Padding-Wert ungueltig.");
        }

        validateKdfConfig(header.kdf);
        return { header: header, headerBytes: headerBytes, payload: fullData.slice(offset) };
    }

    async function decryptLegacy(fullData, password) {
        if (fullData.length < 29) {
            throw new Error("Defekte Legacy-Datei.");
        }

        const salt = fullData.slice(0, 16);
        const iv = fullData.slice(16, 28);
        const encrypted = fullData.slice(28);
        const key = await deriveLegacyKey(password, keyfileBytes, salt, "decrypt");
        return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encrypted));
    }

    async function decryptV2(fullData, password) {
        const parsed = parseV2Envelope(fullData);
        const kdf = parsed.header.kdf;
        const useAad = parsed.header.aad === 1;

        let payload = parsed.payload;
        for (let layer = parsed.header.layers; layer >= 1; layer--) {
            if (payload.length < 29) {
                throw new Error("Defekte NEON2-Datei: Layer " + layer + " zu kurz.");
            }
            const salt = payload.slice(0, 16);
            const iv = payload.slice(16, 28);
            const encrypted = payload.slice(28);

            const key = await deriveAesKey(password, keyfileBytes, salt, kdf, "layer-" + layer, "decrypt", parsed.header.km);
            const params = useAad
                ? { name: "AES-GCM", iv: iv, additionalData: buildLayerAad(parsed.headerBytes, layer) }
                : { name: "AES-GCM", iv: iv };
            payload = new Uint8Array(await crypto.subtle.decrypt(params, key, encrypted));
        }

        if (parsed.header.padPlain > payload.length) {
            throw new Error("Defekte NEON2-Datei: Padding groesser als Inhalt.");
        }
        if (parsed.header.padPlain > 0) {
            payload = payload.slice(0, payload.length - parsed.header.padPlain);
        }

        return { plaintext: payload, header: parsed.header };
    }

    function parseVaultEntries(decrypted) {
        const entries = [];
        const decoder = new TextDecoder();
        let offset = 0;

        while (offset < decrypted.length) {
            const headerLength = readUint32LE(decrypted, offset);
            offset += FILE_HEADER_LENGTH_BYTES;

            if (headerLength < 2 || offset + headerLength > decrypted.length) {
                throw new Error("Defekter Tresorinhalt: Header ausserhalb des Datenbereichs.");
            }

            const headerBytes = decrypted.slice(offset, offset + headerLength);
            offset += headerLength;

            let header;
            try {
                header = JSON.parse(decoder.decode(headerBytes));
            } catch {
                throw new Error("Defekter Tresorinhalt: Datei-Header ist ungueltig.");
            }

            const validSize = Number.isInteger(header.s) && header.s >= 0;
            if (!header || typeof header.n !== "string" || !validSize || offset + header.s > decrypted.length) {
                throw new Error("Defekter Tresorinhalt: Datei-Metadaten ungueltig.");
            }

            const mimeType = typeof header.t === "string" && header.t ? header.t : "application/octet-stream";
            const fileData = decrypted.slice(offset, offset + header.s);
            offset += header.s;

            entries.push({ name: header.n, type: mimeType, data: fileData });
        }

        if (entries.length === 0) {
            throw new Error("Tresor ist leer.");
        }

        return entries;
    }

    function renderPreviewItem(previewGrid, entry) {
        const url = URL.createObjectURL(new Blob([entry.data], { type: entry.type }));
        const card = document.createElement('div');
        card.className = 'preview-item';

        if (entry.type.startsWith('image/')) {
            const img = document.createElement('img');
            img.src = url;
            img.alt = entry.name;
            card.appendChild(img);
        } else {
            const icon = document.createElement('div');
            icon.style.fontSize = "2rem";
            icon.style.marginBottom = "5px";
            icon.textContent = entry.type.startsWith('video/') ? "🎬" : entry.type.startsWith('audio/') ? "🎵" : "📄";
            card.appendChild(icon);
        }

        const name = document.createElement('div');
        name.style.fontSize = "0.7rem";
        name.style.margin = "5px 0";
        name.textContent = entry.name;

        const link = document.createElement('a');
        link.href = url;
        link.download = entry.name;
        link.textContent = "Laden";
        link.style.background = "var(--neon)";
        link.style.color = "#000";
        link.style.padding = "2px 8px";
        link.style.textDecoration = "none";
        link.style.borderRadius = "4px";
        link.style.fontSize = "0.7rem";
        link.style.fontWeight = "bold";

        card.appendChild(name);
        card.appendChild(link);
        previewGrid.appendChild(card);
    }

    async function unlock(pw) {
        const log = document.getElementById('log');
        const previewGrid = document.getElementById('previews');
        previewGrid.innerHTML = "";

        const fullData = new Uint8Array(await currentFiles[0].arrayBuffer());
        const useV2 = startsWithMagic(fullData);
        let decrypted;
        let v2Header = null;
        if (useV2) {
            const parsed = await decryptV2(fullData, pw);
            decrypted = parsed.plaintext;
            v2Header = parsed.header;
        } else {
            decrypted = await decryptLegacy(fullData, pw);
        }
        const entries = parseVaultEntries(decrypted);

        for (const entry of entries) {
            renderPreviewItem(previewGrid, entry);
        }

        if (useV2 && v2Header && v2Header.cloud === 1) {
            log.innerText = "✅ INTEGRITAETS-CHECK: OK. Tresor geoeffnet (NEON2 Cloud-Mode).";
        } else {
            log.innerText = useV2
                ? "✅ INTEGRITAETS-CHECK: OK. Tresor geoeffnet (NEON2)."
                : "✅ INTEGRITAETS-CHECK: OK. Tresor geoeffnet (Legacy).";
        }
        log.style.color = "var(--success)";
    }
