const MAGIC_V2 = new TextEncoder().encode("NEON2");
const FILE_HEADER_LENGTH_BYTES = 4;

function toUint8(value) {
    if (!value) return new Uint8Array(0);
    return value instanceof Uint8Array ? value : new Uint8Array(value);
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

function buildPurposeSalt(salt, purpose) {
    const purposeBytes = new TextEncoder().encode("|" + purpose);
    return concatUint8(salt, purposeBytes);
}

function buildLayerAad(headerBytes, layerIndex) {
    return concatUint8(MAGIC_V2, writeUint32LE(layerIndex), headerBytes);
}

function validateKdfConfig(kdf) {
    const isHashAllowed = kdf.hash === "SHA-256" || kdf.hash === "SHA-512";
    const isIterationSafe = Number.isInteger(kdf.iterations) && kdf.iterations >= 100000 && kdf.iterations <= 3000000;
    if (!isHashAllowed || !isIterationSafe) {
        throw new Error("Invalid KDF configuration.");
    }
}

async function getLegacyKeyMaterial(password, keyBytes) {
    const encoder = new TextEncoder();
    let passBytes = encoder.encode(password);
    if (keyBytes && keyBytes.length > 0) {
        const combined = new Uint8Array(passBytes.length + keyBytes.length);
        combined.set(passBytes);
        combined.set(keyBytes, passBytes.length);
        passBytes = combined;
    }
    return crypto.subtle.importKey("raw", passBytes, "PBKDF2", false, ["deriveKey"]);
}

async function getHardenedKeyMaterial(password, keyBytes, recoveredDigest) {
    const encoder = new TextEncoder();
    const passBytes = encoder.encode(password);
    const keyDigest = keyBytes && keyBytes.length > 0
        ? new Uint8Array(await crypto.subtle.digest("SHA-512", keyBytes))
        : (recoveredDigest && recoveredDigest.length > 0 ? recoveredDigest : new Uint8Array(0));
    const seed = concatUint8(encoder.encode("NEON2-KM2|"), passBytes, encoder.encode("|"), keyDigest);
    const material = new Uint8Array(await crypto.subtle.digest("SHA-512", seed));
    return crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
}

async function getQuantumKeyMaterial(password, keyBytes, recoveredDigest) {
    const encoder = new TextEncoder();
    const passBytes = encoder.encode(password);
    const keyDigest = keyBytes && keyBytes.length > 0
        ? new Uint8Array(await crypto.subtle.digest("SHA-512", keyBytes))
        : (recoveredDigest && recoveredDigest.length > 0 ? recoveredDigest : new Uint8Array(0));
    const phase1Seed = concatUint8(encoder.encode("NEON2-QM3|"), passBytes, encoder.encode("|"), keyDigest);
    const phase1 = new Uint8Array(await crypto.subtle.digest("SHA-512", phase1Seed));
    const phase2 = new Uint8Array(await crypto.subtle.digest("SHA-256", concatUint8(phase1, passBytes)));
    const phase3 = new Uint8Array(await crypto.subtle.digest("SHA-512", concatUint8(phase2, keyDigest, phase1)));
    const mixed = concatUint8(phase1, phase2, phase3);
    const finalMaterial = new Uint8Array(await crypto.subtle.digest("SHA-512", mixed));
    return crypto.subtle.importKey("raw", finalMaterial, "PBKDF2", false, ["deriveKey"]);
}

async function deriveAesKey(password, keyBytes, recoveredDigest, salt, kdf, purpose, usage, keyMaterialVersion) {
    validateKdfConfig(kdf);
    const keyMaterial = keyMaterialVersion === 3
        ? await getQuantumKeyMaterial(password, keyBytes, recoveredDigest)
        : keyMaterialVersion === 2
            ? await getHardenedKeyMaterial(password, keyBytes, recoveredDigest)
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

async function encryptLayers(payloadBytes, password, keyBytes, recoveredDigest, profile, headerBytes) {
    const kdf = { iterations: profile.iterations, hash: profile.hash };
    const layers = Number(profile.layers || 1);
    const km = Number(profile.keyMaterialVersion || 2);
    let payload = payloadBytes;
    for (let layer = 1; layer <= layers; layer++) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveAesKey(password, keyBytes, recoveredDigest, salt, kdf, "layer-" + layer, "encrypt", km);
        const aad = buildLayerAad(headerBytes, layer);
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: aad }, key, payload));
        payload = concatUint8(salt, iv, encrypted);
    }
    return payload;
}

async function decryptLayers(payloadBytes, password, keyBytes, recoveredDigest, header, headerBytes) {
    const kdf = header.kdf;
    const useAad = header.aad === 1;
    let payload = payloadBytes;
    for (let layer = header.layers; layer >= 1; layer--) {
        if (payload.length < 29) {
            throw new Error("Corrupt NEON2 part: invalid layer length.");
        }
        const salt = payload.slice(0, 16);
        const iv = payload.slice(16, 28);
        const encrypted = payload.slice(28);
        const key = await deriveAesKey(password, keyBytes, recoveredDigest, salt, kdf, "layer-" + layer, "decrypt", header.km);
        const params = useAad
            ? { name: "AES-GCM", iv: iv, additionalData: buildLayerAad(headerBytes, layer) }
            : { name: "AES-GCM", iv: iv };
        payload = new Uint8Array(await crypto.subtle.decrypt(params, key, encrypted));
    }
    return payload;
}

self.onmessage = async (event) => {
    const data = event.data || {};
    const id = data.id;
    const type = data.type;
    const payload = data.payload || {};
    try {
        if (type === "encryptLayers") {
            const out = await encryptLayers(
                toUint8(payload.payload),
                String(payload.password || ""),
                payload.keyBytes ? toUint8(payload.keyBytes) : null,
                payload.recoveredDigest ? toUint8(payload.recoveredDigest) : null,
                payload.profile || {},
                toUint8(payload.headerBytes)
            );
            self.postMessage({ id: id, ok: true, payload: out.buffer }, [out.buffer]);
            return;
        }
        if (type === "decryptLayers") {
            const out = await decryptLayers(
                toUint8(payload.payload),
                String(payload.password || ""),
                payload.keyBytes ? toUint8(payload.keyBytes) : null,
                payload.recoveredDigest ? toUint8(payload.recoveredDigest) : null,
                payload.header || {},
                toUint8(payload.headerBytes)
            );
            self.postMessage({ id: id, ok: true, payload: out.buffer }, [out.buffer]);
            return;
        }
        if (type === "digest") {
            const algo = String(payload.algorithm || "SHA-256");
            const out = new Uint8Array(await crypto.subtle.digest(algo, toUint8(payload.data)));
            self.postMessage({ id: id, ok: true, payload: out.buffer }, [out.buffer]);
            return;
        }
        throw new Error("Unknown worker message type: " + type);
    } catch (error) {
        const message = error && typeof error.message === "string" ? error.message : "Worker operation failed.";
        self.postMessage({ id: id, ok: false, error: message });
    }
};
