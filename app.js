    let currentFiles = [];
    let keyfileBytes = null;
    let keyfileDisplayName = "";
    let generatedKeyfileBytes = null;
    let generatedKeyfileName = "";
    let recoveredKeyDigestOverride = null;
    let inactivityTimer = null;
    let unlockedEntries = [];
    let lastUnlockMeta = null;
    const previewObjectUrls = [];

    const LEGACY_KDF = { iterations: 600000, hash: "SHA-256" };
    const MAGIC_V2 = new TextEncoder().encode("NEON2");
    const FILE_HEADER_LENGTH_BYTES = 4;
    const MAX_LOCK_BATCH_BYTES = 32 * 1024 * 1024;
    const MAX_LOCK_BATCH_FILES = 80;
    const MAX_ZIP_CHUNK_BYTES = 96 * 1024 * 1024;
    const PART_FILENAME_RE = /\.part(\d+)-of-(\d+)\.neon$/i;
    const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    const cryptoWorkerState = {
        worker: null,
        ready: false,
        pending: new Map(),
        seq: 0
    };

    const SECURITY_PROFILES = {
        balanced: {
            label: "Balanced",
            iterations: 600000,
            hash: "SHA-256",
            layers: 1,
            keyMaterialVersion: 2,
            hintKey: "profileHintBalanced"
        },
        hardened: {
            label: "Hardened",
            iterations: 1200000,
            hash: "SHA-512",
            layers: 1,
            keyMaterialVersion: 2,
            hintKey: "profileHintHardened"
        },
        fortress: {
            label: "Fortress",
            iterations: 1500000,
            hash: "SHA-512",
            layers: 2,
            keyMaterialVersion: 2,
            hintKey: "profileHintFortress"
        },
        apex5: {
            label: "Apex-5",
            iterations: 1900000,
            hash: "SHA-512",
            layers: 5,
            keyMaterialVersion: 3,
            hintKey: "profileHintApex"
        },
        quantum8: {
            label: "Quantum-8",
            iterations: 2300000,
            hash: "SHA-512",
            layers: 8,
            keyMaterialVersion: 3,
            hintKey: "profileHintQuantum"
        }
    };

    const dropArea = document.getElementById('drop-area');
    const fileInput = document.getElementById('file-input');
    const folderInput = document.getElementById('folder-input');
    const pickFilesButton = document.getElementById('pick-files-btn');
    const pickFolderButton = document.getElementById('pick-folder-btn');
    const fileInfo = document.getElementById('file-info');
    const overlay = document.getElementById('loading-overlay');
    const passInput = document.getElementById('pass');
    const strengthFill = document.getElementById('strength-fill');
    const profileSelect = document.getElementById('security-profile');
    const profileHint = document.getElementById('profile-hint');
    const cloudModeToggle = document.getElementById('cloud-mode-toggle');
    const cloudModeHint = document.getElementById('cloud-mode-hint');
    const cloudPadSelect = document.getElementById('cloud-pad-select');
    const cloudChaffToggle = document.getElementById('cloud-chaff-toggle');
    const requireKeyfileToggle = document.getElementById('require-keyfile-toggle');
    const clearSecretToggle = document.getElementById('clear-secret-toggle');
    const autoLockSelect = document.getElementById('auto-lock-select');
    const ecoModeToggle = document.getElementById('eco-mode-toggle');
    const securityReportEl = document.getElementById('security-report');
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const keyfileToggle = document.getElementById('keyfile-toggle');
    const genKeyfileButton = document.getElementById('gen-keyfile-btn');
    const downloadKeyfileButton = document.getElementById('download-keyfile-btn');
    const passToggle = document.getElementById('toggle-pass');
    const lockButton = document.getElementById('lock-btn');
    const unlockButton = document.getElementById('unlock-btn');
    const recoveryToggle = document.getElementById('recovery-toggle');
    const recoveryPanel = document.getElementById('recovery-panel');
    const recoveryPassInput = document.getElementById('recovery-pass');
    const recoveryCountSelect = document.getElementById('recovery-count');
    const previewActions = document.getElementById('preview-actions');
    const previewSummary = document.getElementById('preview-summary');
    const downloadAllZipButton = document.getElementById('download-all-zip-btn');
    const saveFolderButton = document.getElementById('save-folder-btn');

    const keyfileDrop = document.getElementById('keyfile-drop');
    const keyfileInput = document.getElementById('keyfile-input');
    const trustState = { ok: true, reason: "" };
    let currentLang = "de";

    const I18N = {
        de: {
            headerSubtitle: "Open Source auf GitHub | Entwickelt von einem Einzelentwickler",
            guideTitle: "📖 Anleitung & Sicherheit",
            guideIntro: "Schütze deine privaten Dateien direkt auf deinem Gerät, ohne Cloud-Zwang.",
            guideB1: "<strong>Verschlüsselung:</strong> AES-256-GCM mit Integritätsprüfung. Manipulierte Daten werden erkannt.",
            guideB2: "<strong>LOCK:</strong> Dateien auswählen, starkes Passwort setzen, optional Keyfile hinzufügen, dann Tresor erzeugen.",
            guideB3: "<strong>UNLOCK:</strong> <code>.neon</code>-Datei laden, Passwort (und ggf. Keyfile) eingeben, Inhalte sicher wiederherstellen.",
            guideB4: "<strong>Cloud-Mode:</strong> Für Backups mit anonymisiertem Dateinamen, Padding und SHA-256-Prüfdatei.",
            guideProfilesTitle: "<strong>Welche Stufe soll ich wählen?</strong>",
            guideP1: "<strong>Balanced:</strong> Alltag, kleine/mittlere Dateien, schnell.",
            guideP2: "<strong>Hardened:</strong> Mehr Schutz bei weiterhin guter Nutzbarkeit.",
            guideP3: "<strong>Fortress:</strong> Für sensible Daten auf modernen Geräten.",
            guideP4: "<strong>Apex-5:</strong> Sehr hoher Schutz, deutlich langsamer.",
            guideP5: "<strong>Quantum-8:</strong> Maximale Härte (extrem langsam), nur für sehr sensible Daten.",
            guideBestPractice: "<strong>Empfehlung:</strong> Nimm ein langes Passwort (mind. 16+ Zeichen) und aktiviere bei wichtigen Daten ein Keyfile.",
            guideAlert: "⚠️ WICHTIG: Ohne korrektes Passwort (und ggf. Keyfile) ist eine Wiederherstellung nicht möglich.",
            guidePrivacy: "<strong>Datenschutz:</strong> Verschlüsselung und Entschlüsselung laufen im Browser. Du entscheidest selbst, wo du die erzeugten Dateien speicherst.",
            filesTitle: "01_DATEIEN AUSWÄHLEN",
            dropText: "Dateien oder Ordner hierher ziehen oder klicken",
            pickFilesBtn: "Dateien wählen",
            pickFolderBtn: "Ordner wählen",
            noFiles: "Keine Dateien geladen.",
            filesReadySuffix: "Datei(en) bereit",
            securityTitle: "02_SICHERHEITS-SCHLÜSSEL",
            passPlaceholder: "Dein Master-Passwort...",
            keyfileLabel: "📂 „Schlüssel-Datei“ (Keyfile) als 2-Faktor-Schutz nutzen (optional)",
            keyfileDropTitle: "[HIER KEYFILE ZIEHEN]",
            keyfileDropSub: "Bild, MP3 oder beliebige Datei als Schlüssel nutzen",
            genKeyfileBtn: "🔑 Keyfile lokal generieren",
            downloadKeyfileBtn: "⬇ Keyfile herunterladen",
            genKeyfileHint: "Erstellt eine zufällige Keyfile-Datei lokal auf deinem Gerät.",
            profileLabel: "🔐 Sicherheitsprofil (für neue LOCK-Dateien)",
            profileBalanced: "Balanced | PBKDF2-SHA256 | 600k | 1 Layer",
            profileHardened: "Hardened | PBKDF2-SHA512 | 1,2M | 1 Layer",
            profileFortress: "Fortress | PBKDF2-SHA512 | 1,5M | 2 Layer",
            profileApex: "Apex-5 | PBKDF2-SHA512 | 1,9M | 5 Layer",
            profileQuantum: "Quantum-8 | PBKDF2-SHA512 | 2,3M | 8 Layer",
            cloudLabel: "☁️ Cloud-Mode (Zero-Knowledge): zufälliger Dateiname, Padding, Integritäts-Hash",
            cloudHintOn: "Cloud-Mode aktiv: Fortress + Keyfile-Pflicht + SHA-256-Hash zur Upload-Kontrolle.",
            cloudHintOff: "Für Cloud-Backup ohne Klartextdaten. Empfohlen mit Keyfile.",
            cloudPadLabel: "Cloud-Padding Blockgröße",
            cloudPad1: "1 MB",
            cloudPad4: "4 MB",
            cloudPad8: "8 MB",
            cloudChaffLabel: "Cloud-Tarnmodus: zufällige Lockvogel-Dateien hinzufügen",
            requireKeyfileLabel: "Keyfile für LOCK erzwingen (empfohlen für sensible Daten)",
            recoveryToggleLabel: "🔁 Recovery ohne Keyfile erlauben (2. Passwort + Sicherheitsfragen)",
            recoveryPassLabel: "Recovery-Passwort (anders als Master-Passwort)",
            recoveryPassPlaceholder: "Recovery-Passwort...",
            recoveryCountLabel: "Anzahl Sicherheitsfragen (1-5)",
            recoveryCount1: "1 Frage",
            recoveryCount2: "2 Fragen",
            recoveryCount3: "3 Fragen",
            recoveryCount4: "4 Fragen",
            recoveryCount5: "5 Fragen",
            recoveryQ1: "Frage 1",
            recoveryQ2: "Frage 2",
            recoveryQ3: "Frage 3",
            recoveryQ4: "Frage 4",
            recoveryQ5: "Frage 5",
            recoveryA1: "Antwort 1",
            recoveryA2: "Antwort 2",
            recoveryA3: "Antwort 3",
            recoveryA4: "Antwort 4",
            recoveryA5: "Antwort 5",
            recoveryNote: "Nur wenn alle Antworten exakt stimmen, ist UNLOCK ohne Keyfile möglich.",
            clearSecretLabel: "Passwort nach jeder Aktion automatisch löschen",
            autoLockLabel: "Auto-Lock bei Inaktivität",
            autoLockOff: "Aus",
            autoLock5: "5 Minuten",
            autoLock10: "10 Minuten",
            autoLock30: "30 Minuten",
            autoLockHint: "Auto-Lock leert Passwort und Vorschau automatisch nach Inaktivität.",
            ecoModeLabel: "🧠 Eco-Mode: adaptive RAM-sparende Verarbeitung",
            ecoModeHint: "Reduziert Batch-Größe automatisch auf schwächeren Geräten.",
            lockBtn: "🔒 LOCK (.neon)",
            unlockBtn: "🔓 UNLOCK",
            versionText: "Version: 1.8 (Aktuell)",
            footerText: "Ich bin ein Einzelentwickler und gebe mein Bestes, diese Webseite ständig zu verbessern. Wenn du Fehler findest oder Vorschläge hast, melde dich gerne:",
            copyrightText: "© 2025 Neon-Shield Project. 100 % Datenschutz-Fokus.",
            profileHintBalanced: "Schnell und stark. Gute Standardwahl für normale Nutzung.",
            profileHintHardened: "Höhere Brute-Force-Kosten, aber spürbar langsamer auf älteren Geräten.",
            profileHintFortress: "Maximale lokale Härte: hohe KDF-Kosten + doppelte AES-GCM-Verschlüsselung.",
            profileHintApex: "Extremprofil: 5 AES-GCM-Layer + starkes KDF-Mixing. Deutlich langsamer, aber robuster.",
            profileHintQuantum: "Quantum-Hardening: 8 AES-GCM-Layer + mehrfaches KDF-Mixing. Sehr langsam, maximale Härte.",
            trustContextError: "Unsicherer Kontext (ohne HTTPS).",
            blockedContext: "❌ BLOCKIERT: Kryptofunktionen nur in sicherem Kontext erlaubt.",
            errorNoPassword: "❌ Fehler: Passwort fehlt!",
            errorNoFiles: "❌ Fehler: Keine Dateien!",
            errorKeyfileMissing: "❌ Fehler: Keyfile aktiviert, aber keine Datei gewählt!",
            errorFolderUnsupported: "❌ Dieser Browser unterstützt keine Ordner-Auswahl. Nutze Drag&Drop oder einen Chromium-Browser.",
            errorCloudNeedsKeyfile: "❌ Cloud-Mode braucht zwingend eine Keyfile.",
            errorRequireKeyfile: "❌ LOCK blockiert: Diese Einstellung verlangt eine Keyfile.",
            errorRecoveryNeedsKeyfile: "❌ Recovery kann nur mit aktivem Keyfile erstellt werden.",
            errorRecoveryNeedsPass: "❌ Recovery aktiviert: Bitte Recovery-Passwort setzen.",
            errorRecoveryNeedsQuestions: "❌ Recovery aktiviert: Bitte 1-5 Fragen mit Antworten vollständig ausfüllen.",
            errorRecoveryAnswerMissing: "❌ Recovery-UNLOCK: Bitte alle erforderlichen Antworten eingeben.",
            errorRecoverySamePassword: "❌ Recovery-Passwort muss sich vom Master-Passwort unterscheiden.",
            recoveryPromptReady: "ℹ️ Recovery verfügbar: Bitte Recovery-Passwort und Antworten eingeben.",
            errorNoGeneratedKeyfile: "❌ Es ist noch keine generierte Keyfile vorhanden.",
            errorPasswordShort: "❌ LOCK blockiert: Nutze mindestens 10 Zeichen Passwort.",
            errorUnlockSingle: "❌ Für UNLOCK bitte genau eine .neon-Datei auswählen.",
            weakConfirm: "Passwort ist eher schwach. Trotzdem fortfahren?",
            weakAbort: "⚠️ Abgebrochen: Bitte stärkeres Passwort wählen.",
            cryptoError: "❌ FEHLER / INTEGRITÄTS-CHECK GESCHEITERT!\n(Falsches Passwort/Keyfile oder Datei beschädigt)",
            unexpectedError: "❌ Unerwarteter Fehler. Bitte Seite neu laden und erneut versuchen.",
            keyfileLoaded: "✅ Keyfile geladen:",
            keyfileGenerated: "✅ Keyfile lokal generiert und geladen:",
            keyfileGeneratedReady: "✅ Keyfile erstellt. Klicke jetzt auf „Keyfile herunterladen“.",
            doneCloud: "✅ FERTIG:",
            doneCloudSuffix: "+ SHA-256-Hash exportiert (Cloud-Mode).",
            doneLock: "✅ FERTIG:",
            doneLockSuffix: "gespeichert. Profil:",
            doneCloudMultiSuffix: "Teile + SHA-256-Hashes exportiert (Cloud-Mode).",
            doneLockMultiSuffix: "Teile gespeichert. Profil:",
            lockBatchRunning: "⏳ LOCK läuft: Teil",
            lockBatchOf: "von",
            lockManifestReady: "Manifest gespeichert:",
            progressIdle: "Bereit.",
            progressLock: "LOCK-Fortschritt",
            progressUnlock: "UNLOCK-Fortschritt",
            progressExportZip: "ZIP-Export",
            progressExportFolder: "Ordner-Export",
            previewActionsTitle: "03_EXPORT",
            downloadAllZipBtn: "⬇ Alle als ZIP herunterladen",
            saveFolderBtn: "📁 Ordnerstruktur speichern",
            exportHint: "Große Exporte werden automatisch in mehrere ZIP-Dateien aufgeteilt.",
            unlockNoVaultFiles: "❌ Für UNLOCK wurde keine .neon-Datei ausgewählt.",
            unlockNeedsParts: "❌ Ungültige Part-Auswahl. Bitte zusammengehörige .partXXX-of-YYY.neon Dateien wählen.",
            unlockMissingParts: "⚠️ Fehlende Teile erkannt:",
            unlockMissingPartsAsk: "Fehlende Teile erkannt. Nur vorhandene Teile entschlüsseln?",
            unlockPartialChosen: "⚠️ Fortsetzung im Teilmodus. Fehlende Teile werden übersprungen.",
            unlockPartFailed: "Teil konnte nicht entschlüsselt werden",
            unlockHashMismatch: "Integritätsfehler (SHA-256) im Teil",
            unlockDoneMulti: "✅ Mehrteiliger UNLOCK abgeschlossen.",
            unlockSummaryLine: "Entschlüsselte Teile",
            summaryFiles: "Dateien",
            summarySize: "Gesamtgröße",
            summaryFailedParts: "Fehlerteile",
            summaryMissingParts: "Fehlende Teile",
            zipDone: "✅ ZIP-Export fertig.",
            folderDone: "✅ Ordner-Export fertig.",
            folderApiMissing: "❌ Dieser Browser unterstützt keinen Ordner-Export. Nutze ZIP-Export.",
            exportNoEntries: "❌ Kein entschlüsselter Inhalt zum Exportieren.",
            integrityCloud: "✅ INTEGRITÄTS-CHECK: OK. Tresor geöffnet (NEON2 Cloud-Mode).",
            integrityNeon2: "✅ INTEGRITÄTS-CHECK: OK. Tresor geöffnet (NEON2).",
            integrityLegacy: "✅ INTEGRITÄTS-CHECK: OK. Tresor geöffnet (Legacy).",
            previewDownload: "Laden",
            autoLockTriggered: "🔒 Auto-Lock: Passwort und Vorschau wurden wegen Inaktivität gelöscht.",
            networkDisabled: "Netzwerkzugriff ist in diesem Build deaktiviert.",
            securityReportTitle: "Schutzbericht",
            reportMode: "Modus",
            reportModeLock: "LOCK",
            reportModeUnlock: "UNLOCK",
            reportProfile: "Profil",
            reportKdf: "KDF",
            reportLayers: "Layer",
            reportKeyfile: "Keyfile",
            reportLegacy: "Legacy",
            reportYes: "Ja",
            reportNo: "Nein",
            reportAad: "Header-AAD",
            reportCloud: "Cloud-Hash",
            reportRecovery: "Recovery",
            reportActive: "Aktiv",
            reportEmpty: "Noch kein Sicherheitsbericht verfügbar."
        },
        en: {
            headerSubtitle: "Open Source on GitHub | Built by a solo developer",
            guideTitle: "📖 Guide & Security",
            guideIntro: "Protect your private files directly on your device, without forced cloud usage.",
            guideB1: "<strong>Encryption:</strong> AES-256-GCM with integrity verification. Tampered data is detected.",
            guideB2: "<strong>LOCK:</strong> Select files, set a strong password, optionally add a keyfile, then create your vault.",
            guideB3: "<strong>UNLOCK:</strong> Load a <code>.neon</code> file, enter password (and keyfile if used), then recover your files securely.",
            guideB4: "<strong>Cloud mode:</strong> For backups with randomized filename, padding, and SHA-256 verification file.",
            guideProfilesTitle: "<strong>Which profile should I choose?</strong>",
            guideP1: "<strong>Balanced:</strong> Daily use, small/medium files, fast.",
            guideP2: "<strong>Hardened:</strong> More protection with good usability.",
            guideP3: "<strong>Fortress:</strong> For sensitive files on modern devices.",
            guideP4: "<strong>Apex-5:</strong> Very high protection, clearly slower.",
            guideP5: "<strong>Quantum-8:</strong> Maximum hardness (very slow), only for highly sensitive data.",
            guideBestPractice: "<strong>Best practice:</strong> Use a long password (at least 16+ chars) and enable a keyfile for important data.",
            guideAlert: "⚠️ IMPORTANT: Without the correct password (and keyfile, if enabled), recovery is not possible.",
            guidePrivacy: "<strong>Privacy:</strong> Encryption and decryption happen in your browser. You decide where generated files are stored.",
            filesTitle: "01_SELECT FILES",
            dropText: "Drag files or folders here, or click",
            pickFilesBtn: "Choose files",
            pickFolderBtn: "Choose folder",
            noFiles: "No files loaded.",
            filesReadySuffix: "file(s) ready",
            securityTitle: "02_SECURITY KEY",
            passPlaceholder: "Your master password...",
            keyfileLabel: "📂 Use a keyfile as 2nd factor (optional)",
            keyfileDropTitle: "[DROP KEYFILE HERE]",
            keyfileDropSub: "Use image, MP3 or any file as key",
            genKeyfileBtn: "🔑 Generate local keyfile",
            downloadKeyfileBtn: "⬇ Download keyfile",
            genKeyfileHint: "Creates a random keyfile locally on your device.",
            profileLabel: "🔐 Security profile (for new LOCK files)",
            profileBalanced: "Balanced | PBKDF2-SHA256 | 600k | 1 layer",
            profileHardened: "Hardened | PBKDF2-SHA512 | 1.2M | 1 layer",
            profileFortress: "Fortress | PBKDF2-SHA512 | 1.5M | 2 layers",
            profileApex: "Apex-5 | PBKDF2-SHA512 | 1.9M | 5 layers",
            profileQuantum: "Quantum-8 | PBKDF2-SHA512 | 2.3M | 8 layers",
            cloudLabel: "☁️ Cloud mode (Zero-Knowledge): random filename, padding, integrity hash",
            cloudHintOn: "Cloud mode active: Fortress + required keyfile + SHA-256 upload verification.",
            cloudHintOff: "For cloud backups without plaintext leakage. Keyfile recommended.",
            cloudPadLabel: "Cloud padding block size",
            cloudPad1: "1 MB",
            cloudPad4: "4 MB",
            cloudPad8: "8 MB",
            cloudChaffLabel: "Cloud stealth mode: add random decoy files",
            requireKeyfileLabel: "Require keyfile for LOCK (recommended for sensitive data)",
            recoveryToggleLabel: "🔁 Allow recovery without keyfile (2nd password + security questions)",
            recoveryPassLabel: "Recovery password (different from master password)",
            recoveryPassPlaceholder: "Recovery password...",
            recoveryCountLabel: "Number of security questions (1-5)",
            recoveryCount1: "1 question",
            recoveryCount2: "2 questions",
            recoveryCount3: "3 questions",
            recoveryCount4: "4 questions",
            recoveryCount5: "5 questions",
            recoveryQ1: "Question 1",
            recoveryQ2: "Question 2",
            recoveryQ3: "Question 3",
            recoveryQ4: "Question 4",
            recoveryQ5: "Question 5",
            recoveryA1: "Answer 1",
            recoveryA2: "Answer 2",
            recoveryA3: "Answer 3",
            recoveryA4: "Answer 4",
            recoveryA5: "Answer 5",
            recoveryNote: "UNLOCK without keyfile works only if every answer is exactly correct.",
            clearSecretLabel: "Auto-clear password after each action",
            autoLockLabel: "Auto-lock on inactivity",
            autoLockOff: "Off",
            autoLock5: "5 minutes",
            autoLock10: "10 minutes",
            autoLock30: "30 minutes",
            autoLockHint: "Auto-lock clears password and preview after inactivity.",
            ecoModeLabel: "🧠 Eco mode: adaptive RAM-saving processing",
            ecoModeHint: "Automatically reduces batch sizes on weaker devices.",
            lockBtn: "🔒 LOCK (.neon)",
            unlockBtn: "🔓 UNLOCK",
            versionText: "Version: 1.8 (Current)",
            footerText: "I'm a solo developer and constantly improving this website. If you find issues or have ideas, contact me:",
            copyrightText: "© 2025 Neon-Shield Project. 100% privacy focused.",
            profileHintBalanced: "Fast and strong. Good default for normal usage.",
            profileHintHardened: "Higher brute-force cost, but noticeably slower on older devices.",
            profileHintFortress: "Maximum local hardness: high KDF cost + double AES-GCM encryption.",
            profileHintApex: "Extreme profile: 5 AES-GCM layers + stronger KDF mixing. Much slower, harder to brute force.",
            profileHintQuantum: "Quantum hardening: 8 AES-GCM layers + multi-stage KDF mixing. Very slow, maximum hardness.",
            trustContextError: "Insecure context (no HTTPS).",
            blockedContext: "❌ BLOCKED: Crypto functions are only allowed in a secure context.",
            errorNoPassword: "❌ Error: Password missing!",
            errorNoFiles: "❌ Error: No files selected!",
            errorKeyfileMissing: "❌ Error: Keyfile enabled, but no file selected!",
            errorFolderUnsupported: "❌ This browser does not support folder selection. Use drag & drop or a Chromium browser.",
            errorCloudNeedsKeyfile: "❌ Cloud mode requires a keyfile.",
            errorRequireKeyfile: "❌ LOCK blocked: This setting requires a keyfile.",
            errorRecoveryNeedsKeyfile: "❌ Recovery can only be created with an active keyfile.",
            errorRecoveryNeedsPass: "❌ Recovery enabled: Please set a recovery password.",
            errorRecoveryNeedsQuestions: "❌ Recovery enabled: Please provide 1-5 complete question/answer pairs.",
            errorRecoveryAnswerMissing: "❌ Recovery UNLOCK: Please enter all required answers.",
            errorRecoverySamePassword: "❌ Recovery password must be different from the master password.",
            recoveryPromptReady: "ℹ️ Recovery available: Enter recovery password and answers.",
            errorNoGeneratedKeyfile: "❌ No generated keyfile is available yet.",
            errorPasswordShort: "❌ LOCK blocked: Use at least 10 password characters.",
            errorUnlockSingle: "❌ For UNLOCK, please select exactly one .neon file.",
            weakConfirm: "Password looks weak. Continue anyway?",
            weakAbort: "⚠️ Aborted: Please choose a stronger password.",
            cryptoError: "❌ ERROR / INTEGRITY CHECK FAILED!\n(Wrong password/keyfile or damaged file)",
            unexpectedError: "❌ Unexpected error. Please reload the page and try again.",
            keyfileLoaded: "✅ Keyfile loaded:",
            keyfileGenerated: "✅ Keyfile generated locally and loaded:",
            keyfileGeneratedReady: "✅ Keyfile created. Click “Download keyfile” now.",
            doneCloud: "✅ DONE:",
            doneCloudSuffix: "+ SHA-256 hash exported (Cloud mode).",
            doneLock: "✅ DONE:",
            doneLockSuffix: "saved. Profile:",
            doneCloudMultiSuffix: "parts + SHA-256 hashes exported (Cloud mode).",
            doneLockMultiSuffix: "parts saved. Profile:",
            lockBatchRunning: "⏳ LOCK running: part",
            lockBatchOf: "of",
            lockManifestReady: "Manifest saved:",
            progressIdle: "Ready.",
            progressLock: "LOCK progress",
            progressUnlock: "UNLOCK progress",
            progressExportZip: "ZIP export",
            progressExportFolder: "Folder export",
            previewActionsTitle: "03_EXPORT",
            downloadAllZipBtn: "⬇ Download all as ZIP",
            saveFolderBtn: "📁 Save folder structure",
            exportHint: "Large exports are automatically split into multiple ZIP files.",
            unlockNoVaultFiles: "❌ No .neon file selected for UNLOCK.",
            unlockNeedsParts: "❌ Invalid part selection. Please select matching .partXXX-of-YYY.neon files.",
            unlockMissingParts: "⚠️ Missing parts detected:",
            unlockMissingPartsAsk: "Missing parts detected. Decrypt only available parts?",
            unlockPartialChosen: "⚠️ Continuing in partial mode. Missing parts are skipped.",
            unlockPartFailed: "Part could not be decrypted",
            unlockHashMismatch: "Integrity error (SHA-256) in part",
            unlockDoneMulti: "✅ Multi-part UNLOCK finished.",
            unlockSummaryLine: "Decrypted parts",
            summaryFiles: "Files",
            summarySize: "Total size",
            summaryFailedParts: "Failed parts",
            summaryMissingParts: "Missing parts",
            zipDone: "✅ ZIP export complete.",
            folderDone: "✅ Folder export complete.",
            folderApiMissing: "❌ This browser does not support folder export. Use ZIP export.",
            exportNoEntries: "❌ No decrypted content available for export.",
            integrityCloud: "✅ INTEGRITY CHECK: OK. Vault opened (NEON2 Cloud mode).",
            integrityNeon2: "✅ INTEGRITY CHECK: OK. Vault opened (NEON2).",
            integrityLegacy: "✅ INTEGRITY CHECK: OK. Vault opened (Legacy).",
            previewDownload: "Download",
            autoLockTriggered: "🔒 Auto-lock: Password and previews were cleared due to inactivity.",
            networkDisabled: "Network access is disabled in this build.",
            securityReportTitle: "Security Report",
            reportMode: "Mode",
            reportModeLock: "LOCK",
            reportModeUnlock: "UNLOCK",
            reportProfile: "Profile",
            reportKdf: "KDF",
            reportLayers: "Layers",
            reportKeyfile: "Keyfile",
            reportLegacy: "Legacy",
            reportYes: "Yes",
            reportNo: "No",
            reportAad: "Header-AAD",
            reportCloud: "Cloud hash",
            reportRecovery: "Recovery",
            reportActive: "Active",
            reportEmpty: "No security report yet."
        }
    };

    function t(key) {
        const table = I18N[currentLang] || I18N.de;
        return table[key] || key;
    }

    function setSecurityReport(lines) {
        if (!securityReportEl) return;
        const normalized = Array.isArray(lines) ? lines : [];
        securityReportEl.textContent = normalized.length > 0 ? normalized.join("\n") : t("reportEmpty");
    }

    function getYesNoLabel(flag) {
        return flag ? t("reportYes") : t("reportNo");
    }

    function updateFileInfo() {
        if (!fileInfo) return;
        if (currentFiles.length > 0) {
            const previewNames = currentFiles
                .slice(0, 6)
                .map((f) => f.vaultPath || f.name);
            const suffix = currentFiles.length > 6 ? ", …" : "";
            const totalBytes = currentFiles.reduce((sum, file) => sum + getFileSizeSafe(file), 0);
            const cfg = getAdaptiveBatchConfig(currentFiles);
            const estimatedParts = estimateBatchCount(currentFiles, cfg);
            const partLabel = currentLang === "en" ? "parts" : "Teile";
            fileInfo.innerText =
                currentFiles.length + " " + t("filesReadySuffix") +
                " | " + formatBytes(totalBytes) +
                " | ~" + estimatedParts + " " + partLabel +
                ": " + previewNames.join(", ") + suffix;
            fileInfo.style.color = "var(--neon)";
            return;
        }
        fileInfo.innerText = t("noFiles");
        fileInfo.style.color = "inherit";
    }

    function updateKeyfileStatus() {
        const nameEl = document.getElementById('keyfile-name');
        if (!nameEl) return;
        if (!keyfileDisplayName) {
            nameEl.innerText = "";
            return;
        }
        nameEl.innerText = t("keyfileLoaded") + " " + keyfileDisplayName;
    }

    function updateDownloadKeyfileButton() {
        if (!downloadKeyfileButton) return;
        downloadKeyfileButton.style.display = generatedKeyfileBytes ? "block" : "none";
    }

    function normalizeVaultPath(path, fallbackName) {
        const raw = typeof path === "string" ? path : "";
        const normalized = raw
            .replace(/\\/g, "/")
            .replace(/^\/+/, "")
            .replace(/\/{2,}/g, "/")
            .trim();
        return normalized || fallbackName;
    }

    function normalizeFilesWithVaultPath(files) {
        return Array.from(files || []).map((file) => {
            const sourcePath = file.webkitRelativePath || file.vaultPath || file.name;
            file.vaultPath = normalizeVaultPath(sourcePath, file.name);
            return file;
        });
    }

    function readDirectoryEntries(reader) {
        return new Promise((resolve, reject) => {
            reader.readEntries(resolve, reject);
        });
    }

    async function readAllDirectoryEntries(directoryEntry) {
        const reader = directoryEntry.createReader();
        const out = [];
        while (true) {
            const entries = await readDirectoryEntries(reader);
            if (!entries || entries.length === 0) break;
            out.push(...entries);
        }
        return out;
    }

    function readFileFromEntry(fileEntry) {
        return new Promise((resolve, reject) => {
            fileEntry.file(resolve, reject);
        });
    }

    async function collectFilesFromEntry(entry) {
        if (!entry) return [];
        if (entry.isFile) {
            const file = await readFileFromEntry(entry);
            file.vaultPath = normalizeVaultPath(entry.fullPath || file.webkitRelativePath || file.name, file.name);
            return [file];
        }
        if (!entry.isDirectory) return [];

        const children = await readAllDirectoryEntries(entry);
        const nested = [];
        for (const child of children) {
            nested.push(...await collectFilesFromEntry(child));
        }
        return nested;
    }

    async function collectFilesFromHandle(handle, basePath = "") {
        if (!handle) return [];
        if (handle.kind === "file") {
            const file = await handle.getFile();
            const fullPath = normalizeVaultPath(basePath + "/" + file.name, file.name);
            file.vaultPath = fullPath;
            return [file];
        }
        if (handle.kind !== "directory") return [];

        const nested = [];
        for await (const [name, child] of handle.entries()) {
            const childBase = normalizeVaultPath(basePath + "/" + name, name);
            if (child.kind === "file") {
                const file = await child.getFile();
                file.vaultPath = childBase;
                nested.push(file);
                continue;
            }
            nested.push(...await collectFilesFromHandle(child, childBase));
        }
        return nested;
    }

    async function collectFilesFromDrop(dataTransfer) {
        if (!dataTransfer) return [];

        const items = Array.from(dataTransfer.items || []);
        const itemEntries = items
            .map((item) => typeof item.webkitGetAsEntry === "function" ? item.webkitGetAsEntry() : null)
            .filter(Boolean);

        if (itemEntries.length > 0) {
            const out = [];
            for (const entry of itemEntries) {
                out.push(...await collectFilesFromEntry(entry));
            }
            return normalizeFilesWithVaultPath(out);
        }

        // Fallback for browsers that expose FileSystemHandle on drag items.
        if (items.length > 0 && typeof items[0].getAsFileSystemHandle === "function") {
            const handles = await Promise.all(items.map(async (item) => {
                try {
                    return await item.getAsFileSystemHandle();
                } catch {
                    return null;
                }
            }));
            const out = [];
            for (const handle of handles.filter(Boolean)) {
                out.push(...await collectFilesFromHandle(handle, ""));
            }
            if (out.length > 0) {
                return normalizeFilesWithVaultPath(out);
            }
        }

        return normalizeFilesWithVaultPath(dataTransfer.files || []);
    }

    function supportsDirectoryInput() {
        const probe = document.createElement("input");
        probe.type = "file";
        return "webkitdirectory" in probe || "directory" in probe || "mozdirectory" in probe;
    }

    function showFolderUnsupportedMessage() {
        const log = document.getElementById('log');
        if (log) {
            log.innerText = t("errorFolderUnsupported");
            log.style.color = "var(--warning)";
        }
    }

    function createDirectoryInputElement() {
        const input = document.createElement("input");
        input.type = "file";
        input.multiple = true;
        input.style.position = "fixed";
        input.style.left = "-9999px";
        input.style.top = "-9999px";
        input.setAttribute("webkitdirectory", "");
        input.setAttribute("directory", "");
        input.setAttribute("mozdirectory", "");
        try { input.webkitdirectory = true; } catch {}
        try { input.directory = true; } catch {}
        try { input.mozdirectory = true; } catch {}
        document.body.appendChild(input);
        return input;
    }

    function hasFolderHierarchy(files) {
        return Array.from(files || []).some((file) => {
            const path = file.webkitRelativePath || file.vaultPath || "";
            return String(path).includes("/");
        });
    }

    function handleFolderSelection(files) {
        const normalized = normalizeFilesWithVaultPath(files);
        if (!hasFolderHierarchy(normalized)) {
            showFolderUnsupportedMessage();
            return;
        }
        handleFiles(normalized);
    }

    async function openFolderPicker() {
        resetInactivityTimer();

        if (typeof window.showDirectoryPicker === "function") {
            try {
                const handle = await window.showDirectoryPicker({ mode: "read" });
                const files = await collectFilesFromHandle(handle, handle.name || "");
                if (files.length > 0) {
                    handleFiles(files);
                }
                return;
            } catch (error) {
                if (error && error.name === "AbortError") return;
                console.error(error);
            }
        }

        if (supportsDirectoryInput()) {
            const tempInput = createDirectoryInputElement();
            const cleanup = () => tempInput.remove();

            tempInput.addEventListener("change", (event) => {
                const files = event.target.files;
                if (!files || files.length === 0) {
                    cleanup();
                    return;
                }
                handleFolderSelection(files);
                cleanup();
            }, { once: true });

            try {
                tempInput.click();
            } catch (error) {
                cleanup();
                if (error && error.name === "AbortError") return;
                console.error(error);
                showFolderUnsupportedMessage();
            }
            return;
        }

        showFolderUnsupportedMessage();
    }

    function toBase64(bytes) {
        let binary = "";
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
            binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
        }
        return btoa(binary);
    }

    function fromBase64(text) {
        const binary = atob(text);
        const out = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
        return out;
    }

    function normalizeSecretText(value) {
        return String(value || "").trim();
    }

    function getRecoveryQuestionInput(index) {
        return document.getElementById("recovery-q" + index);
    }

    function getRecoveryAnswerInput(index) {
        return document.getElementById("recovery-a" + index);
    }

    function updateRecoveryRowsVisibility() {
        const count = Math.min(5, Math.max(1, Number(recoveryCountSelect.value || 3)));
        for (let i = 1; i <= 5; i++) {
            const row = document.getElementById("recovery-row-" + i);
            if (!row) continue;
            row.classList.toggle("hidden", i > count);
        }
    }

    function toggleRecoveryPanel() {
        recoveryPanel.classList.toggle("active", recoveryToggle.checked);
    }

    function collectRecoveryPairsForLock() {
        const count = Math.min(5, Math.max(1, Number(recoveryCountSelect.value || 3)));
        const pairs = [];
        for (let i = 1; i <= count; i++) {
            const q = normalizeSecretText(getRecoveryQuestionInput(i)?.value);
            const a = normalizeSecretText(getRecoveryAnswerInput(i)?.value);
            if (!q || !a) return null;
            pairs.push({ q, a });
        }
        return pairs.length > 0 ? pairs : null;
    }

    function collectRecoveryAnswersForUnlock(questions) {
        const answers = [];
        for (let i = 0; i < questions.length; i++) {
            const answer = normalizeSecretText(getRecoveryAnswerInput(i + 1)?.value);
            if (!answer) return null;
            answers.push(answer);
        }
        return answers;
    }

    async function deriveRecoveryKey(recoveryPassword, questions, answers, salt, iterations) {
        const encoder = new TextEncoder();
        const pairs = questions.map((question, index) => {
            return "[" + (index + 1) + "]" + normalizeSecretText(question) + "=" + normalizeSecretText(answers[index] || "");
        }).join("|");
        const seed = concatUint8(
            encoder.encode("NEON-RECOVERY|"),
            encoder.encode(normalizeSecretText(recoveryPassword)),
            encoder.encode("|"),
            encoder.encode(pairs)
        );
        const material = await crypto.subtle.importKey("raw", seed, "PBKDF2", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt, iterations, hash: "SHA-512" },
            material,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function buildRecoveryPackage(recoveryPassword, pairs, keyDigest) {
        const salt = randomBytes(16);
        const iv = randomBytes(12);
        const iterations = 700000;
        const questions = pairs.map((pair) => pair.q);
        const answers = pairs.map((pair) => pair.a);
        const key = await deriveRecoveryKey(recoveryPassword, questions, answers, salt, iterations);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, keyDigest));
        return {
            v: 1,
            iter: iterations,
            hash: "SHA-512",
            q: questions,
            salt: toBase64(salt),
            iv: toBase64(iv),
            ct: toBase64(ciphertext)
        };
    }

    async function tryRecoverKeyDigest(recoveryMeta) {
        const recoveryPassword = normalizeSecretText(recoveryPassInput.value);
        if (!recoveryPassword) {
            throw new Error(t("errorRecoveryNeedsPass"));
        }
        const questions = Array.isArray(recoveryMeta.q) ? recoveryMeta.q : [];
        const answers = collectRecoveryAnswersForUnlock(questions);
        if (!answers) {
            throw new Error(t("errorRecoveryAnswerMissing"));
        }
        const salt = fromBase64(recoveryMeta.salt);
        const iv = fromBase64(recoveryMeta.iv);
        const ciphertext = fromBase64(recoveryMeta.ct);
        const iterations = Number.isInteger(recoveryMeta.iter) ? recoveryMeta.iter : 700000;
        const key = await deriveRecoveryKey(recoveryPassword, questions, answers, salt, iterations);
        return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
    }

    function getCloudPadUnitBytes() {
        const mb = Math.max(1, Math.min(8, Number(cloudPadSelect.value || 1)));
        return mb * 1024 * 1024;
    }

    async function generateLocalKeyfile() {
        const bytes = randomBytes(1024 * 1024);
        const ts = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
        const filename = "neon-keyfile-" + ts + ".bin";
        generatedKeyfileBytes = bytes;
        generatedKeyfileName = filename;
        updateDownloadKeyfileButton();
        keyfileBytes = bytes;
        keyfileDisplayName = filename;
        if (!keyfileToggle.checked) {
            keyfileToggle.checked = true;
            toggleKeyfileUI();
        }
        updateKeyfileStatus();
        const log = document.getElementById('log');
        log.innerText = t("keyfileGeneratedReady");
        log.style.color = "var(--success)";
    }

    function setRecoveryQuestionReadOnly(flag, count = 5) {
        for (let i = 1; i <= 5; i++) {
            const input = getRecoveryQuestionInput(i);
            if (!input) continue;
            input.readOnly = flag && i <= count;
        }
    }

    function applyRecoveryMetaToUi(recoveryMeta) {
        if (!recoveryMeta || !Array.isArray(recoveryMeta.q) || recoveryMeta.q.length === 0) {
            setRecoveryQuestionReadOnly(false, 0);
            return;
        }
        const count = Math.min(5, recoveryMeta.q.length);
        recoveryToggle.checked = true;
        toggleRecoveryPanel();
        recoveryCountSelect.value = String(count);
        updateRecoveryRowsVisibility();
        for (let i = 1; i <= count; i++) {
            const qInput = getRecoveryQuestionInput(i);
            if (qInput) qInput.value = recoveryMeta.q[i - 1];
        }
        setRecoveryQuestionReadOnly(true, count);
    }

    async function getRecoveryMetaFromFile(file) {
        if (!file) return null;
        const fullData = new Uint8Array(await file.arrayBuffer());
        if (!startsWithMagic(fullData)) return null;
        const parsed = parseV2Envelope(fullData);
        return parsed?.header?.recovery || null;
    }

    function wipePreviewUrls() {
        while (previewObjectUrls.length > 0) {
            const url = previewObjectUrls.pop();
            URL.revokeObjectURL(url);
        }
    }

    function clearPreviewGrid() {
        const previewGrid = document.getElementById('previews');
        if (!previewGrid) return;
        wipePreviewUrls();
        previewGrid.innerHTML = "";
        unlockedEntries = [];
        lastUnlockMeta = null;
        if (previewActions) previewActions.style.display = "none";
        if (previewSummary) previewSummary.textContent = "";
    }

    function formatBytes(value) {
        const num = Number(value);
        if (!Number.isFinite(num) || num <= 0) return "0 B";
        const units = ["B", "KB", "MB", "GB", "TB"];
        let size = num;
        let idx = 0;
        while (size >= 1024 && idx < units.length - 1) {
            size /= 1024;
            idx++;
        }
        const digits = size >= 100 ? 0 : size >= 10 ? 1 : 2;
        return size.toFixed(digits) + " " + units[idx];
    }

    function setProgress(active, percent, text) {
        if (progressFill) {
            const value = Math.max(0, Math.min(100, Number(percent) || 0));
            progressFill.style.width = value + "%";
        }
        if (progressText) {
            progressText.dataset.active = active ? "1" : "";
            progressText.textContent = text || t("progressIdle");
        }
    }

    function resetProgress() {
        setProgress(false, 0, t("progressIdle"));
    }

    function showPreviewActions(entries, meta) {
        unlockedEntries = Array.isArray(entries) ? entries : [];
        lastUnlockMeta = meta || null;
        if (!previewActions || !previewSummary) return;
        if (unlockedEntries.length === 0) {
            previewActions.style.display = "none";
            previewSummary.textContent = "";
            return;
        }
        const totalBytes = unlockedEntries.reduce((sum, entry) => sum + (entry?.data?.length || 0), 0);
        const summaryLines = [
            t("summaryFiles") + ": " + unlockedEntries.length,
            t("summarySize") + ": " + formatBytes(totalBytes)
        ];
        if (meta && Number.isInteger(meta.successParts) && Number.isInteger(meta.totalParts)) {
            summaryLines.push(t("unlockSummaryLine") + ": " + meta.successParts + "/" + meta.totalParts);
        }
        if (meta && Array.isArray(meta.failedParts) && meta.failedParts.length > 0) {
            summaryLines.push(t("summaryFailedParts") + ": " + meta.failedParts.join(", "));
        }
        if (meta && Array.isArray(meta.missingParts) && meta.missingParts.length > 0) {
            summaryLines.push(t("summaryMissingParts") + ": " + meta.missingParts.join(", "));
        }
        previewSummary.textContent = summaryLines.join("\n");
        previewActions.style.display = "block";
    }

    function wipeKeyfileBytes() {
        if (keyfileBytes instanceof Uint8Array) {
            keyfileBytes.fill(0);
        }
        keyfileBytes = null;
    }

    function clearSensitiveUiState(reasonKey) {
        passInput.value = "";
        updatePasswordStrength();
        clearPreviewGrid();
        resetProgress();
        if (reasonKey) {
            const log = document.getElementById('log');
            if (log) {
                log.innerText = t(reasonKey);
                log.style.color = "var(--caution)";
            }
        }
    }

    function resetInactivityTimer() {
        if (inactivityTimer) {
            clearTimeout(inactivityTimer);
            inactivityTimer = null;
        }
        const minutes = Number(autoLockSelect.value || 0);
        if (!Number.isFinite(minutes) || minutes <= 0) return;
        inactivityTimer = setTimeout(() => {
            clearSensitiveUiState("autoLockTriggered");
        }, minutes * 60 * 1000);
    }

    function updateAutoLockWatchers() {
        ACTIVITY_EVENTS.forEach((eventName) => {
            window.removeEventListener(eventName, resetInactivityTimer);
        });
        const enabled = Number(autoLockSelect.value || 0) > 0;
        if (!enabled) {
            if (inactivityTimer) {
                clearTimeout(inactivityTimer);
                inactivityTimer = null;
            }
            return;
        }
        ACTIVITY_EVENTS.forEach((eventName) => {
            window.addEventListener(eventName, resetInactivityTimer, { passive: true });
        });
        resetInactivityTimer();
    }

    function setLockSecurityReport(profile, cloudModeEnabled) {
        setSecurityReport([
            t("securityReportTitle"),
            t("reportMode") + ": " + t("reportModeLock"),
            t("reportProfile") + ": " + profile.label,
            t("reportKdf") + ": PBKDF2-" + profile.hash + " / " + profile.iterations,
            t("reportLayers") + ": " + profile.layers,
            t("reportKeyfile") + ": " + getYesNoLabel(Boolean(keyfileToggle.checked && keyfileBytes)),
            t("reportAad") + ": " + t("reportActive"),
            t("reportCloud") + ": " + getYesNoLabel(cloudModeEnabled),
            t("reportRecovery") + ": " + getYesNoLabel(recoveryToggle.checked)
        ]);
    }

    function setUnlockSecurityReport(useV2, header, keyfileWasUsed) {
        if (useV2 && header) {
            const hash = typeof header.kdf?.hash === "string" ? header.kdf.hash : "SHA-256";
            const iterations = Number.isInteger(header.kdf?.iterations) ? header.kdf.iterations : LEGACY_KDF.iterations;
            const layers = Number.isInteger(header.layers) ? header.layers : 1;
            setSecurityReport([
                t("securityReportTitle"),
                t("reportMode") + ": " + t("reportModeUnlock"),
                t("reportProfile") + ": NEON2",
                t("reportKdf") + ": PBKDF2-" + hash + " / " + iterations,
                t("reportLayers") + ": " + layers,
                t("reportKeyfile") + ": " + getYesNoLabel(keyfileWasUsed),
                t("reportAad") + ": " + (header.aad === 1 ? t("reportActive") : t("reportNo")),
                t("reportCloud") + ": " + getYesNoLabel(header.cloud === 1),
                t("reportRecovery") + ": " + getYesNoLabel(Boolean(header.recovery))
            ]);
            return;
        }

        setSecurityReport([
            t("securityReportTitle"),
            t("reportMode") + ": " + t("reportModeUnlock"),
            t("reportProfile") + ": " + t("reportLegacy"),
            t("reportKdf") + ": PBKDF2-" + LEGACY_KDF.hash + " / " + LEGACY_KDF.iterations,
            t("reportLayers") + ": 1",
            t("reportKeyfile") + ": " + getYesNoLabel(keyfileWasUsed),
            t("reportAad") + ": " + t("reportNo"),
            t("reportCloud") + ": " + t("reportNo"),
            t("reportRecovery") + ": " + t("reportNo")
        ]);
    }

    function applyStaticTranslations() {
        document.getElementById("header-subtitle").textContent = t("headerSubtitle");
        document.getElementById("guide-title").textContent = t("guideTitle");
        document.getElementById("guide-intro").textContent = t("guideIntro");
        document.getElementById("guide-b1").innerHTML = t("guideB1");
        document.getElementById("guide-b2").innerHTML = t("guideB2");
        document.getElementById("guide-b3").innerHTML = t("guideB3");
        document.getElementById("guide-b4").innerHTML = t("guideB4");
        document.getElementById("guide-profiles-title").innerHTML = t("guideProfilesTitle");
        document.getElementById("guide-p1").innerHTML = t("guideP1");
        document.getElementById("guide-p2").innerHTML = t("guideP2");
        document.getElementById("guide-p3").innerHTML = t("guideP3");
        document.getElementById("guide-p4").innerHTML = t("guideP4");
        document.getElementById("guide-p5").innerHTML = t("guideP5");
        document.getElementById("guide-best-practice").innerHTML = t("guideBestPractice");
        document.getElementById("guide-alert").textContent = t("guideAlert");
        document.getElementById("guide-privacy").innerHTML = t("guidePrivacy");
        document.getElementById("files-title").textContent = t("filesTitle");
        document.getElementById("drop-text").textContent = t("dropText");
        document.getElementById("pick-files-btn").textContent = t("pickFilesBtn");
        document.getElementById("pick-folder-btn").textContent = t("pickFolderBtn");
        document.getElementById("security-title").textContent = t("securityTitle");
        passInput.placeholder = t("passPlaceholder");
        document.getElementById("keyfile-label").textContent = t("keyfileLabel");
        document.getElementById("keyfile-drop-title").textContent = t("keyfileDropTitle");
        document.getElementById("keyfile-drop-sub").textContent = t("keyfileDropSub");
        document.getElementById("gen-keyfile-btn").textContent = t("genKeyfileBtn");
        document.getElementById("download-keyfile-btn").textContent = t("downloadKeyfileBtn");
        document.getElementById("gen-keyfile-hint").textContent = t("genKeyfileHint");
        document.getElementById("profile-label").textContent = t("profileLabel");
        document.getElementById("profile-balanced").textContent = t("profileBalanced");
        document.getElementById("profile-hardened").textContent = t("profileHardened");
        document.getElementById("profile-fortress").textContent = t("profileFortress");
        document.getElementById("profile-apex").textContent = t("profileApex");
        document.getElementById("profile-quantum").textContent = t("profileQuantum");
        document.getElementById("cloud-label").textContent = t("cloudLabel");
        document.getElementById("cloud-pad-label").textContent = t("cloudPadLabel");
        document.getElementById("cloud-pad-1").textContent = t("cloudPad1");
        document.getElementById("cloud-pad-4").textContent = t("cloudPad4");
        document.getElementById("cloud-pad-8").textContent = t("cloudPad8");
        document.getElementById("cloud-chaff-label").textContent = t("cloudChaffLabel");
        document.getElementById("require-keyfile-label").textContent = t("requireKeyfileLabel");
        document.getElementById("recovery-toggle-label").textContent = t("recoveryToggleLabel");
        document.getElementById("recovery-pass-label").textContent = t("recoveryPassLabel");
        document.getElementById("recovery-count-label").textContent = t("recoveryCountLabel");
        recoveryPassInput.placeholder = t("recoveryPassPlaceholder");
        document.querySelector("#recovery-count option[value='1']").textContent = t("recoveryCount1");
        document.querySelector("#recovery-count option[value='2']").textContent = t("recoveryCount2");
        document.querySelector("#recovery-count option[value='3']").textContent = t("recoveryCount3");
        document.querySelector("#recovery-count option[value='4']").textContent = t("recoveryCount4");
        document.querySelector("#recovery-count option[value='5']").textContent = t("recoveryCount5");
        document.getElementById("recovery-q1").placeholder = t("recoveryQ1");
        document.getElementById("recovery-q2").placeholder = t("recoveryQ2");
        document.getElementById("recovery-q3").placeholder = t("recoveryQ3");
        document.getElementById("recovery-q4").placeholder = t("recoveryQ4");
        document.getElementById("recovery-q5").placeholder = t("recoveryQ5");
        document.getElementById("recovery-a1").placeholder = t("recoveryA1");
        document.getElementById("recovery-a2").placeholder = t("recoveryA2");
        document.getElementById("recovery-a3").placeholder = t("recoveryA3");
        document.getElementById("recovery-a4").placeholder = t("recoveryA4");
        document.getElementById("recovery-a5").placeholder = t("recoveryA5");
        document.getElementById("recovery-note").textContent = t("recoveryNote");
        document.getElementById("clear-secret-label").textContent = t("clearSecretLabel");
        document.getElementById("auto-lock-label").textContent = t("autoLockLabel");
        document.getElementById("auto-lock-off").textContent = t("autoLockOff");
        document.getElementById("auto-lock-5").textContent = t("autoLock5");
        document.getElementById("auto-lock-10").textContent = t("autoLock10");
        document.getElementById("auto-lock-30").textContent = t("autoLock30");
        document.getElementById("auto-lock-hint").textContent = t("autoLockHint");
        document.getElementById("eco-mode-label").textContent = t("ecoModeLabel");
        document.getElementById("eco-mode-hint").textContent = t("ecoModeHint");
        lockButton.textContent = t("lockBtn");
        unlockButton.textContent = t("unlockBtn");
        document.getElementById("preview-actions-title").textContent = t("previewActionsTitle");
        downloadAllZipButton.textContent = t("downloadAllZipBtn");
        saveFolderButton.textContent = t("saveFolderBtn");
        document.getElementById("export-hint").textContent = t("exportHint");
        document.getElementById("version-text").textContent = t("versionText");
        document.getElementById("footer-text").textContent = t("footerText");
        document.getElementById("copyright-text").textContent = t("copyrightText");
        document.title = currentLang === "en"
            ? "NEON-SHIELD V1.8 | Military-grade data vault"
            : "NEON-SHIELD V1.8 | Militärischer Datentresor";
    }

    function setLanguage(lang) {
        currentLang = lang === "en" ? "en" : "de";
        localStorage.setItem("neon-lang", currentLang);
        document.documentElement.lang = currentLang;
        document.getElementById("lang-de").classList.toggle("active", currentLang === "de");
        document.getElementById("lang-en").classList.toggle("active", currentLang === "en");
        applyStaticTranslations();
        updateRecoveryRowsVisibility();
        toggleRecoveryPanel();
        updateProfileHint();
        updateFileInfo();
        updateKeyfileStatus();
        updateDownloadKeyfileButton();
        document.querySelectorAll("#previews a").forEach((link) => {
            link.textContent = t("previewDownload");
        });
        if (progressText && !progressText.dataset.active) {
            progressText.textContent = t("progressIdle");
        }
        setSecurityReport([]);
        if (Array.isArray(unlockedEntries) && unlockedEntries.length > 0) {
            showPreviewActions(unlockedEntries, lastUnlockMeta);
        }
        const ctx = evaluateTrustedContext();
        trustState.ok = ctx.ok;
        trustState.reason = ctx.reason;
    }

    function evaluateTrustedContext() {
        const protocol = window.location.protocol;
        const localFile = protocol === "file:";
        const secureWeb = protocol === "https:" && window.isSecureContext;
        if (localFile || secureWeb) return { ok: true, reason: "" };
        return {
            ok: false,
            reason: t("trustContextError")
        };
    }

    function lockDownNetworkApis() {
        const createNetworkError = () => new Error(t("networkDisabled"));

        try {
            if (typeof window.fetch === "function") {
                window.fetch = async function () { throw createNetworkError(); };
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
                xhrProto.open = function () { throw createNetworkError(); };
                xhrProto.send = function () { throw createNetworkError(); };
            }
        } catch {}

        try {
            if (typeof window.WebSocket === "function") {
                window.WebSocket = function () { throw createNetworkError(); };
            }
        } catch {}

        try {
            if (typeof window.EventSource === "function") {
                window.EventSource = function () { throw createNetworkError(); };
            }
        } catch {}

        try {
            if (typeof window.RTCPeerConnection === "function") {
                window.RTCPeerConnection = function () { throw createNetworkError(); };
            }
        } catch {}
    }

    function applyRuntimeSecurityGuards() {
        lockDownNetworkApis();
        const ctx = evaluateTrustedContext();
        trustState.ok = ctx.ok;
        trustState.reason = ctx.reason;
    }

    function assertTrustedContext(logEl) {
        if (trustState.ok) return true;
        logEl.innerText = t("blockedContext") + " " + trustState.reason;
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
        profileHint.innerText = t(profile.hintKey || "profileHintBalanced");
        cloudModeHint.innerText = getCloudModeEnabled() ? t("cloudHintOn") : t("cloudHintOff");
    }

    function toggleCloudMode() {
        if (getCloudModeEnabled()) {
            profileSelect.value = "fortress";
            profileSelect.disabled = true;
            if (!keyfileToggle.checked) {
                keyfileToggle.checked = true;
                toggleKeyfileUI();
            }
            keyfileToggle.disabled = true;
            requireKeyfileToggle.checked = true;
            requireKeyfileToggle.disabled = true;
            cloudPadSelect.disabled = false;
            cloudChaffToggle.disabled = false;
        } else {
            profileSelect.disabled = false;
            keyfileToggle.disabled = false;
            requireKeyfileToggle.disabled = false;
            cloudPadSelect.disabled = true;
            cloudChaffToggle.disabled = true;
        }
        updateProfileHint();
    }

    applyRuntimeSecurityGuards();
    initCryptoWorker();

    document.getElementById("lang-de").addEventListener("click", () => setLanguage("de"));
    document.getElementById("lang-en").addEventListener("click", () => setLanguage("en"));
    passInput.addEventListener('input', () => {
        updatePasswordStrength();
        resetInactivityTimer();
    });
    profileSelect.addEventListener('change', updateProfileHint);
    cloudModeToggle.addEventListener('change', toggleCloudMode);
    keyfileToggle.addEventListener('change', () => {
        toggleKeyfileUI();
        resetInactivityTimer();
    });
    recoveryToggle.addEventListener('change', () => {
        toggleRecoveryPanel();
        resetInactivityTimer();
    });
    recoveryCountSelect.addEventListener('change', () => {
        updateRecoveryRowsVisibility();
        resetInactivityTimer();
    });
    cloudPadSelect.addEventListener('change', resetInactivityTimer);
    cloudChaffToggle.addEventListener('change', resetInactivityTimer);
    ecoModeToggle.addEventListener('change', () => {
        updateFileInfo();
        resetInactivityTimer();
    });
    recoveryPassInput.addEventListener('input', resetInactivityTimer);
    for (let i = 1; i <= 5; i++) {
        getRecoveryQuestionInput(i).addEventListener('input', resetInactivityTimer);
        getRecoveryAnswerInput(i).addEventListener('input', resetInactivityTimer);
    }
    autoLockSelect.addEventListener('change', updateAutoLockWatchers);
    passToggle.addEventListener('click', togglePass);
    lockButton.addEventListener('click', () => process('lock'));
    unlockButton.addEventListener('click', () => process('unlock'));
    downloadAllZipButton.addEventListener('click', () => {
        exportUnlockedAsZip().catch((error) => {
            console.error(error);
            const log = document.getElementById('log');
            log.innerText = t("unexpectedError");
            log.style.color = "var(--warning)";
        });
    });
    saveFolderButton.addEventListener('click', () => {
        exportUnlockedToFolder().catch((error) => {
            console.error(error);
            const log = document.getElementById('log');
            log.innerText = t("unexpectedError");
            log.style.color = "var(--warning)";
        });
    });
    genKeyfileButton.addEventListener('click', () => {
        generateLocalKeyfile().catch((error) => {
            console.error(error);
            const log = document.getElementById('log');
            log.innerText = t("unexpectedError");
            log.style.color = "var(--warning)";
        });
    });
    downloadKeyfileButton.addEventListener('click', () => {
        const log = document.getElementById('log');
        if (!generatedKeyfileBytes || !generatedKeyfileName) {
            log.innerText = t("errorNoGeneratedKeyfile");
            log.style.color = "var(--warning)";
            return;
        }
        downloadBlob(new Blob([generatedKeyfileBytes], { type: "application/octet-stream" }), generatedKeyfileName);
        log.innerText = t("keyfileGenerated") + " " + generatedKeyfileName;
        log.style.color = "var(--success)";
    });
    pickFilesButton.addEventListener('click', () => fileInput.click());
    pickFolderButton.addEventListener('click', () => {
        openFolderPicker().catch((error) => {
            console.error(error);
            const log = document.getElementById('log');
            log.innerText = t("unexpectedError");
            log.style.color = "var(--warning)";
        });
    });
    setLanguage(localStorage.getItem("neon-lang") || "de");
    updatePasswordStrength();
    updateDownloadKeyfileButton();
    updateRecoveryRowsVisibility();
    toggleRecoveryPanel();
    toggleCloudMode();
    updateAutoLockWatchers();
    resetProgress();

    window.addEventListener("error", () => {
        const log = document.getElementById('log');
        if (!log) return;
        log.innerText = t("unexpectedError");
        log.style.color = "var(--warning)";
    });
    window.addEventListener("unhandledrejection", (event) => {
        console.error(event.reason);
        const log = document.getElementById('log');
        if (log) {
            log.innerText = t("unexpectedError");
            log.style.color = "var(--warning)";
        }
        event.preventDefault();
    });

    function toggleKeyfileUI() {
        if (keyfileToggle.checked) {
            keyfileDrop.classList.add('active');
        } else {
            keyfileDrop.classList.remove('active');
            wipeKeyfileBytes();
            keyfileDisplayName = "";
            keyfileInput.value = "";
            updateKeyfileStatus();
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
        keyfileDisplayName = file.name;
        updateKeyfileStatus();
        resetInactivityTimer();
    }

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach((e) => {
        dropArea.addEventListener(e, (evt) => {
            evt.preventDefault();
            evt.stopPropagation();
        }, false);
    });
    dropArea.addEventListener('dragover', () => dropArea.classList.add('dragover'));
    dropArea.addEventListener('dragleave', () => dropArea.classList.remove('dragover'));
    dropArea.addEventListener('drop', async (e) => {
        dropArea.classList.remove('dragover');
        try {
            const droppedFiles = await collectFilesFromDrop(e.dataTransfer);
            handleFiles(droppedFiles);
        } catch (error) {
            console.error(error);
            const log = document.getElementById('log');
            log.innerText = t("unexpectedError");
            log.style.color = "var(--warning)";
        }
    });
    dropArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
        e.target.value = "";
    });
    folderInput.addEventListener('change', (e) => {
        handleFolderSelection(e.target.files);
        e.target.value = "";
    });

    function handleFiles(files) {
        currentFiles = normalizeFilesWithVaultPath(files);
        if (currentFiles.length !== 1) {
            setRecoveryQuestionReadOnly(false, 0);
        }
        updateFileInfo();
        resetInactivityTimer();
    }

    function pickFirstVaultFile(files) {
        const list = Array.isArray(files) ? files : [];
        const neon = list.find((file) => typeof file?.name === "string" && file.name.toLowerCase().endsWith(".neon"));
        return neon || null;
    }

    async function process(action) {
        const pw = passInput.value;
        const log = document.getElementById('log');
        const useKeyfile = keyfileToggle.checked;
        const cloudMode = getCloudModeEnabled();
        let recoveryPairs = null;

        if (!assertTrustedContext(log)) return;

        if (!pw) {
            log.innerText = t("errorNoPassword");
            log.style.color = "var(--warning)";
            return;
        }
        if (currentFiles.length === 0) {
            log.innerText = t("errorNoFiles");
            log.style.color = "var(--warning)";
            return;
        }
        if (action === 'lock') {
            setRecoveryQuestionReadOnly(false, 0);
        }
        if (action === 'unlock') {
            const firstVault = pickFirstVaultFile(currentFiles);
            if (!firstVault) {
                log.innerText = t("unlockNoVaultFiles");
                log.style.color = "var(--warning)";
                return;
            }
            try {
                const recoveryMeta = await getRecoveryMetaFromFile(firstVault);
                if (recoveryMeta) {
                    applyRecoveryMetaToUi(recoveryMeta);
                    log.innerText = t("recoveryPromptReady");
                    log.style.color = "var(--caution)";
                }
            } catch (error) {
                console.error(error);
            }
        }
        if (action === 'lock' && useKeyfile && !keyfileBytes) {
            log.innerText = t("errorKeyfileMissing");
            log.style.color = "var(--warning)";
            return;
        }
        if (action === 'lock' && cloudMode && (!useKeyfile || !keyfileBytes)) {
            log.innerText = t("errorCloudNeedsKeyfile");
            log.style.color = "var(--warning)";
            return;
        }
        if (action === 'lock' && requireKeyfileToggle.checked && !keyfileBytes) {
            log.innerText = t("errorRequireKeyfile");
            log.style.color = "var(--warning)";
            return;
        }
        if (action === 'lock' && recoveryToggle.checked) {
            if (!useKeyfile || !keyfileBytes) {
                log.innerText = t("errorRecoveryNeedsKeyfile");
                log.style.color = "var(--warning)";
                return;
            }
            const recoveryPassword = normalizeSecretText(recoveryPassInput.value);
            if (!recoveryPassword) {
                log.innerText = t("errorRecoveryNeedsPass");
                log.style.color = "var(--warning)";
                return;
            }
            if (recoveryPassword === pw) {
                log.innerText = t("errorRecoverySamePassword");
                log.style.color = "var(--warning)";
                return;
            }
            recoveryPairs = collectRecoveryPairsForLock();
            if (!recoveryPairs) {
                log.innerText = t("errorRecoveryNeedsQuestions");
                log.style.color = "var(--warning)";
                return;
            }
        }

        if (action === 'lock') {
            if (pw.length < 10) {
                log.innerText = t("errorPasswordShort");
                log.style.color = "var(--warning)";
                return;
            }
            if (calculatePasswordScore(pw) < 60) {
                const proceed = window.confirm(t("weakConfirm"));
                if (!proceed) {
                    log.innerText = t("weakAbort");
                    log.style.color = "var(--caution)";
                    return;
                }
            }
        }

        resetInactivityTimer();
        overlay.style.display = 'flex';
        setTimeout(async () => {
            try {
                if (action === 'lock') {
                    await lock(pw, recoveryPairs);
                } else {
                    await unlock(pw);
                }
            } catch (e) {
                console.error(e);
                const message = typeof e?.message === "string" ? e.message : "";
                log.innerText = message.startsWith("❌") ? message : t("cryptoError");
                log.style.color = "var(--warning)";
                setSecurityReport([]);
            } finally {
                overlay.style.display = 'none';
                if (clearSecretToggle.checked) {
                    passInput.value = "";
                    updatePasswordStrength();
                }
                if (progressText && progressText.dataset.active) {
                    resetProgress();
                }
                resetInactivityTimer();
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
            throw new Error("Defekter Datenblock: Uint32 außerhalb der Datei.");
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

    function initCryptoWorker() {
        if (typeof Worker !== "function") return;
        try {
            const worker = new Worker("./crypto-worker.js");
            worker.onmessage = (event) => {
                const data = event.data || {};
                const entry = cryptoWorkerState.pending.get(data.id);
                if (!entry) return;
                cryptoWorkerState.pending.delete(data.id);
                if (data.ok) {
                    entry.resolve(data.payload);
                } else {
                    entry.reject(new Error(data.error || "Worker request failed."));
                }
            };
            worker.onerror = () => {
                cryptoWorkerState.ready = false;
                for (const [, entry] of cryptoWorkerState.pending) {
                    entry.reject(new Error("Crypto worker failed."));
                }
                cryptoWorkerState.pending.clear();
            };
            cryptoWorkerState.worker = worker;
            cryptoWorkerState.ready = true;
        } catch (error) {
            console.warn("Crypto worker unavailable, using main thread.", error);
            cryptoWorkerState.ready = false;
            cryptoWorkerState.worker = null;
        }
    }

    function runCryptoWorkerTask(type, payload, transferList) {
        if (!cryptoWorkerState.ready || !cryptoWorkerState.worker) {
            throw new Error("worker-not-ready");
        }
        return new Promise((resolve, reject) => {
            const id = ++cryptoWorkerState.seq;
            cryptoWorkerState.pending.set(id, { resolve, reject });
            try {
                cryptoWorkerState.worker.postMessage(
                    { id: id, type: type, payload: payload },
                    Array.isArray(transferList) ? transferList : []
                );
            } catch (error) {
                cryptoWorkerState.pending.delete(id);
                reject(error);
            }
        });
    }

    async function digestBytes(algorithm, bytes) {
        const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || 0);
        if (cryptoWorkerState.ready && input.length <= (8 * 1024 * 1024)) {
            try {
                const outBuffer = await runCryptoWorkerTask(
                    "digest",
                    { algorithm: algorithm, data: input.buffer },
                    []
                );
                return new Uint8Array(outBuffer);
            } catch {
                cryptoWorkerState.ready = false;
            }
        }
        return new Uint8Array(await crypto.subtle.digest(algorithm, input));
    }

    async function encryptPayloadLayers(payload, pw, keyBytesForLock, profile, envelopeHeader) {
        const input = payload instanceof Uint8Array ? payload : new Uint8Array(payload || 0);
        if (cryptoWorkerState.ready) {
            try {
                const outBuffer = await runCryptoWorkerTask(
                    "encryptLayers",
                    {
                        payload: input.buffer,
                        password: pw,
                        keyBytes: keyBytesForLock ? keyBytesForLock.buffer : null,
                        recoveredDigest: null,
                        profile: {
                            iterations: profile.iterations,
                            hash: profile.hash,
                            layers: profile.layers,
                            keyMaterialVersion: profile.keyMaterialVersion || 2
                        },
                        headerBytes: envelopeHeader.buffer
                    },
                    []
                );
                return new Uint8Array(outBuffer);
            } catch {
                cryptoWorkerState.ready = false;
            }
        }

        let out = input;
        for (let layer = 1; layer <= profile.layers; layer++) {
            const salt = randomBytes(16);
            const iv = randomBytes(12);
            const key = await deriveAesKey(
                pw,
                keyBytesForLock,
                salt,
                profile,
                "layer-" + layer,
                "encrypt",
                profile.keyMaterialVersion || 2
            );
            const aad = buildLayerAad(envelopeHeader, layer);
            const encrypted = new Uint8Array(await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv, additionalData: aad },
                key,
                out
            ));
            out = concatUint8(salt, iv, encrypted);
        }
        return out;
    }

    async function decryptPayloadLayers(parsed, password, keyBytes) {
        const input = parsed.payload;
        const recoveryDigest = recoveredKeyDigestOverride instanceof Uint8Array ? recoveredKeyDigestOverride : null;
        if (cryptoWorkerState.ready) {
            try {
                const outBuffer = await runCryptoWorkerTask(
                    "decryptLayers",
                    {
                        payload: input.buffer,
                        password: password,
                        keyBytes: keyBytes ? keyBytes.buffer : null,
                        recoveredDigest: recoveryDigest ? recoveryDigest.buffer : null,
                        header: parsed.header,
                        headerBytes: parsed.headerBytes.buffer
                    },
                    []
                );
                return new Uint8Array(outBuffer);
            } catch {
                cryptoWorkerState.ready = false;
            }
        }

        const kdf = parsed.header.kdf;
        const useAad = parsed.header.aad === 1;
        let payload = input;
        for (let layer = parsed.header.layers; layer >= 1; layer--) {
            if (payload.length < 29) {
                throw new Error("Defekte NEON2-Datei: Layer " + layer + " zu kurz.");
            }
            const salt = payload.slice(0, 16);
            const iv = payload.slice(16, 28);
            const encrypted = payload.slice(28);
            const key = await deriveAesKey(password, keyBytes, salt, kdf, "layer-" + layer, "decrypt", parsed.header.km);
            const params = useAad
                ? { name: "AES-GCM", iv: iv, additionalData: buildLayerAad(parsed.headerBytes, layer) }
                : { name: "AES-GCM", iv: iv };
            payload = new Uint8Array(await crypto.subtle.decrypt(params, key, encrypted));
        }
        return payload;
    }

    function generateVaultFilename(cloudModeEnabled) {
        if (!cloudModeEnabled) return "tresor.neon";
        const ts = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
        const rand = toHex(crypto.getRandomValues(new Uint8Array(4)));
        return "vault-" + ts + "-" + rand + ".neon";
    }

    function getFileSizeSafe(file) {
        const size = Number(file?.size);
        return Number.isFinite(size) && size >= 0 ? size : 0;
    }

    function getAdaptiveBatchConfig(files) {
        const source = Array.isArray(files) ? files : [];
        const totalBytes = source.reduce((sum, file) => sum + getFileSizeSafe(file), 0);
        let maxBytes = MAX_LOCK_BATCH_BYTES;
        let maxFiles = MAX_LOCK_BATCH_FILES;
        const ecoEnabled = Boolean(ecoModeToggle && ecoModeToggle.checked);
        const deviceMemory = Number(navigator?.deviceMemory || 0);

        if (ecoEnabled) {
            if (Number.isFinite(deviceMemory) && deviceMemory > 0 && deviceMemory <= 4) {
                maxBytes = 16 * 1024 * 1024;
                maxFiles = 40;
            } else if (Number.isFinite(deviceMemory) && deviceMemory > 0 && deviceMemory <= 8) {
                maxBytes = 24 * 1024 * 1024;
                maxFiles = 60;
            }
            if (source.length >= 300) {
                maxFiles = Math.min(maxFiles, 50);
            }
            if (totalBytes >= (1024 * 1024 * 1024)) {
                maxBytes = Math.min(maxBytes, 24 * 1024 * 1024);
            }
        }

        return { maxBytes: maxBytes, maxFiles: maxFiles };
    }

    function estimateBatchCount(files, config) {
        const batches = splitFilesIntoLockBatches(files, config);
        return Math.max(1, batches.length);
    }

    function splitFilesIntoLockBatches(files, config) {
        const source = Array.isArray(files) ? files : [];
        const cfg = config || getAdaptiveBatchConfig(source);
        const maxBytes = Math.max(1, Number(cfg.maxBytes) || MAX_LOCK_BATCH_BYTES);
        const maxFiles = Math.max(1, Number(cfg.maxFiles) || MAX_LOCK_BATCH_FILES);
        const batches = [];
        let batch = [];
        let batchBytes = 0;

        for (const file of source) {
            const fileBytes = getFileSizeSafe(file);
            const exceedsBytes = batch.length > 0 && (batchBytes + fileBytes) > maxBytes;
            const exceedsFiles = batch.length >= maxFiles;
            if (exceedsBytes || exceedsFiles) {
                batches.push(batch);
                batch = [];
                batchBytes = 0;
            }
            batch.push(file);
            batchBytes += fileBytes;
        }

        if (batch.length > 0) {
            batches.push(batch);
        }
        return batches;
    }

    function buildVaultPartFilename(baseName, partIndex, partCount) {
        if (partCount <= 1) return baseName;
        const part = String(partIndex).padStart(3, "0");
        const total = String(partCount).padStart(3, "0");
        if (baseName.toLowerCase().endsWith(".neon")) {
            return baseName.slice(0, -5) + ".part" + part + "-of-" + total + ".neon";
        }
        return baseName + ".part" + part + "-of-" + total + ".neon";
    }

    function buildManifestFilename(baseName) {
        if (baseName.toLowerCase().endsWith(".neon")) {
            return baseName.slice(0, -5) + ".manifest.json";
        }
        return baseName + ".manifest.json";
    }

    async function buildVaultPayloadForBatch(files, encoder, cloudModeEnabled, addDecoys) {
        const entries = [];
        let totalLength = 0;

        for (const file of files) {
            const expectedSize = getFileSizeSafe(file);
            const filePath = normalizeVaultPath(file.vaultPath || file.webkitRelativePath || file.name, file.name);
            const headerBytes = encoder.encode(JSON.stringify({
                n: filePath,
                t: typeof file.type === "string" ? file.type : "",
                s: expectedSize
            }));
            entries.push({ file: file, headerBytes: headerBytes, expectedSize: expectedSize });
            totalLength += FILE_HEADER_LENGTH_BYTES + headerBytes.length + expectedSize;
        }

        const decoys = [];
        if (cloudModeEnabled && addDecoys) {
            const decoyCount = 1 + (randomBytes(1)[0] % 3);
            for (let i = 0; i < decoyCount; i++) {
                const name = ".mask-" + toHex(randomBytes(6)) + ".bin";
                const sizeSeed = randomBytes(2);
                const decoySize = 4096 + ((sizeSeed[0] << 8) | sizeSeed[1]) % 65536;
                const decoyData = randomBytes(decoySize);
                const decoyHeader = encoder.encode(JSON.stringify({
                    n: name,
                    t: "application/octet-stream",
                    s: decoyData.length,
                    d: 1
                }));
                decoys.push({ headerBytes: decoyHeader, data: decoyData });
                totalLength += FILE_HEADER_LENGTH_BYTES + decoyHeader.length + decoyData.length;
            }
        }

        let payload = new Uint8Array(totalLength);
        let offset = 0;

        for (const entry of entries) {
            payload.set(writeUint32LE(entry.headerBytes.length), offset);
            offset += FILE_HEADER_LENGTH_BYTES;
            payload.set(entry.headerBytes, offset);
            offset += entry.headerBytes.length;

            const content = new Uint8Array(await entry.file.arrayBuffer());
            if (content.length !== entry.expectedSize) {
                throw new Error("Datei wurde waehrend LOCK veraendert. Bitte erneut versuchen.");
            }
            payload.set(content, offset);
            offset += content.length;
        }

        for (const decoy of decoys) {
            payload.set(writeUint32LE(decoy.headerBytes.length), offset);
            offset += FILE_HEADER_LENGTH_BYTES;
            payload.set(decoy.headerBytes, offset);
            offset += decoy.headerBytes.length;
            payload.set(decoy.data, offset);
            offset += decoy.data.length;
        }

        let plainPad = 0;
        if (cloudModeEnabled) {
            const cloudPadUnit = getCloudPadUnitBytes();
            plainPad = (cloudPadUnit - (payload.length % cloudPadUnit)) % cloudPadUnit;
            if (plainPad > 0) {
                const padded = new Uint8Array(payload.length + plainPad);
                padded.set(payload, 0);
                padded.set(randomBytes(plainPad), payload.length);
                payload = padded;
            }
        }

        return { payload: payload, plainPad: plainPad };
    }

    function downloadBlob(blob, filename) {
        const a = document.createElement('a');
        const url = URL.createObjectURL(blob);
        a.href = url;
        a.download = filename;
        a.style.display = "none";
        document.body.appendChild(a);
        a.click();
        a.remove();
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
            : recoveredKeyDigestOverride instanceof Uint8Array
                ? recoveredKeyDigestOverride
                : new Uint8Array(0);
        const seed = concatUint8(encoder.encode("NEON2-KM2|"), passBytes, encoder.encode("|"), keyDigest);
        const material = new Uint8Array(await crypto.subtle.digest("SHA-512", seed));
        return crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
    }

    async function getQuantumKeyMaterial(password, keyBytes) {
        const encoder = new TextEncoder();
        const passBytes = encoder.encode(password);
        const keyDigest = keyBytes
            ? new Uint8Array(await crypto.subtle.digest("SHA-512", keyBytes))
            : recoveredKeyDigestOverride instanceof Uint8Array
                ? recoveredKeyDigestOverride
                : new Uint8Array(0);

        const phase1Seed = concatUint8(encoder.encode("NEON2-QM3|"), passBytes, encoder.encode("|"), keyDigest);
        const phase1 = new Uint8Array(await crypto.subtle.digest("SHA-512", phase1Seed));
        const phase2 = new Uint8Array(await crypto.subtle.digest("SHA-256", concatUint8(phase1, passBytes)));
        const phase3 = new Uint8Array(await crypto.subtle.digest("SHA-512", concatUint8(phase2, keyDigest, phase1)));
        const mixed = concatUint8(phase1, phase2, phase3);
        const finalMaterial = new Uint8Array(await crypto.subtle.digest("SHA-512", mixed));

        return crypto.subtle.importKey("raw", finalMaterial, "PBKDF2", false, ["deriveKey"]);
    }

    function validateKdfConfig(kdf) {
        const isHashAllowed = kdf.hash === "SHA-256" || kdf.hash === "SHA-512";
        const isIterationSafe = Number.isInteger(kdf.iterations) && kdf.iterations >= 100000 && kdf.iterations <= 3000000;
        if (!isHashAllowed || !isIterationSafe) {
            throw new Error("Ungültige KDF-Parameter.");
        }
    }

    async function deriveAesKey(password, keyBytes, salt, kdf, purpose, usage, keyMaterialVersion) {
        validateKdfConfig(kdf);
        const keyMaterial = keyMaterialVersion === 3
            ? await getQuantumKeyMaterial(password, keyBytes)
            : keyMaterialVersion === 2
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

    async function lock(pw, recoveryPairs) {
        const log = document.getElementById('log');
        const encoder = new TextEncoder();
        const cloudMode = getCloudModeEnabled();
        const keyBytesForLock = keyfileToggle.checked ? keyfileBytes : null;
        const selectedProfileKey = cloudMode ? "fortress" : getSelectedProfileKey();
        const profile = SECURITY_PROFILES[selectedProfileKey];
        const batchConfig = getAdaptiveBatchConfig(currentFiles);
        const lockBatches = splitFilesIntoLockBatches(currentFiles, batchConfig);
        const totalParts = lockBatches.length;
        const baseOutName = generateVaultFilename(cloudMode);
        const addDecoys = cloudMode && cloudChaffToggle.checked;
        const manifestParts = [];
        const manifestName = buildManifestFilename(baseOutName);

        let recoveryMeta = null;
        if (Array.isArray(recoveryPairs) && recoveryPairs.length > 0 && keyBytesForLock) {
            const recoveryPassword = normalizeSecretText(recoveryPassInput.value);
            const keyDigest = await digestBytes("SHA-512", keyBytesForLock);
            recoveryMeta = await buildRecoveryPackage(recoveryPassword, recoveryPairs, keyDigest);
        }

        for (let partIndex = 0; partIndex < totalParts; partIndex++) {
            const partNumber = partIndex + 1;
            const percentStart = ((partNumber - 1) / totalParts) * 100;
            const percentDone = (partNumber / totalParts) * 100;
            if (totalParts > 1) {
                log.innerText = t("lockBatchRunning") + " " + partNumber + " " + t("lockBatchOf") + " " + totalParts + "…";
                log.style.color = "var(--caution)";
            }
            setProgress(true, percentStart, t("progressLock") + ": " + partNumber + "/" + totalParts);

            let payloadInfo = await buildVaultPayloadForBatch(lockBatches[partIndex], encoder, cloudMode, addDecoys);
            let payload = payloadInfo.payload;
            const plainPad = payloadInfo.plainPad;

            const envelopeMeta = {
                v: 2,
                kdf: { iterations: profile.iterations, hash: profile.hash },
                layers: profile.layers,
                km: profile.keyMaterialVersion || 2,
                aad: 1,
                padPlain: plainPad
            };
            if (cloudMode) {
                envelopeMeta.cloud = 1;
                envelopeMeta.padUnitMb = Number(cloudPadSelect.value || 1);
                if (cloudChaffToggle.checked) envelopeMeta.chaff = 1;
            }
            if (totalParts > 1) {
                envelopeMeta.part = { i: partNumber, t: totalParts };
            }
            if (recoveryMeta) envelopeMeta.recovery = recoveryMeta;
            const envelopeHeader = encoder.encode(JSON.stringify(envelopeMeta));

            payload = await encryptPayloadLayers(payload, pw, keyBytesForLock, profile, envelopeHeader);

            const outBytes = concatUint8(MAGIC_V2, writeUint32LE(envelopeHeader.length), envelopeHeader, payload);
            const outName = buildVaultPartFilename(baseOutName, partNumber, totalParts);
            downloadBlob(new Blob([outBytes], { type: "application/octet-stream" }), outName);
            const digest = await digestBytes("SHA-256", outBytes);
            const digestHex = toHex(digest);

            if (cloudMode) {
                const hashLine = digestHex + "  " + outName + "\n";
                downloadBlob(new Blob([hashLine], { type: "text/plain" }), outName + ".sha256.txt");
            }

            manifestParts.push({
                index: partNumber,
                name: outName,
                sha256: digestHex,
                files: lockBatches[partIndex].length,
                plainBytes: lockBatches[partIndex].reduce((sum, f) => sum + getFileSizeSafe(f), 0)
            });

            payloadInfo = null;
            payload = new Uint8Array(0);
            setProgress(true, percentDone, t("progressLock") + ": " + partNumber + "/" + totalParts);
            await new Promise((resolve) => setTimeout(resolve, 0));
        }

        if (totalParts > 1) {
            const manifest = {
                kind: "NEON2_MULTI_MANIFEST",
                version: 1,
                createdAt: new Date().toISOString(),
                baseName: baseOutName,
                partsTotal: totalParts,
                cloud: cloudMode ? 1 : 0,
                profile: selectedProfileKey,
                filesTotal: currentFiles.length,
                batch: { maxBytes: batchConfig.maxBytes, maxFiles: batchConfig.maxFiles },
                parts: manifestParts
            };
            const json = JSON.stringify(manifest, null, 2) + "\n";
            downloadBlob(new Blob([json], { type: "application/json" }), manifestName);
        }

        if (cloudMode) {
            if (totalParts > 1) {
                log.innerText = t("doneCloud") + " " + totalParts + " " + t("doneCloudMultiSuffix");
            } else {
                log.innerText = t("doneCloud") + " " + baseOutName + " " + t("doneCloudSuffix");
            }
        } else if (totalParts > 1) {
            log.innerText = t("doneLock") + " " + totalParts + " " + t("doneLockMultiSuffix") + " " + profile.label + " (" + profile.layers + " Layer).";
        } else {
            log.innerText = t("doneLock") + " " + baseOutName + " " + t("doneLockSuffix") + " " + profile.label + " (" + profile.layers + " Layer).";
        }
        if (totalParts > 1) {
            log.innerText += " " + t("lockManifestReady") + " " + manifestName;
        }
        log.style.color = "var(--success)";
        setProgress(false, 100, t("progressIdle"));
        setLockSecurityReport(profile, cloudMode);
    }

    function parseV2Envelope(fullData) {
        let offset = MAGIC_V2.length;
        const headerLength = readUint32LE(fullData, offset);
        offset += FILE_HEADER_LENGTH_BYTES;

        if (headerLength < 2 || offset + headerLength > fullData.length) {
            throw new Error("Defekte NEON2-Datei: Header ungültig.");
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
            throw new Error("Nicht unterstützte NEON-Dateiversion.");
        }
        if (!header.kdf || typeof header.kdf !== "object") {
            throw new Error("Defekte NEON2-Datei: KDF-Daten fehlen.");
        }
        if (!Number.isInteger(header.layers) || header.layers < 1 || header.layers > 8) {
            throw new Error("Defekte NEON2-Datei: Layer-Wert ist ungültig.");
        }
        if (header.km === undefined) header.km = 1;
        if (header.km !== 1 && header.km !== 2 && header.km !== 3) {
            throw new Error("Defekte NEON2-Datei: Key-Material-Version ungültig.");
        }
        if (header.aad !== undefined && header.aad !== 0 && header.aad !== 1) {
            throw new Error("Defekte NEON2-Datei: AAD-Flag ungültig.");
        }
        if (header.padPlain === undefined) header.padPlain = 0;
        if (!Number.isInteger(header.padPlain) || header.padPlain < 0 || header.padPlain > (32 * 1024 * 1024)) {
            throw new Error("Defekte NEON2-Datei: Padding-Wert ungültig.");
        }
        if (header.recovery !== undefined) {
            const recovery = header.recovery;
            const validQuestions = Array.isArray(recovery?.q) && recovery.q.length >= 1 && recovery.q.length <= 5;
            const validStrings = typeof recovery?.salt === "string" && typeof recovery?.iv === "string" && typeof recovery?.ct === "string";
            const validIter = Number.isInteger(recovery?.iter) && recovery.iter >= 100000 && recovery.iter <= 3000000;
            if (!validQuestions || !validStrings || !validIter) {
                throw new Error("Defekte NEON2-Datei: Recovery-Daten ungültig.");
            }
        }
        if (header.part !== undefined) {
            const part = header.part;
            const validPart = Number.isInteger(part?.i) && Number.isInteger(part?.t) && part.i >= 1 && part.t >= 1 && part.i <= part.t;
            if (!validPart) {
                throw new Error("Defekte NEON2-Datei: Part-Daten ungültig.");
            }
        }

        validateKdfConfig(header.kdf);
        return { header: header, headerBytes: headerBytes, payload: fullData.slice(offset) };
    }

    async function decryptLegacy(fullData, password, keyBytes) {
        if (fullData.length < 29) {
            throw new Error("Defekte Legacy-Datei.");
        }

        const salt = fullData.slice(0, 16);
        const iv = fullData.slice(16, 28);
        const encrypted = fullData.slice(28);
        const key = await deriveLegacyKey(password, keyBytes, salt, "decrypt");
        return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encrypted));
    }

    async function decryptV2(fullData, password, keyBytes) {
        const parsed = parseV2Envelope(fullData);

        if (!keyBytes && parsed.header.recovery) {
            recoveredKeyDigestOverride = await tryRecoverKeyDigest(parsed.header.recovery);
        }

        try {
            let payload = await decryptPayloadLayers(parsed, password, keyBytes);

            if (parsed.header.padPlain > payload.length) {
                throw new Error("Defekte NEON2-Datei: Padding größer als Inhalt.");
            }
            if (parsed.header.padPlain > 0) {
                payload = payload.slice(0, payload.length - parsed.header.padPlain);
            }

            return { plaintext: payload, header: parsed.header };
        } finally {
            recoveredKeyDigestOverride = null;
        }
    }

    function parseVaultEntries(decrypted) {
        const entries = [];
        const decoder = new TextDecoder();
        let offset = 0;

        while (offset < decrypted.length) {
            const headerLength = readUint32LE(decrypted, offset);
            offset += FILE_HEADER_LENGTH_BYTES;

            if (headerLength < 2 || offset + headerLength > decrypted.length) {
                throw new Error("Defekter Tresorinhalt: Header außerhalb des Datenbereichs.");
            }

            const headerBytes = decrypted.slice(offset, offset + headerLength);
            offset += headerLength;

            let header;
            try {
                header = JSON.parse(decoder.decode(headerBytes));
            } catch {
                throw new Error("Defekter Tresorinhalt: Datei-Header ist ungültig.");
            }

            const validSize = Number.isInteger(header.s) && header.s >= 0;
            if (!header || typeof header.n !== "string" || !validSize || offset + header.s > decrypted.length) {
                throw new Error("Defekter Tresorinhalt: Datei-Metadaten ungültig.");
            }

            const mimeType = typeof header.t === "string" && header.t ? header.t : "application/octet-stream";
            const fileData = decrypted.slice(offset, offset + header.s);
            offset += header.s;

            if (header.d === 1) {
                continue;
            }
            entries.push({ name: header.n, type: mimeType, data: fileData });
        }

        if (entries.length === 0) {
            throw new Error("Tresor ist leer.");
        }

        return entries;
    }

    function toDownloadFilename(vaultPath) {
        const normalized = normalizeVaultPath(vaultPath, "file.bin");
        return normalized.replace(/[\\/]/g, "__");
    }

    function toZipPath(vaultPath, fallbackName) {
        const normalized = normalizeVaultPath(vaultPath, fallbackName || "file.bin").replace(/\\/g, "/");
        const cleaned = normalized
            .split("/")
            .filter((segment) => segment && segment !== "." && segment !== "..")
            .join("/");
        return cleaned || (fallbackName || "file.bin");
    }

    function renderPreviewItem(previewGrid, entry) {
        const url = URL.createObjectURL(new Blob([entry.data], { type: entry.type }));
        previewObjectUrls.push(url);
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
        link.download = toDownloadFilename(entry.name);
        link.textContent = t("previewDownload");
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

    function parsePartDescriptor(filename) {
        const name = typeof filename === "string" ? filename : "";
        const match = name.match(PART_FILENAME_RE);
        if (!match) return null;
        const index = Number(match[1]);
        const total = Number(match[2]);
        if (!Number.isInteger(index) || !Number.isInteger(total) || index < 1 || total < 1 || index > total) {
            return null;
        }
        return { index: index, total: total };
    }

    function formatPartLabel(index, total) {
        return "part" + String(index).padStart(3, "0") + "-of-" + String(total).padStart(3, "0");
    }

    async function parseManifestFromSelection(files) {
        const candidates = Array.from(files || []).filter((file) => typeof file?.name === "string" && file.name.toLowerCase().endsWith(".json"));
        for (const file of candidates) {
            try {
                const text = await file.text();
                const parsed = JSON.parse(text);
                if (parsed?.kind !== "NEON2_MULTI_MANIFEST") continue;
                if (!Number.isInteger(parsed?.partsTotal) || parsed.partsTotal < 1) continue;
                const parts = Array.isArray(parsed.parts)
                    ? parsed.parts
                        .map((part) => ({
                            index: Number(part?.index),
                            name: typeof part?.name === "string" ? part.name : "",
                            sha256: typeof part?.sha256 === "string" ? part.sha256.toLowerCase() : ""
                        }))
                        .filter((part) => Number.isInteger(part.index) && part.index >= 1 && part.index <= parsed.partsTotal && part.name.length > 0)
                        .sort((a, b) => a.index - b.index)
                    : [];
                if (parts.length === 0) continue;
                return {
                    file: file,
                    partsTotal: parsed.partsTotal,
                    parts: parts
                };
            } catch {}
        }
        return null;
    }

    async function buildUnlockPlan(files) {
        const allFiles = Array.from(files || []);
        const vaultFiles = allFiles.filter((file) => typeof file?.name === "string" && file.name.toLowerCase().endsWith(".neon"));
        if (vaultFiles.length === 0) {
            throw new Error(t("unlockNoVaultFiles"));
        }

        const manifest = await parseManifestFromSelection(allFiles);
        if (manifest) {
            const selectedByName = new Map(vaultFiles.map((file) => [file.name, file]));
            const selectedParts = [];
            const missingParts = [];
            for (const part of manifest.parts) {
                const file = selectedByName.get(part.name);
                if (!file) {
                    missingParts.push(part.name);
                    continue;
                }
                selectedParts.push({
                    file: file,
                    name: part.name,
                    index: part.index,
                    total: manifest.partsTotal,
                    sha256: part.sha256 || ""
                });
            }
            if (selectedParts.length === 0) {
                throw new Error(t("unlockNeedsParts"));
            }
            return {
                mode: manifest.partsTotal > 1 || selectedParts.length > 1 ? "multi" : "single",
                parts: selectedParts.sort((a, b) => a.index - b.index),
                expectedTotal: manifest.partsTotal,
                missingParts: missingParts
            };
        }

        const partDescriptors = vaultFiles.map((file) => ({ file: file, part: parsePartDescriptor(file.name) }));
        const allPartNamed = partDescriptors.every((row) => Boolean(row.part));
        if (allPartNamed && vaultFiles.length > 0) {
            const totals = new Set(partDescriptors.map((row) => row.part.total));
            if (totals.size !== 1) {
                throw new Error(t("unlockNeedsParts"));
            }
            const expectedTotal = partDescriptors[0].part.total;
            const byIndex = new Map();
            for (const row of partDescriptors) {
                if (!byIndex.has(row.part.index)) {
                    byIndex.set(row.part.index, row.file);
                }
            }
            const selectedParts = Array.from(byIndex.entries())
                .sort((a, b) => a[0] - b[0])
                .map(([index, file]) => ({
                    file: file,
                    name: file.name,
                    index: index,
                    total: expectedTotal,
                    sha256: ""
                }));
            const missingParts = [];
            for (let i = 1; i <= expectedTotal; i++) {
                if (!byIndex.has(i)) {
                    missingParts.push(formatPartLabel(i, expectedTotal));
                }
            }
            return {
                mode: expectedTotal > 1 || selectedParts.length > 1 ? "multi" : "single",
                parts: selectedParts,
                expectedTotal: expectedTotal,
                missingParts: missingParts
            };
        }

        if (vaultFiles.length === 1) {
            return {
                mode: "single",
                parts: [{ file: vaultFiles[0], name: vaultFiles[0].name, index: 1, total: 1, sha256: "" }],
                expectedTotal: 1,
                missingParts: []
            };
        }

        return {
            mode: "multi",
            parts: vaultFiles.map((file, index) => ({ file: file, name: file.name, index: index + 1, total: vaultFiles.length, sha256: "" })),
            expectedTotal: vaultFiles.length,
            missingParts: []
        };
    }

    const CRC32_TABLE = (() => {
        const table = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) {
                c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            }
            table[i] = c >>> 0;
        }
        return table;
    })();

    function crc32(bytes) {
        let crc = 0xFFFFFFFF;
        for (let i = 0; i < bytes.length; i++) {
            crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
        }
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    function splitEntriesForZip(entries, maxChunkBytes) {
        const source = Array.isArray(entries) ? entries : [];
        const chunks = [];
        let chunk = [];
        let chunkBytes = 0;
        for (let i = 0; i < source.length; i++) {
            const entry = source[i];
            const nameBytes = new TextEncoder().encode(toZipPath(entry.name, "file-" + i + ".bin"));
            const estimate = (entry?.data?.length || 0) + nameBytes.length + 160;
            if (chunk.length > 0 && (chunkBytes + estimate) > maxChunkBytes) {
                chunks.push(chunk);
                chunk = [];
                chunkBytes = 0;
            }
            chunk.push(entry);
            chunkBytes += estimate;
        }
        if (chunk.length > 0) chunks.push(chunk);
        return chunks;
    }

    function buildStoredZipBlob(entries) {
        const encoder = new TextEncoder();
        const files = entries.map((entry, index) => {
            const name = toZipPath(entry.name, "file-" + index + ".bin");
            const nameBytes = encoder.encode(name);
            const data = entry.data instanceof Uint8Array ? entry.data : new Uint8Array(entry.data || 0);
            return {
                nameBytes: nameBytes,
                data: data,
                crc: crc32(data)
            };
        });

        const localTotal = files.reduce((sum, file) => sum + 30 + file.nameBytes.length + file.data.length, 0);
        const centralTotal = files.reduce((sum, file) => sum + 46 + file.nameBytes.length, 0);
        const totalLength = localTotal + centralTotal + 22;
        const out = new Uint8Array(totalLength);
        const view = new DataView(out.buffer);
        let offset = 0;
        const localOffsets = [];

        for (const file of files) {
            localOffsets.push(offset);
            view.setUint32(offset, 0x04034b50, true); offset += 4;
            view.setUint16(offset, 20, true); offset += 2;
            view.setUint16(offset, 0x0800, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint32(offset, file.crc >>> 0, true); offset += 4;
            view.setUint32(offset, file.data.length >>> 0, true); offset += 4;
            view.setUint32(offset, file.data.length >>> 0, true); offset += 4;
            view.setUint16(offset, file.nameBytes.length, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            out.set(file.nameBytes, offset); offset += file.nameBytes.length;
            out.set(file.data, offset); offset += file.data.length;
        }

        const centralOffset = offset;
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            view.setUint32(offset, 0x02014b50, true); offset += 4;
            view.setUint16(offset, 20, true); offset += 2;
            view.setUint16(offset, 20, true); offset += 2;
            view.setUint16(offset, 0x0800, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint32(offset, file.crc >>> 0, true); offset += 4;
            view.setUint32(offset, file.data.length >>> 0, true); offset += 4;
            view.setUint32(offset, file.data.length >>> 0, true); offset += 4;
            view.setUint16(offset, file.nameBytes.length, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint16(offset, 0, true); offset += 2;
            view.setUint32(offset, 0, true); offset += 4;
            view.setUint32(offset, localOffsets[i], true); offset += 4;
            out.set(file.nameBytes, offset); offset += file.nameBytes.length;
        }

        const centralSize = offset - centralOffset;
        view.setUint32(offset, 0x06054b50, true); offset += 4;
        view.setUint16(offset, 0, true); offset += 2;
        view.setUint16(offset, 0, true); offset += 2;
        view.setUint16(offset, files.length, true); offset += 2;
        view.setUint16(offset, files.length, true); offset += 2;
        view.setUint32(offset, centralSize >>> 0, true); offset += 4;
        view.setUint32(offset, centralOffset >>> 0, true); offset += 4;
        view.setUint16(offset, 0, true); offset += 2;

        return new Blob([out], { type: "application/zip" });
    }

    async function exportUnlockedAsZip() {
        const log = document.getElementById('log');
        if (!Array.isArray(unlockedEntries) || unlockedEntries.length === 0) {
            log.innerText = t("exportNoEntries");
            log.style.color = "var(--warning)";
            return;
        }
        const maxChunk = ecoModeToggle.checked ? Math.min(MAX_ZIP_CHUNK_BYTES, 64 * 1024 * 1024) : MAX_ZIP_CHUNK_BYTES;
        const chunks = splitEntriesForZip(unlockedEntries, maxChunk);
        const total = chunks.length;
        for (let i = 0; i < total; i++) {
            const part = i + 1;
            setProgress(true, (part - 1) / total * 100, t("progressExportZip") + ": " + part + "/" + total);
            const blob = buildStoredZipBlob(chunks[i]);
            const filename = total === 1
                ? "unlock-all.zip"
                : "unlock-all.part" + String(part).padStart(3, "0") + "-of-" + String(total).padStart(3, "0") + ".zip";
            downloadBlob(blob, filename);
            setProgress(true, part / total * 100, t("progressExportZip") + ": " + part + "/" + total);
            await new Promise((resolve) => setTimeout(resolve, 0));
        }
        log.innerText = t("zipDone");
        log.style.color = "var(--success)";
        resetProgress();
    }

    async function getOrCreateNestedDirectory(rootHandle, pathParts) {
        let dir = rootHandle;
        for (const part of pathParts) {
            dir = await dir.getDirectoryHandle(part, { create: true });
        }
        return dir;
    }

    async function exportUnlockedToFolder() {
        const log = document.getElementById('log');
        if (!Array.isArray(unlockedEntries) || unlockedEntries.length === 0) {
            log.innerText = t("exportNoEntries");
            log.style.color = "var(--warning)";
            return;
        }
        if (typeof window.showDirectoryPicker !== "function") {
            log.innerText = t("folderApiMissing");
            log.style.color = "var(--warning)";
            return;
        }

        const root = await window.showDirectoryPicker();
        const total = unlockedEntries.length;
        for (let i = 0; i < total; i++) {
            const entry = unlockedEntries[i];
            const normalized = toZipPath(entry.name, "file-" + (i + 1) + ".bin");
            const parts = normalized.split("/").filter(Boolean);
            const filename = parts.pop() || ("file-" + (i + 1) + ".bin");
            const dir = await getOrCreateNestedDirectory(root, parts);
            const handle = await dir.getFileHandle(filename, { create: true });
            const writable = await handle.createWritable();
            await writable.write(entry.data);
            await writable.close();
            setProgress(true, ((i + 1) / total) * 100, t("progressExportFolder") + ": " + (i + 1) + "/" + total);
            if ((i + 1) % 10 === 0) {
                await new Promise((resolve) => setTimeout(resolve, 0));
            }
        }
        log.innerText = t("folderDone");
        log.style.color = "var(--success)";
        resetProgress();
    }

    async function unlock(pw) {
        const log = document.getElementById('log');
        const previewGrid = document.getElementById('previews');
        clearPreviewGrid();
        const keyBytesForUnlock = keyfileToggle.checked ? keyfileBytes : null;
        const plan = await buildUnlockPlan(currentFiles);

        if (plan.missingParts.length > 0) {
            const missingText = plan.missingParts.join(", ");
            log.innerText = t("unlockMissingParts") + " " + missingText;
            log.style.color = "var(--caution)";
            const proceed = window.confirm(t("unlockMissingPartsAsk") + "\n" + missingText);
            if (!proceed) {
                resetProgress();
                return;
            }
            log.innerText = t("unlockPartialChosen");
            log.style.color = "var(--caution)";
        }

        const allEntries = [];
        const failedParts = [];
        let firstV2Header = null;
        let firstUseV2 = false;
        let successParts = 0;
        const totalParts = Math.max(1, plan.expectedTotal || plan.parts.length);

        for (let i = 0; i < plan.parts.length; i++) {
            const row = plan.parts[i];
            const progressStart = (i / plan.parts.length) * 100;
            const progressDone = ((i + 1) / plan.parts.length) * 100;
            setProgress(true, progressStart, t("progressUnlock") + ": " + (i + 1) + "/" + plan.parts.length);
            try {
                const fullData = new Uint8Array(await row.file.arrayBuffer());
                if (row.sha256) {
                    const digest = await digestBytes("SHA-256", fullData);
                    if (toHex(digest).toLowerCase() !== row.sha256.toLowerCase()) {
                        throw new Error(t("unlockHashMismatch") + ": " + row.name);
                    }
                }

                const useV2 = startsWithMagic(fullData);
                let decrypted;
                let header = null;
                if (useV2) {
                    const parsed = await decryptV2(fullData, pw, keyBytesForUnlock);
                    decrypted = parsed.plaintext;
                    header = parsed.header;
                } else {
                    decrypted = await decryptLegacy(fullData, pw, keyBytesForUnlock);
                }
                const entries = parseVaultEntries(decrypted);
                allEntries.push(...entries);
                successParts += 1;
                if (useV2 && !firstUseV2) {
                    firstUseV2 = true;
                    firstV2Header = header;
                }
            } catch (error) {
                console.error(error);
                failedParts.push(row.name);
            }
            setProgress(true, progressDone, t("progressUnlock") + ": " + (i + 1) + "/" + plan.parts.length);
            await new Promise((resolve) => setTimeout(resolve, 0));
        }

        if (allEntries.length === 0) {
            resetProgress();
            throw new Error(t("cryptoError"));
        }

        for (const entry of allEntries) {
            renderPreviewItem(previewGrid, entry);
        }

        const partial = failedParts.length > 0 || plan.missingParts.length > 0 || successParts < totalParts;
        if (plan.mode === "single" && !partial) {
            if (firstUseV2 && firstV2Header && firstV2Header.cloud === 1) {
                log.innerText = t("integrityCloud");
            } else {
                log.innerText = firstUseV2 ? t("integrityNeon2") : t("integrityLegacy");
            }
            log.style.color = "var(--success)";
        } else {
            const partsInfo = t("unlockSummaryLine") + ": " + successParts + "/" + totalParts;
            const failInfo = failedParts.length > 0 ? (" | " + t("unlockPartFailed") + ": " + failedParts.join(", ")) : "";
            const missingInfo = plan.missingParts.length > 0 ? (" | " + t("unlockMissingParts") + " " + plan.missingParts.join(", ")) : "";
            log.innerText = t("unlockDoneMulti") + " " + partsInfo + failInfo + missingInfo;
            log.style.color = partial ? "var(--caution)" : "var(--success)";
        }

        showPreviewActions(allEntries, {
            successParts: successParts,
            totalParts: totalParts,
            failedParts: failedParts,
            missingParts: plan.missingParts
        });
        setUnlockSecurityReport(firstUseV2, firstV2Header, Boolean(keyBytesForUnlock));
        resetProgress();
    }
