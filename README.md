# NEON-SHIELD Web (v1.7)

Diese README beschreibt die aktuelle Web-Version (`index.html` + `app.js`): was sie kann, was sie nicht kann und welche Sicherheitsgrenzen wichtig sind.

## Was die Webseite kann

- Dateien lokal im Browser verschlüsseln (`LOCK`) und als `.neon` speichern.
- `.neon`-Dateien lokal entschlüsseln (`UNLOCK`) und Inhalte wieder herunterladen.
- AES-256-GCM mit Integritätsprüfung (manipulierte Daten werden erkannt).
- Sicherheitsprofile:
  - `Balanced`: PBKDF2-SHA256, 600k, 1 Layer
  - `Hardened`: PBKDF2-SHA512, 1.2M, 1 Layer
  - `Fortress`: PBKDF2-SHA512, 1.5M, 2 Layer
- Optional Keyfile als zusätzlicher Faktor (Passwort + Datei).
- Cloud-Mode:
  - random Dateiname
  - Padding gegen grobe Größenleaks
  - SHA-256 Hash-Datei zur Integritätskontrolle
- NEON2-Format für neue Tresore + Legacy-Unterstützung für ältere `.neon`-Dateien.
- CSP/Runtime-Härtung gegen Netzwerkausleitungen (`connect-src 'none'`, gesperrte Netzwerk-APIs).
- Host-Guard: Kryptofunktionen sind nur in erlaubten Kontexten nutzbar (`file://`, `localhost`, `https://*.github.io`).

## Was die Webseite nicht kann

- Kein „100% unknackbar“ garantieren.
- Kein Passwort-Reset oder Wiederherstellung bei verlorenem Passwort.
- Keine echte Hardware-Bindung an Secure Enclave/Keychain (Browser-Grenze).
- Keine forensisch harte Speicherlöschung wie in nativen Sicherheitsanwendungen.
- Kein automatisches Cloud-Sync/Account-System (bewusst lokal/zero-knowledge gehalten).
- Kein eingebautes Argon2id ohne zusätzliche lokale Kryptobibliothek.

## Sicherheitsmodell (kurz)

- Verschlüsselung und Entschlüsselung laufen clientseitig.
- Der Betreiber soll keine Klartextdaten/Passwörter erhalten.
- Trotzdem gilt: Wenn der ausgelieferte Webseiten-Code manipuliert wird, kann Sicherheit unterlaufen werden.

## Praktische Empfehlungen

1. Immer langes, starkes Passwort nutzen.
2. Für wichtige Daten zusätzlich Keyfile aktivieren.
3. Für Upload/Backup in Cloud den Cloud-Mode verwenden.
4. Datei möglichst lokal/offline oder nur auf eigener, vertrauenswürdiger Domain ausführen.
5. `*.sha256.txt` bei Cloud-Backups mitprüfen.

## Dateiformat-Hinweis

- Neu: `NEON2` (versionierter Header, KDF-/Layer-Metadaten, AAD-gebundene Header-Integrität, optional Padding/Cloud-Flag).
- Alt: Legacy-Format wird beim Entschlüsseln weiterhin unterstützt.

