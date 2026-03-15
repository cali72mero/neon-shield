# NEON-SHIELD Web

<p align="center">
  <a href="./index.html"><img alt="App starten" src="https://img.shields.io/badge/App-starten-00f2ff?style=for-the-badge&logo=icloud&logoColor=black"></a>
  <a href="./README_NEON_SHIELD_WEB.md"><img alt="Security Details" src="https://img.shields.io/badge/Security-Details-0f172a?style=for-the-badge&logo=shield&logoColor=white"></a>
  <a href="./app.js"><img alt="Quellcode ansehen" src="https://img.shields.io/badge/Quellcode-JavaScript-111827?style=for-the-badge&logo=javascript&logoColor=f7df1e"></a>
</p>

<p align="center">
  Lokale Dateiverschlüsselung im Browser mit <b>AES-256-GCM</b>, Keyfile-Option, Cloud-Mode und DE/EN-Sprachumschaltung.
</p>

## Schnellstart

1. `index.html` im Browser öffnen.
2. Dateien in die Drop-Zone ziehen.
3. Starkes Passwort setzen (optional Keyfile aktivieren).
4. `LOCK` zum Verschlüsseln oder `UNLOCK` zum Entschlüsseln nutzen.

## Kurz-Anleitung: Welches Profil wann?

- `Balanced`: Für Alltag und schnelle Verarbeitung.
- `Hardened`: Wenn du mehr Schutz willst, aber noch gute Geschwindigkeit brauchst.
- `Fortress`: Für sensible Daten mit starker lokaler Absicherung.
- `Apex-5`: Für sehr sensible Daten, wenn längere Wartezeit okay ist.
- `Quantum-8`: Maximale Härte, sehr langsam, nur für besonders kritische Daten.

Empfohlene Praxis:

- Passwort mit mindestens 16+ Zeichen nutzen.
- Für wichtige Daten zusätzlich Keyfile aktivieren.
- Bei Cloud-Backups immer die `*.sha256.txt` Prüfsumme mit prüfen.

## Was die App kann

- AES-256-GCM mit Integritätsprüfung.
- Sicherheitsprofile: `Balanced`, `Hardened`, `Fortress`, `Apex-5`, `Quantum-8`.
- Optionales Keyfile als zweiter Faktor.
- Lokaler Keyfile-Generator (`🔑 Keyfile lokal generieren`).
- Cloud-Mode mit zufälligem Dateinamen, Padding und `SHA-256`-Prüfdatei.
- Zusätzliche Cloud-Härtung: wählbare Padding-Blockgröße + optionaler Tarnmodus (Decoy-Dateien).
- Ganze Ordner verschlüsseln (Drag & Drop oder `Ordner wählen`).
- Keyfile für `LOCK` erzwingen.
- Optionaler Recovery-Modus ohne Keyfile: 2. Passwort + 1–5 Sicherheitsfragen.
- Passwort nach Aktion automatisch löschen.
- Auto-Lock bei Inaktivität.
- DE/EN direkt in der Oberfläche umschalten.

## Was die App nicht kann

- Kein „Passwort vergessen“: Ohne korrektes Passwort ist keine Wiederherstellung möglich.
- Ohne Keyfile nur dann UNLOCK möglich, wenn Recovery beim LOCK vorher aktiv konfiguriert wurde.
- Kein System ist „100 % unknackbar“.
- Eine Browser-App kann Manipulationen am Endgerät oder unsichere Browser-Umgebungen nicht vollständig verhindern.

## Projektdateien

- `index.html` – Oberfläche und Layout.
- `app.js` – Kryptologik, i18n, Sicherheitsoptionen.
- `README_NEON_SHIELD_WEB.md` – ausführliche Sicherheitsdetails.

## Sicherheits-Hinweis

Für maximalen Schutz: langes Passwort + Keyfile nutzen und bei Cloud-Backups die erzeugte `*.sha256.txt` Datei mitprüfen.
