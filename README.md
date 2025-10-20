# 🔐 Secure File System – PyQt5 Desktop Application

Ova aplikacija predstavlja **sigurni sistem za autentifikaciju i upravljanje fajlovima** uz upotrebu digitalnih sertifikata, enkripcije i kontrole pristupa. Projekat je razvijen u **Pythonu** koristeći **PyQt5 GUI framework** i **cryptography biblioteku**.


---

## ⚙️ Funkcionalnosti

### 🧾 Registracija (`register.py`)
- Kreira novog korisnika i upisuje podatke u `users.txt`
- Generiše **par ključeva (javnog i privatnog)** i digitalni sertifikat
- Privatni ključ se enkriptuje pomoću **AES simetrične enkripcije**
- Lozinka se hešira pomoću više hash funkcija (`SHA-256`, `SHA-512`, `BLAKE2b`)

### 🔑 Prijava (`login.py`)
- Autentifikuje korisnika na osnovu:
  - korisničkog imena
  - lozinke (heš provjera)
  - putanje do digitalnog sertifikata
- Provjerava:
  - ispravnost sertifikata (datum važenja)
  - da sertifikat nije opozvan (CRL)
  - uspješno dešifrovanje privatnog ključa
- Svaka akcija se bilježi u **audit_log.txt** fajl

### 🗂️ Secure File System (`secureFileSystem.py`)
- Omogućava rad s fajlovima nakon prijave:
  - čitanje, pisanje i brisanje fajlova
  - sigurnu enkripciju i dekripciju podataka
- Svi podaci su dostupni samo prijavljenom korisniku

### 💾 Baza podataka (`database.py`)
- Implementira mehanizme za čuvanje i čitanje korisničkih podataka iz `users.txt`
- Može se lako proširiti na SQLite bazu u budućim verzijama

---

## 🧠 Sigurnosni mehanizmi

| Mehanizam | Opis |
|------------|------|
| **Hashing** | Lozinke se čuvaju u heširanom obliku pomoću SHA-256, SHA-512 i BLAKE2b |
| **AES enkripcija** | Privatni ključevi se čuvaju enkriptovani pomoću AES (CBC mod) |
| **Digitalni sertifikati** | Autentifikacija korisnika zasnovana na X.509 sertifikatima |
| **CRL (Certificate Revocation List)** | Sertifikati koji su opozvani čuvaju se u `crl/` folderu |
| **Audit log** | Sve akcije (pokušaji prijave, greške, uspjesi) bilježe se u `audit_log.txt` |



