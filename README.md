# metode-DSA
# Tugas Kriptografi: Implementasi DSA (From Scratch)

Repositori ini berisi implementasi algoritma **DSA (Digital Signature Algorithm)** asimetris yang dibangun murni dari awal (*from scratch*) menggunakan JavaScript. Program ini tidak menggunakan *library* kriptografi instan bawaan apa pun dan mendemonstrasikan logika matematika di balik pembuatan parameter global, pembangkitan kunci (*Key Generation*), penandatanganan (*Signing*), dan verifikasi tanda tangan (*Verification*).

Implementasi ini dibuat untuk memenuhi Tugas Mata Kuliah **Keamanan Data dan Informasi**.

---

## Fitur Utama

- **Tanpa Library Eksternal:** Seluruh kalkulasi matematika (`gcd`, `modInverse`, `modExp`, `simpleHash`) ditulis secara manual.
- **Dukungan BigInt:** Menggunakan tipe data `BigInt` asli bawaan JavaScript untuk mencegah eror presisi atau limitasi memori saat menghitung eksponensial modular yang sangat besar.
- **Parameter Generator Dinamis:** Membangkitkan parameter domain `(p, q, g)` secara otomatis dan acak setiap kali program dijalankan, sesuai dengan standar DSA.
- **Uji Integritas Pesan:** Program mendemonstrasikan dua skenario — verifikasi tanda tangan pada pesan **asli** (valid) dan pada pesan yang **dipalsukan** (tidak valid) — sehingga terlihat jelas bagaimana DSA mendeteksi manipulasi data.

---

## Cara Menjalankan Program

Program ini dieksekusi melalui *Command Line Interface (CLI)* menggunakan Node.js. Berikut adalah langkah-langkah untuk menjalankannya:

### 1. Prasyarat (Prerequisites)

Pastikan komputer Anda sudah terinstal **Node.js**. Anda bisa mengunduh dan menginstalnya melalui [situs resmi Node.js](https://nodejs.org/).

Untuk mengecek apakah Node.js sudah terinstal, buka terminal/Command Prompt dan ketik:

```bash
node -v
```

### 2. Persiapan File

Unduh file `dsa-from-scratch.js` dari repositori ini, atau salin seluruh source code dan simpan ke dalam file baru bernama `dsa-from-scratch.js` di komputer Anda.

Buka **Terminal** (macOS/Linux) atau **Command Prompt / PowerShell** (Windows).

Arahkan direktori terminal ke folder tempat Anda menyimpan file tersebut. Contoh:

```bash
cd letak/folder/penyimpanan/anda/
```

### 3. Eksekusi Program

Jalankan perintah berikut di terminal:

```bash
node dsa-from-scratch.js
```

### 4. Kustomisasi Pesan (Opsional)

Jika Anda ingin mencoba menandatangani dan memverifikasi pesan lain, Anda dapat mengedit file `dsa-from-scratch.js` menggunakan text editor (seperti VS Code, Notepad, dll).

Cari baris kode berikut (di bagian bawah file):

```javascript
// Pesan yang akan ditandatangani
const pesanAsli = "HELLO DSA";
```

Ganti `"HELLO DSA"` dengan pesan apa pun yang Anda inginkan, lalu simpan file dan jalankan ulang perintah `node dsa-from-scratch.js`.

---

## Contoh Output Program

Saat dijalankan, program akan menghasilkan output dinamis di terminal (karena nilai parameter dibangkitkan secara acak). Berikut adalah contoh log yang akan muncul:

```
==========================================
  SIMULASI ALGORITMA DSA (FROM SCRATCH)
==========================================

--- [TAHAP 1] Pembangkitan Parameter Global ---
   -> q (prima kecil)   = 101
   -> p (prima besar)   = 607  [p = 6*q + 1]
   -> g (generator)     = 64

--- [TAHAP 2] Pembangkitan Pasangan Kunci ---
   -> Kunci Privat (x)  = 15
   -> Kunci Publik (y)  = 271

   [!] Kunci Publik  (p, q, g, y) -> dibagikan secara terbuka
   [!] Kunci Privat  (x)          -> RAHASIA, jangan dibagikan!

==========================================
  Pesan yang akan ditandatangani: "HELLO DSA"
==========================================

--- [TAHAP 3] Proses Penandatanganan (Signing) ---
   -> Hash pesan H      = 36
   -> Nilai acak k      = 90  (rahasia, hanya dipakai sekali)
   -> r = (g^k mod p) mod q = 88
   -> s = k^-1 * (H + x*r) mod q = 42

   ✔  Tanda Tangan Digital: (r=88, s=42)

[UJI 1] Verifikasi dengan pesan ASLI: "HELLO DSA"

--- [TAHAP 4] Proses Verifikasi (Verification) ---
   -> Cek syarat 0 < r < q dan 0 < s < q : VALID
   -> Hash pesan H      = 36
   -> w = s^-1 mod q    = 89
   -> u1 = (H * w) mod q = 73
   -> u2 = (r * w) mod q = 55
   -> v = ((g^u1 * y^u2) mod p) mod q = 88

   -> Membandingkan: v (88) == r (88) ?
   ✔  TANDA TANGAN VALID! Pesan asli dan tidak dimanipulasi.

[UJI 2] Verifikasi dengan pesan DIPALSUKAN: "HELLO DSB"

--- [TAHAP 4] Proses Verifikasi (Verification) ---
   -> Cek syarat 0 < r < q dan 0 < s < q : VALID
   -> Hash pesan H      = 37
   -> w = s^-1 mod q    = 89
   -> u1 = (H * w) mod q = 61
   -> u2 = (r * w) mod q = 55
   -> v = ((g^u1 * y^u2) mod p) mod q = 21

   -> Membandingkan: v (21) == r (88) ?
   ✘  TANDA TANGAN TIDAK VALID! Pesan mungkin telah diubah.

==========================================
  Simulasi DSA Selesai!
==========================================
```

---

## Struktur Fungsi

| Fungsi / Class | Deskripsi |
|---|---|
| `gcd(a, b)` | Mencari Faktor Persekutuan Terbesar (FPB) menggunakan algoritma Euclidean. |
| `modInverse(a, m)` | Extended Euclidean Algorithm untuk mencari invers modular. |
| `modExp(base, exp, mod)` | Modular Exponentiation efisien menggunakan metode *square-and-multiply*. |
| `isPrime(num)` | Mengecek keprimaan suatu angka dengan optimasi pola $6k \pm 1$. |
| `generateRandomPrime(min, max)` | Mencari angka prima secara acak dalam batas tertentu. |
| `simpleHash(message)` | Fungsi hash manual berbasis operasi bitwise (simulasi SHA-like). |
| `class DSA` | Mengelola keseluruhan logika DSA: parameter, kunci, signing, dan verification. |
| `generateParameters()` | Membangkitkan parameter domain global `(p, q, g)`. |
| `generateKeys()` | Membangkitkan pasangan kunci privat `x` dan kunci publik `y`. |
| `sign(message)` | Menandatangani pesan dan menghasilkan tanda tangan digital `(r, s)`. |
| `verify(message, signature, publicKey)` | Memverifikasi keaslian tanda tangan menggunakan kunci publik. |

---

## Informasi Mahasiswa

| | |
|---|---|
| **Nama** | Ahmad Arkanul Falah Al Khalimi |
| **NIM** | 24051204033 |
| **Kelas** | TI 2024 A |
| **Mata Kuliah** | Keamanan Data dan Informasi |
| **Algoritma** | DSA (Digital Signature Algorithm) |
