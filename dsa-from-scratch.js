// ==========================================
// TUGAS KRIPTOGRAFI: IMPLEMENTASI DSA (FROM SCRATCH)
// Digital Signature Algorithm
// Nama  : Ahmad Arkanul Falah Al Khalimi
// NIM   : 24051204033
// Kelas : TI 2024 A
// ==========================================

// ==========================================
// 1. Fungsi Bantuan Matematika (Mathematical Helpers)
// ==========================================

// Fungsi Eksponensial Modular (Modular Exponentiation)
// Menghitung (base^exp) % mod secara efisien
// tanpa membuat angka menjadi terlalu raksasa
function modExp(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        // Jika pangkat ganjil, kalikan base dengan result
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        // Geser bit pangkat ke kanan (dibagi 2) dan kuadratkan base
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}

// Fungsi Extended Euclidean Algorithm untuk mencari Invers Modular
// Mencari x sehingga (a * x) % m == 1
function modInverse(a, m) {
    let m0 = m;
    let y = 0n, x = 1n;

    if (m === 1n) return 0n;

    while (a > 1n) {
        let q = a / m;
        let t = m;

        m = a % m;
        a = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0n) x += m0;

    return x;
}

// Fungsi untuk mencari Faktor Persekutuan Terbesar (GCD)
function gcd(a, b) {
    while (b !== 0n) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Fungsi untuk mengecek apakah sebuah BigInt adalah bilangan prima
function isPrime(num) {
    if (num <= 1n) return false;
    if (num <= 3n) return true;
    if (num % 2n === 0n || num % 3n === 0n) return false;

    for (let i = 5n; i * i <= num; i += 6n) {
        if (num % i === 0n || num % (i + 2n) === 0n) {
            return false;
        }
    }
    return true;
}

// Fungsi untuk mencari bilangan prima acak di antara nilai min dan max
function generateRandomPrime(min, max) {
    let prime = 0n;
    while (!isPrime(prime)) {
        let randomNum = Math.floor(Math.random() * (max - min + 1)) + min;
        prime = BigInt(randomNum);
    }
    return prime;
}

// Fungsi Hash sederhana (simulasi SHA-like) yang menghasilkan nilai BigInt
// Catatan: Di dunia nyata, gunakan SHA-256 dari library standar.
// Ini dibuat manual agar sesuai ketentuan "from scratch".
function simpleHash(message) {
    let hash = 0n;
    for (let i = 0; i < message.length; i++) {
        // Operasi bitwise untuk mensimulasikan proses hashing
        hash = (hash * 31n + BigInt(message.charCodeAt(i))) % (2n ** 160n);
    }
    return hash;
}


// ==========================================
// 2. Inti Algoritma DSA
// ==========================================

class DSA {
    constructor() {
        this.p = null; // Bilangan prima besar (domain parameter)
        this.q = null; // Bilangan prima kecil, faktor dari (p-1)
        this.g = null; // Generator
        this.x = null; // Kunci Privat
        this.y = null; // Kunci Publik
    }

    // ----------------------------------------
    // TAHAP 1: Pembangkitan Parameter Global
    // Membangun domain parameters (p, q, g)
    // ----------------------------------------
    generateParameters() {
        console.log("\n--- [TAHAP 1] Pembangkitan Parameter Global ---");

        // Pilih bilangan prima q (kecil, sebagai sub-group order)
        this.q = generateRandomPrime(100, 500);
        console.log(`   -> q (prima kecil)   = ${this.q}`);

        // Cari bilangan prima p sehingga q | (p - 1), yaitu (p-1) % q == 0
        // Caranya: p = k*q + 1, lalu cek apakah p prima
        let k = 2n;
        this.p = k * this.q + 1n;
        while (!isPrime(this.p)) {
            k++;
            this.p = k * this.q + 1n;
        }
        console.log(`   -> p (prima besar)   = ${this.p}  [p = ${k}*q + 1]`);

        // Cari generator g: g = h^((p-1)/q) mod p, di mana g > 1
        // h adalah sembarang bilangan antara 2 dan p-2
        let h = 2n;
        this.g = 1n;
        while (this.g === 1n) {
            this.g = modExp(h, (this.p - 1n) / this.q, this.p);
            h++;
        }
        console.log(`   -> g (generator)     = ${this.g}`);
    }

    // ----------------------------------------
    // TAHAP 2: Pembangkitan Pasangan Kunci
    // Menghasilkan Kunci Privat (x) dan Kunci Publik (y)
    // ----------------------------------------
    generateKeys() {
        console.log("\n--- [TAHAP 2] Pembangkitan Pasangan Kunci ---");

        // Kunci Privat x: bilangan acak dengan syarat 0 < x < q
        const xRaw = BigInt(Math.floor(Math.random() * (Number(this.q) - 2)) + 1);
        this.x = xRaw;
        console.log(`   -> Kunci Privat (x)  = ${this.x}`);

        // Kunci Publik y: y = g^x mod p
        this.y = modExp(this.g, this.x, this.p);
        console.log(`   -> Kunci Publik (y)  = ${this.y}`);

        console.log("\n   [!] Kunci Publik  (p, q, g, y) -> dibagikan secara terbuka");
        console.log(  "   [!] Kunci Privat  (x)          -> RAHASIA, jangan dibagikan!");
    }

    getPublicKey() {
        return { p: this.p, q: this.q, g: this.g, y: this.y };
    }

    getPrivateKey() {
        return { x: this.x };
    }

    // ----------------------------------------
    // TAHAP 3: Penandatanganan Pesan (Signing)
    // Menghasilkan tanda tangan digital (r, s)
    // ----------------------------------------
    sign(message) {
        console.log("\n--- [TAHAP 3] Proses Penandatanganan (Signing) ---");

        // Hitung nilai hash dari pesan
        const H = simpleHash(message) % this.q;
        console.log(`   -> Hash pesan H      = ${H}`);

        let r = 0n, s = 0n;

        // Ulangi jika r atau s bernilai 0 (syarat DSA)
        while (r === 0n || s === 0n) {
            // Pilih bilangan acak k yang rahasia: 0 < k < q
            const kRaw = BigInt(Math.floor(Math.random() * (Number(this.q) - 2)) + 1);
            const k = kRaw;
            console.log(`   -> Nilai acak k      = ${k}  (rahasia, hanya dipakai sekali)`);

            // Hitung r: r = (g^k mod p) mod q
            r = modExp(this.g, k, this.p) % this.q;
            console.log(`   -> r = (g^k mod p) mod q = ${r}`);

            if (r === 0n) continue;

            // Hitung s: s = k^(-1) * (H + x*r) mod q
            const kInv = modInverse(k, this.q);
            s = (kInv * (H + this.x * r)) % this.q;
            console.log(`   -> s = k^-1 * (H + x*r) mod q = ${s}`);
        }

        console.log(`\n   ✔  Tanda Tangan Digital: (r=${r}, s=${s})`);
        return { r, s };
    }

    // ----------------------------------------
    // TAHAP 4: Verifikasi Tanda Tangan (Verification)
    // Membuktikan keaslian tanda tangan (r, s) menggunakan Kunci Publik
    // ----------------------------------------
    verify(message, signature, publicKey) {
        console.log("\n--- [TAHAP 4] Proses Verifikasi (Verification) ---");

        const { r, s } = signature;
        const { p, q, g, y } = publicKey;

        // Langkah 1: Cek syarat dasar
        if (r <= 0n || r >= q || s <= 0n || s >= q) {
            console.log("   ✘  GAGAL: Nilai r atau s di luar rentang yang valid!");
            return false;
        }
        console.log(`   -> Cek syarat 0 < r < q dan 0 < s < q : VALID`);

        // Langkah 2: Hitung hash pesan yang diterima
        const H = simpleHash(message) % q;
        console.log(`   -> Hash pesan H      = ${H}`);

        // Langkah 3: Hitung w = s^(-1) mod q
        const w = modInverse(s, q);
        console.log(`   -> w = s^-1 mod q    = ${w}`);

        // Langkah 4: Hitung u1 dan u2
        const u1 = (H * w) % q;
        const u2 = (r * w) % q;
        console.log(`   -> u1 = (H * w) mod q = ${u1}`);
        console.log(`   -> u2 = (r * w) mod q = ${u2}`);

        // Langkah 5: Hitung v = ((g^u1 * y^u2) mod p) mod q
        const v = (modExp(g, u1, p) * modExp(y, u2, p)) % p % q;
        console.log(`   -> v = ((g^u1 * y^u2) mod p) mod q = ${v}`);

        // Langkah 6: Tanda tangan valid jika v == r
        console.log(`\n   -> Membandingkan: v (${v}) == r (${r}) ?`);
        if (v === r) {
            console.log("   ✔  TANDA TANGAN VALID! Pesan asli dan tidak dimanipulasi.");
            return true;
        } else {
            console.log("   ✘  TANDA TANGAN TIDAK VALID! Pesan mungkin telah diubah.");
            return false;
        }
    }
}


// ==========================================
// 3. Demonstrasi (Step-by-Step Run)
// ==========================================

console.log("==========================================");
console.log("  SIMULASI ALGORITMA DSA (FROM SCRATCH)  ");
console.log("==========================================");

// Buat instance DSA
const dsa = new DSA();

// Tahap 1 & 2: Bangkitkan parameter dan kunci
dsa.generateParameters();
dsa.generateKeys();

const publicKey  = dsa.getPublicKey();
const privateKey = dsa.getPrivateKey();

// Pesan yang akan ditandatangani
const pesanAsli = "HELLO DSA";
console.log(`\n==========================================`);
console.log(`  Pesan yang akan ditandatangani: "${pesanAsli}"`);
console.log(`==========================================`);

// Tahap 3: Tanda tangani pesan
const signature = dsa.sign(pesanAsli);

// Tahap 4: Verifikasi tanda tangan (dengan pesan ASLI)
console.log(`\n[UJI 1] Verifikasi dengan pesan ASLI: "${pesanAsli}"`);
dsa.verify(pesanAsli, signature, publicKey);

// Uji manipulasi: verifikasi dengan pesan yang DIUBAH
const pesanDipalsukan = "HELLO DSB"; // Pesan berbeda
console.log(`\n[UJI 2] Verifikasi dengan pesan DIPALSUKAN: "${pesanDipalsukan}"`);
dsa.verify(pesanDipalsukan, signature, publicKey);

console.log("\n==========================================");
console.log("  Simulasi DSA Selesai!");
console.log("==========================================");
