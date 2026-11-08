---
id: <nomor>
title: "Login <peran> lewat authmein"
status: open
---
# Todo integrasi authmein: <aplikasi>

Panduan: `integration-kit/docs/GUIDE.md`. Aturan: `integration-kit/docs/RULES.md`. Centang `[x]` hanya dengan bukti (perintah + keluaran
ringkas, tanpa rahasia) di bagian Bukti. Tanda 🔒 = butuh persetujuan pemilik/pengelola sebelum dikerjakan.

## 0. Keputusan
- [ ] Siapa yang boleh masuk dan bagaimana (allowlist undangan / peran): ______
- [ ] Login lama (jika ada) dihapus atau berdampingan? Migrasi pengguna? ______
- [ ] Butuh login sosial? (di luar auth.me.in tidak tersedia secara bawaan; lihat RULES.md A15)
- [ ] Alamat publik dev/beta/prod final: ______

## 1. Pendaftaran client (satu per environment)
- [ ] 🔒 Lengkapi `templates/data-pendaftaran.md`, validasi, pratinjau, persetujuan, daftarkan client dev/beta
- [ ] `client_id` dicatat di CLAUDE.md aplikasi (bukan rahasia). Secret? Client interaktif tidak punya.

## 2. Kode
- [ ] Salin `authmeinclient` (dan `authmeintest` untuk tes) dari integration-kit; catat versinya
- [ ] `OnLogin`: allowlist/peran, upsert pengguna berkunci `sub`, buat sesi aplikasi, atur cookie
- [ ] Sesi aplikasi: cookie httpOnly/Secure/SameSite=Lax/host-only (`__Host-` bila https); cek allowlist di setiap permintaan
- [ ] Keluar mengakhiri sesi aplikasi saja; CSRF untuk POST
- [ ] Konfigurasi opsional: tanpa env authmein aplikasi tetap jalan dan login menjawab 503 (pilihan desain)

## 3. Tes otomatis (tiruan IdP)
- [ ] Seluruh tes dari kit lulus di aplikasi (jalur sukses, state/nonce/PKCE, cookie alur hilang/rusak/kedaluwarsa, replay kode, token rusak,
      email belum terverifikasi, nama kosong, email berubah, gerbang MFA tanpa state, 401 mulai ulang sekali, `next` aman)
- [ ] Mutasi: kembalikan satu per satu logika lama dan pastikan tes terkait GAGAL (dicatat di Bukti)
- [ ] `scripts/smoke.sh` lulus terhadap aplikasi lokal

## 4. Uji nyata di dev/beta (dengan akun authmein asli)
- [ ] Log diagnostik aktif SEBELUM uji (nama parameter, bukan nilai)
- [ ] Hostname uji dibuka; dicatat di housekeeping.md; ditutup bila selesai
- [ ] Login email + sandi (+ OTP) -> kembali ke aplikasi -> sesi terbentuk
- [ ] Keluar lalu masuk lagi (tanpa mengetik sandi; layar persetujuan tampil)
- [ ] Pengguna KEDUA yang tidak diundang ditolak; pengguna kedua yang diundang tidak melihat data pengguna pertama
- [ ] Akun dengan MFA (TOTP): alur selesai
- [ ] Login sosial: sesuai keputusan (tersembunyi di luar auth.me.in, atau origin ditambahkan)

## 5. Produksi
- [ ] 🔒 Daftarkan client produksi (callback produksi PERSIS), pratinjau, persetujuan
- [ ] 🔒 Isi `AUTHMEIN_CLIENT_ID`, `SESSION_SECRET`, `ADMIN_EMAILS` di server (oleh pemilik; berkas rahasia tidak dibaca)
- [ ] `scripts/smoke.sh https://<produksi>` lulus
- [ ] 🔒 Deploy; uji masuk-keluar oleh pemilik
- [ ] Dokumentasi: CLAUDE.md aplikasi memuat bagian "Login = authmein" (templates/CLAUDE-snippet.md)

## Bukti
(perintah dan keluaran ringkas per butir; tanpa rahasia)

## Catatan / kendala
