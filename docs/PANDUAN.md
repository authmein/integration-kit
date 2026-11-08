# Panduan: mengintegrasikan aplikasi dengan authmein

Urutan kerja dari keputusan sampai produksi, dengan templat yang dipakai di tiap tahap. Aturan teknisnya: `ATURAN.md` (kode A1 dst. dirujuk di sini).
Pelajaran proses: `PELAJARAN.md`. Berlaku untuk aplikasi web dengan backend yang login lewat `https://auth.me.in` sebagai client `dynamic` publik.

## Gambaran

```
keputusan -> data pendaftaran -> client dev/beta -> kode + tes dengan tiruan -> uji nyata -> client produksi -> deploy -> dokumentasi
   (0)             (1)                  (1)                  (2, 3)                (4)             (5)          (5)         (6)
```

Prinsip yang menentukan urutan ini:
1. **Tiruan dulu, nyata kemudian.** Hampir semua perilaku dibuktikan terhadap `authmeintest` secara otomatis; uji nyata hanya menutup yang tidak bisa ditiru.
2. **Kode tidak dipercaya sebelum tesnya terbukti gagal pada logika lama** (mutasi, lihat `PELAJARAN.md` 2).
3. **Setiap langkah yang mengubah dunia luar** (mendaftarkan client, membuka hostname, mengisi rahasia produksi, deploy) membutuhkan persetujuan pemilik secara eksplisit.
4. **Bukti, bukan klaim.** Centang hanya dengan perintah dan keluaran ringkas (tanpa rahasia).

## Tahap 0. Keputusan (sebelum menulis kode)

Jawab dan catat (`templates/todo-integrasi.md` bagian 0):
- **Siapa yang boleh masuk?** allowlist undangan, domain email, atau semua orang. Selalu keputusan aplikasi (B3), bukan authmein.
- **Login lama?** dihapus atau berdampingan; ada pengguna yang harus dipindah? (Identitas baru berkunci `sub`; email lama tidak otomatis cocok.)
- **Login sosial?** Di luar `auth.me.in` tidak tersedia secara bawaan (D5). Jika wajib, itu keputusan terpisah dengan pengelola authmein.
- **Alamat publik** dev/beta/prod final (callback tidak bisa diubah, D2).

## Tahap 1. Pendaftaran client

1. Isi `templates/data-pendaftaran.md` (satu lembar per client per environment).
2. Pengelola authmein memvalidasi data, menampilkan **pratinjau**, dan baru mendaftarkan setelah pemilik menyetujui. Hasilnya `client_id` (bukan rahasia)
   dan paket integrasi.
3. Mulai dari client **dev/beta** bernama `Nama App (beta)`. Client produksi menunggu tahap 5.
4. Catat `client_id` dan callback di `CLAUDE.md`/dokumentasi aplikasi memakai `templates/CLAUDE-snippet.md`.

## Tahap 2. Kode

1. Salin `authmeinclient/` ke aplikasi (atau impor modul ini). Catat versi/commit asal; perubahan perilaku dilakukan di kit lebih dulu lalu disalin ulang.
2. Hubungkan:
   - `Config` dari environment (`templates/env.example`): `AUTHMEIN_CLIENT_ID`, `PUBLIC_BASE_URL` (callback = `<PUBLIC_BASE_URL>/auth/authmein/callback`), `SESSION_SECRET`, `COOKIE_SECURE`.
   - `Hooks.OnLogin`: allowlist/peran, upsert pengguna berkunci `Subject`, buat sesi aplikasi, set cookie sesi. Lihat `examples/minimal`.
   - Pemeriksaan allowlist/peran ulang pada setiap permintaan terlindungi (B3).
   - Keluar: akhiri sesi aplikasi saja (C2), POST dengan CSRF.
3. Tombol "Login dengan authmein" mengarah ke `/auth/authmein/start?next=<path lokal>`.
4. Konfigurasi opsional (D4): tanpa env authmein, rute login menjawab 503 dan aplikasi tetap jalan.

## Tahap 3. Tes otomatis dengan tiruan

1. Salin `authmeintest/` dan kerangka `authmeinclient/handler_test.go` ke aplikasi; sesuaikan `OnLogin` tes dengan penyimpanan aplikasi.
2. Semua kelas tes berikut wajib ada (nama di `handler_test.go`): jalur sukses; PKCE/state/nonce terkirim; satu permintaan token tanpa Basic;
   atribut cookie alur; cookie alur hilang/rusak/kedaluwarsa; replay kode; `state` salah; token rusak (aud, iss, exp, nonce, tanda tangan, email belum
   terverifikasi, tanpa email, tanpa sub); akun ditolak aplikasi; nama kosong; email berubah dengan `sub` sama; penyedia tak terjangkau; gerbang MFA
   (selesai, tidak berputar, butuh cookie alur kita, tanpa state diikuti tetapi `code`/`error` tanpa state ditolak); kode 401 diulang sekali dan tidak dua kali;
   `next` lokal.
3. **Mutasi**: untuk tiap aturan penting, kembalikan logika lama sementara dan pastikan tes terkait GAGAL; pulihkan; catat di bukti.
4. `scripts/smoke.sh http://localhost:<port>` lulus. Untuk mencoba dengan tangan: `go run ./cmd/fakeauthmein` dan arahkan `AUTHMEIN_ISSUER` ke sana.

## Tahap 4. Uji nyata (dev/beta)

Hanya yang tidak bisa ditiru: layanan authmein asli, layar persetujuan, MFA nyata, email nyata.
1. Pasang log diagnostik SEBELUM mulai (E2). Bangun ulang wadah uji dengan `AUTHMEIN_CLIENT_ID` client beta dan alamat publik beta.
2. Buka hostname uji ke internet seperlunya; **catat artefaknya** (hostname, wadah, data sementara) dengan syarat penutupan; tutup bila selesai.
3. Uji dengan akun authmein asli: email + sandi (+ OTP) -> kembali -> sesi; keluar lalu masuk lagi; pengguna kedua yang tidak diundang ditolak; pengguna kedua
   yang diundang tidak melihat data pengguna pertama; akun dengan MFA (TOTP).
4. Bila ada perilaku yang tidak sesuai tiruan: **ubah tiruan dulu** (tandai [OBS]), tulis tes yang gagal pada kode lama, baru perbaiki kode.

## Tahap 5. Produksi

1. Daftarkan client produksi (callback produksi persis) dengan pratinjau dan persetujuan.
2. Pemilik mengisi `AUTHMEIN_CLIENT_ID`, `SESSION_SECRET`, `ADMIN_EMAILS` di server (berkas rahasia tidak dibaca atau dicetak oleh siapa pun selain proses aplikasi).
3. `scripts/smoke.sh https://<produksi>` lulus (aman: tidak login, hanya membaca redirect pertama).
4. Deploy dengan persetujuan pemilik; pemilik mencoba masuk dan keluar.

## Tahap 6. Dokumentasi dan serah terima
- `CLAUDE.md`/README aplikasi memuat bagian "Login = authmein" dari `templates/CLAUDE-snippet.md` (client, env, aturan, batas yang diketahui).
- Catatan pelajaran khusus aplikasi (apa yang mengejutkan, bukti uji nyata) disimpan di repo aplikasi; temuan di sisi authmein dilaporkan ke pengelola authmein.
- Hostname uji ditutup dan dicatat; cadangan/sisa uji dibersihkan lewat daftar yang disetujui.

## Pemecahan masalah singkat

| Gejala | Kemungkinan | Rujukan |
|---|---|---|
| "Login tidak valid" setelah login GitHub/Google dengan MFA | callback membandingkan `state` sebelum cabang gerbang MFA | A4, A5 |
| Login kadang gagal acak, 401 dari endpoint token | pustaka mencoba Basic dulu / kode dibatalkan authorize baru | A2, A6 |
| Berhenti di layar "Signed in as ..." di `auth.me.in/app/` | `/app/` dibuka tanpa parameter login (tab lama, bookmark) | F |
| Tombol GitHub/Google tidak ada di layar login | disengaja untuk domain di luar `auth.me.in` | D5 |
| JSON `{"error":"invalid redirect uri"}` di `auth.me.in/oauth_login/...` | tombol sosial untuk origin yang tidak terdaftar | D5 |
| "Akun belum diizinkan" | email tidak di allowlist aplikasi; bukan masalah authmein | B3 |
| Layar persetujuan di setiap login | perilaku client `dynamic` | C3 |
| Tidak bisa mengganti callback | memang tidak bisa; buat client baru | D2 |
