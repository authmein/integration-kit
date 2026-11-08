<!-- Tempel bagian ini ke CLAUDE.md aplikasi, lalu isi <...>. Sumber aturan teknis: integration-kit/docs/RULES.md -->

## Login = authmein (auth.me.in)

Keputusan: login pengguna <peran> HANYA lewat authmein (layanan identitas bersama, Authorizer 2.4.x). Kata sandi, MFA, verifikasi email,
dan login sosial ada di sana; aplikasi ini tidak pernah melihat kredensial. Tombol: "Login dengan authmein".

- **Client**: `<nama client>` (`<environment>`), `client_id` `<id>`, callback `<PUBLIC_BASE_URL>/auth/authmein/callback`.
  Callback TIDAK bisa diubah; pindah alamat = client baru. Client produksi: <sudah / belum; didaftarkan oleh siapa>.
- **Env**: `AUTHMEIN_CLIENT_ID`, `PUBLIC_BASE_URL`, `SESSION_SECRET` (>= 32), `ADMIN_EMAILS`; `AUTHMEIN_ISSUER` bawaan `https://auth.me.in`.
  Berkas rahasia (`.env*`) jangan dibaca atau dicetak.
- **Kode**: `<path paket klien>` (disalin dari integration-kit, versi `<tag/commit>`; jangan diedit di sini tanpa mencatat
  alasannya; perubahan perilaku berarti memperbarui tiruan dan tes).
- **Aturan yang ditegakkan kode dan tes** (jangan dilonggarkan tanpa bukti):
  1. Authorization Code + PKCE S256 dari backend; client publik: `client_id` di badan permintaan, TANPA header Basic.
  2. Kunci akun = `sub`, bukan email. `email_verified` wajib true. Nama bisa kosong.
  3. Siapa boleh masuk = allowlist/peran APLIKASI, dicek ulang pada setiap permintaan.
  4. Callback: cookie alur dulu, lalu jawaban gerbang MFA (tanpa `code` DAN tanpa `state`), baru `state`.
  5. Kode ditolak 401 = mulai ulang login SEKALI, jangan ulangi kodenya.
  6. `next` hanya path lokal.
  7. Keluar hanya mengakhiri sesi aplikasi; jangan arahkan ke `GET /logout` authmein.
- **Tiruan IdP** (`authmeintest`): hanya sebaik pengamatan di belakangnya. Tandai [OBS]/[DOK]/[BELUM]; begitu ada log nyata yang berbeda,
  ubah tiruan dulu, buktikan tes baru GAGAL pada kode lama, baru perbaiki kode.
- **Uji nyata** memakai client `<dev/beta>` lewat alamat publik sementara; hostname itu terbuka ke internet: catat di `housekeeping.md` saat
  dibuat dan tutup bila selesai.
- Pelajaran dan bukti integrasi: `<docs/PELAJARAN-INTEGRASI-AUTHMEIN.md>`.
- **Batas yang diketahui**: login sosial (GitHub/Google) tidak tersedia di luar `auth.me.in` kecuali pengelola menambahkan origin aplikasi;
  layar persetujuan tampil di SETIAP login (perilaku client `dynamic`, bukan bug).
