# Data pendaftaran client authmein: <nama aplikasi> (<dev|staging|prod>)

Lengkapi lalu serahkan ke pengelola authmein (atau isi ke alat pendaftaran). Satu lembar = satu client = satu environment.
Tanda `*` wajib. Jangan menaruh rahasia di lembar ini.

| Isian | Nilai | Catatan |
|---|---|---|
| `name` * | `<Nama App> (dev)` | Tampil di layar persetujuan pengguna dan harus unik. Beri akhiran environment. |
| `owner` * | | Orang/organisasi penanggung jawab |
| `contact_email` * | | Untuk pemberitahuan keamanan |
| `party` * | `first_party` / `third_party` | Aplikasi milik sendiri atau pihak ketiga |
| `environment` * | `dev` / `staging` / `prod` | |
| `app_kind` * | `web_server` / `spa` / `mobile_native` / `backend_m2m` | Aplikasi web dengan backend = `web_server` (kit ini). `backend_m2m` = layanan tanpa pengguna (bukan cakupan kit ini). |
| `stack` * | `go` / `nextjs` / ... | |
| `redirect_uris` * | `https://app.example/auth/authmein/callback` | PERSIS dan TIDAK bisa diubah sesudah dibuat. Pastikan alamat publik final sebelum mendaftar. |
| `post_logout_uris` | | Kosongkan bila keluar hanya mengakhiri sesi aplikasi |
| `origins` | | Hanya untuk SPA |
| `scopes` | `openid email profile` | Secukupnya |

## Pertanyaan yang harus dijawab sebelum mendaftar
- [ ] Alamat publik final (termasuk subdomain beta/dev) sudah ada dan terjangkau dari browser pengguna?
- [ ] Siapa yang boleh masuk (allowlist undangan, domain email, semua orang)? Diputuskan APLIKASI, bukan authmein.
- [ ] Apakah pengguna perlu login sosial (Google/GitHub)? Di luar `auth.me.in` tombol itu **tidak tersedia** kecuali pengelola menambahkan
      origin aplikasi ke daftar origin instance (keputusan per aplikasi). Rancang UI yang tidak mengandalkannya.
- [ ] Client mana untuk environment mana (dev, beta, prod) dan siapa yang mendaftarkan client produksi?
