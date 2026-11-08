# authmein integration kit

Kit untuk mengintegrasikan aplikasi web dengan **authmein** (`https://auth.me.in`, layanan identitas bersama berbasis Authorizer 2.4.x):
aturan yang harus diikuti, klien login server-side yang sudah teruji (Go, `net/http`), tiruan authmein untuk tes dan pengembangan,
skrip uji asap, dan templat dokumen (pendaftaran client, `CLAUDE.md`, daftar kerja).

Diturunkan dari integrasi nyata aplikasi Go pertama; setiap aturan mencatat alasan dan bukti ([OBS] teramati, [DOK] dibaca di kode, [BELUM]).

## Isi

| Jalur | Fungsi |
|---|---|
| `docs/RULES.md` | Aturan teknis yang wajib (A–F), alasan, bukti, dan tes yang menjaganya |
| `docs/GUIDE.md` | Urutan kerja tahap 0–6, dari keputusan sampai produksi |
| `docs/LESSONS.md` | Kesalahan cara kerja yang paling mahal dan cara menghindarinya |
| `authmeinclient/` | Klien login: Authorization Code + PKCE, cookie alur, gerbang MFA, mulai ulang kode 401, verifikasi `id_token` |
| `authmeintest/` | Tiruan authmein (OIDC, klien publik, kode sekali pakai, gerbang MFA, kode 401) untuk tes dan `cmd/fakeauthmein` |
| `examples/minimal/` | Aplikasi lengkap terkecil di atas klien (allowlist, sesi, keluar) |
| `scripts/smoke.sh` | Uji asap yang aman untuk produksi (tanpa login, hanya membaca redirect pertama) |
| `templates/` | `data-pendaftaran.md`, `env.example`, `CLAUDE-snippet.md`, `todo-integrasi.md` |
| `tools/go.sh` | Menjalankan toolchain Go dari image Docker (Go tidak perlu terpasang) |

## Mulai cepat (tanpa client nyata)

```bash
tools/go.sh test ./...                       # tes klien terhadap tiruan authmein
export GO_DOCKER_FLAGS="--network host"      # dua proses di bawah harus berbagi loopback (tidak perlu bila Go terpasang di host)
tools/go.sh run ./cmd/fakeauthmein &         # tiruan di 127.0.0.1:9099 (hanya loopback)
AUTHMEIN_ISSUER=http://127.0.0.1:9099 AUTHMEIN_CLIENT_ID=dev-client \
PUBLIC_BASE_URL=http://127.0.0.1:8080 SESSION_SECRET=$(openssl rand -hex 24) \
COOKIE_SECURE=false ALLOWED_EMAILS=you@example.com ADDR=127.0.0.1:8080 \
  tools/go.sh run ./examples/minimal &       # lalu buka http://127.0.0.1:8080/ dan masuk dengan email apa pun di daftar
scripts/smoke.sh http://127.0.0.1:8080
```

## Memakai di aplikasi

1. Baca `docs/GUIDE.md` dan `docs/RULES.md`.
2. Salin `authmeinclient/` (dan `authmeintest/` untuk tes) ke aplikasi, atau impor modul `github.com/authmein/integration-kit`. Catat versinya.
3. Hubungkan `Hooks.OnLogin` ke penyimpanan pengguna dan sesi aplikasi (`examples/minimal` sebagai bentuk).
4. Daftarkan client lewat pengelola authmein dengan `templates/data-pendaftaran.md`.
5. Jalankan tes, mutasi, uji asap, uji nyata, sesuai panduan.

Aplikasi bukan Go: aturan, urutan callback, perilaku tiruan, dan `scripts/smoke.sh` tidak bergantung bahasa. Porting = mengulang daftar tes di
`docs/GUIDE.md` tahap 3.

## Yang bukan cakupan kit ini
- Service account (M2M, `client_credentials`), SPA tanpa backend, aplikasi mobile: aturannya berbeda (lihat paket integrasi dari pengelola authmein).
- Penyimpanan pengguna/sesi, allowlist, CSRF aplikasi: milik aplikasi (`examples/minimal` hanya contoh dalam memori).
- Mengubah perilaku authmein atau Authorizer.

## Menjaga kit tetap jujur
Tiruan hanya sebaik pengamatan di belakangnya. Bila layanan asli berperilaku berbeda dari `authmeintest`: ubah tiruan (tandai [OBS]), tulis tes yang
gagal pada kode lama, baru perbaiki `authmeinclient`. Setiap perubahan `authmeinclient` diverifikasi ulang dengan mutasi (`docs/LESSONS.md` 2).

## Lisensi
MIT (lihat `LICENSE`).
