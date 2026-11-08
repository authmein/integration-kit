# Aturan integrasi aplikasi dengan authmein

Aturan teknis yang HARUS dipenuhi setiap aplikasi web yang login lewat authmein (`https://auth.me.in`, Authorizer 2.4.x, client `dynamic`
publik). Setiap aturan punya alasan dan, bila mungkin, tes di kit ini yang membuktikannya. Penanda bukti:

- **[OBS]** teramati langsung pada layanan nyata, **[DOK]** dibaca di kode/dokumentasi Authorizer, **[BELUM]** belum terbukti.
- `uji:` = nama tes di `authmeinclient/handler_test.go` (jalankan `tools/go.sh test ./...`).

Aplikasi yang bukan Go tetap wajib mengikuti aturan yang sama; kit ini hanya implementasi acuannya. Porting = mengulang tes yang sama terhadap
tiruan `authmeintest` (atau `cmd/fakeauthmein`).

## A. Alur login

**A1. Authorization Code + PKCE (S256), dari backend.** Backend membuat `state`, `nonce`, dan `code_verifier` acak, mengalihkan browser ke
`/authorize`, dan backend (bukan browser) menukar `code` di endpoint token. DILARANG: implicit flow, token di `localStorage`, memanggil GraphQL
atau `getSession` Authorizer dari browser (cookie pihak ketiga diblokir Safari/Firefox). uji: `TestPKCEStateAndNonceAreSent`.

**A2. Client publik: `client_id` di badan permintaan token, tanpa header Basic, SATU permintaan per kode.** Client `dynamic` tidak punya secret.
Pustaka OAuth yang menebak otentikasi mencoba header Basic dulu lalu mengirim ulang kode; kode authmein sekali pakai, jadi percobaan pertama
menghabiskannya dan login gagal acak-acakan. Di Go: `endpoint.AuthStyle = oauth2.AuthStyleInParams`. [OBS] ditemukan oleh tes, bukan uji manual.
uji: `TestPublicClientSendsOneTokenRequestWithoutBasic`.

**A3. Cookie alur: bertanda tangan, singkat, sekali pakai, terikat browser.** Berisi `state`, `nonce`, `code_verifier`, `next`, dan dua penanda
(sudah-MFA, sudah-diulang). HMAC meliputi nama cookie; HttpOnly; `SameSite=Lax` (callback adalah navigasi tingkat atas dari situs lain);
`Secure` di https; berlaku 10 menit; dihapus begitu callback dipakai; `Path` dibatasi ke awalan rute login. `SESSION_SECRET` >= 32 karakter dan
aplikasi menolak start tanpa itu. uji: `TestFlowCookieAttributes`, `TestFlowCookieMissingTamperedOrExpired`, `TestAuthorizationCodeCannotBeReplayed`.

**A4. Urutan di callback tidak boleh diubah:** (1) cookie alur sah, (2) jawaban gerbang MFA (A5), (3) `state` cocok, (4) `error`, (5) `code`
ada, (6) tukar kode, (7) verifikasi token, (8) keputusan aplikasi (`OnLogin`). Jalur apa pun yang bisa berakhir sebagai sesi (`code`, `error`)
mewajibkan `state` yang benar. uji: `TestStateMismatchIsRejected`.

**A5. Gerbang MFA login sosial = jalan memutar, bukan galat.** Bila akun sosial belum mendaftar/lewat MFA atau harus memasukkan kode, Authorizer
TIDAK memberi `code`: ia mengalihkan ke `redirect_uri` dengan `?mfa_required=1&mfa_methods=..&mfa_gate=offer|verify`, **tanpa `code` dan tanpa
`state`** [OBS, log nyata 2026-11-08]. Karena itu cabang ini dinilai SEBELUM `state` (A4), asalkan: cookie alur sah, tanpa `code`, tanpa `error`,
dan `state` kosong ATAU cocok (yang ada tapi salah ditolak). Penanganan: ulangi permintaan `/authorize` yang sama dari server (tanpa mengikuti
redirect) untuk mengambil URL halaman login hosted (`/app?...&code=<id>`, `Location` harus di host issuer, path `/app...`), tambahkan
`mfa_required`, `mfa_methods`, `mfa_gate`, lalu arahkan browser ke sana; UI authmein menyelesaikan MFA dan kembali ke callback dengan `code`.
SEKALI per login (penanda di cookie alur); jawaban gerbang kedua = halaman galat, bukan putaran tanpa akhir. Tes: `TestMFAGateHandOffCompletesTheLogin`,
`TestMFAGateHandOffNeverLoops`, `TestMFAGateAnswerNeedsOurFlow`, `TestMFAGateAnswerWithoutStateIsFollowedButNothingElseIs`.

**A6. Kode ditolak 401 = mulai ulang login SEKALI.** Authorizer membatalkan kode begitu ada authorize lebih baru di sesi authmein yang sama (tab
kedua, klik ganda) [DOK + OBS]. Buat `state`, `nonce`, `code_verifier` baru dan alihkan lagi, sekali; jangan pernah mencoba ulang kode yang sama;
penolakan kedua = halaman galat. uji: `TestRejectedCodeRestartsTheLoginOnce`, `TestRejectedCodeDoesNotRestartTwice`.

**A7. Verifikasi `id_token` penuh.** Tanda tangan RS256 lewat JWKS, `iss == issuer`, `aud == client_id APLIKASI INI`, `exp`, dan `nonce` milik
percobaan ini. Token tanpa `kid` di header: pakai kunci RS256 yang ada di JWKS. Tanpa cek `aud`, token aplikasi lain bisa dipakai di sini.
uji: `TestBrokenIDTokensAreRejected` (aud, iss, exp, nonce, tanda tangan).

## B. Identitas dan akses

**B1. Kunci akun = `sub`, bukan email.** `sub` tetap sama untuk satu akun lintas metode masuk (sandi, GitHub, Google); email bisa berubah dan
nama bisa kosong. Satu orang BISA punya lebih dari satu `sub` (login sosial dengan email berbeda) [BELUM diuji]: jangan menggabung akun karena
nama sama. uji: `TestEmailChangeKeepsTheSameSubject`, `TestAccountWithoutAProfileNameHasAnEmptyName`.

**B2. `email_verified` wajib true, email dan `sub` wajib ada.** Akun yang belum terverifikasi bisa digantikan orang lain yang masuk lewat
penyedia sosial dengan email itu. Jangan membedakan perilaku dari `login_method`/`amr`. uji: `TestBrokenIDTokensAreRejected` (unverified, no email, no subject).

**B3. Siapa boleh masuk adalah keputusan aplikasi.** authmein hanya membuktikan siapa orangnya. Aplikasi menerapkan allowlist/peran sendiri di
`OnLogin` DAN memeriksanya ulang pada setiap permintaan (menghapus seseorang berlaku seketika; jangan menyalin peran ke dalam token/sesi sekali
jalan). Gagal-tertutup: galat pencarian = ditolak. Peran `roles` Authorizer bersifat global; jangan dipakai sebagai peran aplikasi.
uji: `TestAppDeniesAnIdentityItDoesNotAllow`; pemeriksaan ulang tiap permintaan: `examples/minimal` (`require`).

**B4. `next` hanya path lokal.** Tolak URL absolut, `//host`, `\`, karakter kontrol; jatuh ke halaman bawaan. uji: `TestNextIsOnlyEverALocalPath`, `TestSafeNext`.

## C. Sesi aplikasi

**C1. Sesi milik aplikasi, bukan milik Authorizer.** Cookie sesi dibuat aplikasi sendiri: httpOnly, Secure (https), SameSite=Lax, host-only (tanpa
atribut `Domain`), nama unik per aplikasi, dengan awalan `__Host-` saat Secure. Token acak yang disimpan di database lebih disukai daripada JWT
berumur panjang. Jangan mengandalkan cookie Authorizer dari browser.

**C2. Keluar hanya mengakhiri sesi aplikasi.** Sesi authmein tetap hidup (login berikutnya tanpa mengetik sandi). Jangan arahkan ke
`GET /logout` authmein: tombolnya rusak di 2.4.4 (ditolak pagar CSRF Authorizer sendiri) [OBS]. POST keluar dilindungi CSRF aplikasi.

**C3. Layar persetujuan tampil di SETIAP login** untuk client `dynamic` yang didaftarkan lewat alat pengelola. Itu perilaku, bukan galat
aplikasi; jangan "memperbaikinya".

## D. Client dan konfigurasi

**D1. Satu client per aplikasi per environment, dengan nama unik** (`Nama App (dev)`, `(beta)`, `(prod)`); nama tampil di layar persetujuan.

**D2. Redirect URI tidak bisa diubah sesudah client dibuat.** Pindah alamat = client baru (lalu hapus yang lama). Pastikan alamat publik final
sebelum mendaftar. `RedirectURL` di `Config` harus sama persis.

**D3. Rahasia.** Client interaktif TIDAK punya secret. `SESSION_SECRET` dari secret store/berkas lingkungan yang di-gitignore, tidak pernah di repo,
log, atau pesan. Service account (M2M) mendapat secret yang tampil SEKALI; simpan segera di tempat rahasia dan jangan di berkas yang masuk repo.

**D4. Konfigurasi opsional (pola yang disarankan).** Aplikasi tetap boleh start tanpa konfigurasi authmein; halaman/rute login menjawab 503 dengan
pesan jelas. Ini memungkinkan deploy lebih dulu daripada pendaftaran client. Jangan membuat `log.Fatal` memblokir bagian aplikasi yang tidak butuh login.

**D5. Login sosial (GitHub/Google) di luar `auth.me.in`.** Authorizer 2.4.4 memeriksa tujuan alihan login sosial hanya terhadap daftar origin
instance, bukan `redirect_uri` client [DOK + OBS]. Akibatnya untuk aplikasi di domain lain tombol sosial tidak berfungsi (JSON `invalid redirect
uri`), sehingga layar login authmein menyembunyikannya kecuali pengelola menambahkan origin aplikasi ke daftar itu (keputusan per aplikasi).
Rancang UI aplikasi tanpa mengandalkan login sosial. JANGAN membuat tombol sosial sendiri yang memanggil `/oauth_login`, jangan memindahkan callback
ke bawah `auth.me.in` demi itu, dan jangan menambah origin ke instance sendiri.

## E. Diagnosis

**E1. Log nama parameter, bukan nilai.** Untuk alur yang melewati UI pihak lain (jalan memutar MFA), catat NAMA parameter yang dikirim dan diterima.
Nilai membawa tantangan PKCE, `state`, dan id kode: jangan dicatat. Kegagalan yang tidak bisa dianalisis karena log kurang akan terulang.

**E2. Pasang log diagnostik SEBELUM uji nyata**, bukan sesudah kegagalan pertama.

## F. Yang belum terbukti (jangan diasumsikan)

- Login Google nyata sampai kembali ke aplikasi eksternal; akun sosial yang belum punya MFA sama sekali (mode `mfa_gate=offer`) di aplikasi eksternal.
- Satu percobaan berhenti di layar bawaan "Signed in as ..." di `auth.me.in/app/` dan tidak kembali ke callback; penyebab tidak ditemukan. Dugaan: `/app/`
  hanya melanjutkan ke `/authorize` bila URL membawa `redirect_uri` plus salah satu `state/client_id/scope/...`; layar itu muncul bila `/app/` dibuka tanpa
  parameter tersebut (tab lama, bookmark). Awasi bila terulang.
- Perilaku server asli terhadap header Basic pada client publik (tiruan ketat sengaja menolaknya).
- Layar persetujuan, refresh token, dan batas laju tidak ditiru oleh `authmeintest`.
