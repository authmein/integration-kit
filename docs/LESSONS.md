# Pelajaran proses dari integrasi authmein pertama

Aturan teknis ada di `RULES.md`. Berkas ini memuat kesalahan cara kerja yang paling mahal, supaya integrasi berikutnya tidak mengulanginya.

## 1. Tiruan hanya sebaik pengamatan di baliknya
Tiruan IdP pertama memberi `state` pada redirect gerbang MFA, sehingga semua tes hijau sementara produksi gagal ("Login tidak valid"). Tiruan yang
menyalin asumsi kita membuktikan asumsi itu, bukan integrasinya.
- Tandai setiap perilaku tiruan sebagai [OBS] (terlihat di layanan nyata), [DOK] (dibaca di kode/dokumen), atau [BELUM] (asumsi).
- Begitu ada log nyata yang berbeda, ubah tiruan mengikuti kenyataan DULU, lalu perbaiki kode.

## 2. Buktikan tes baru gagal pada kode lama
Kembalikan logika lama sementara, jalankan tes, pulihkan. Tes yang tidak pernah gagal belum membuktikan apa pun. Di kit ini empat mutasi
(tanpa `AuthStyleInParams`; `state` diperiksa sebelum gerbang MFA; mulai ulang tanpa batas; `email_verified` dilewati) masing-masing membuat
tes terkait gagal. Ulangi pola itu setiap kali Anda mengubah `authmeinclient`.

## 3. Jangan melonggarkan pagar lebih dari yang dibuktikan
Perbaikan gerbang MFA sempit: hanya cabang `mfa_required=1` tanpa `code` dan tanpa `error`, `state` kosong ATAU cocok, dengan tes negatif untuk `code`
tanpa state, `error` tanpa state, dan `code` dengan state salah. Pagar lain (cookie alur, sekali pakai, `next` lokal) tidak disentuh.

## 4. Pasang log diagnostik SEBELUM uji nyata
Satu percobaan nyata berhenti di layar bawaan authmein dan tidak bisa dijelaskan karena log tidak mencatat parameter. Catat nama parameter (bukan nilai)
untuk alur yang melewati UI pihak lain.

## 5. Edit tidak terterapkan diam-diam
Satu perbaikan pertama tidak terpasang karena beda spasi. Setelah mengubah kode kritis, periksa isi berkas (`cat -A`/`git diff`), jangan hanya
percaya pesan sukses alat; dan jalankan tes yang seharusnya gagal-lalu-lulus.

## 6. Bug pustaka OAuth terlihat sebagai kegagalan acak
Header Basic yang dicoba dulu oleh pustaka (A2) menghabiskan kode sekali pakai. Gejalanya "kadang gagal". Tes yang menghitung jumlah permintaan token
(harus 1, tanpa Basic) menangkapnya; uji manual tidak.

## 7. Batas antara aplikasi dan layanan identitas
Temuan di sisi authmein (misalnya tombol sosial untuk domain lain) dilaporkan ke pengelola authmein, tidak ditambal di aplikasi. Penambalan di
aplikasi (tombol sosial buatan sendiri, callback dipindah) menciptakan celah baru.

## 8. Uji nyata mengubah dunia luar
Hostname uji terbuka ke internet dan wadahnya berisi sesi. Catat saat dibuat (siapa, apa isinya, kapan ditutup) dan jangan dibiarkan bermalam tanpa
keputusan pemilik.

## 9. Satu client per environment
Callback client tidak bisa diubah; mendaftarkan produksi dengan callback uji berarti mengulang. Daftarkan client produksi hanya saat alamat final pasti
dan atas persetujuan pemilik.
