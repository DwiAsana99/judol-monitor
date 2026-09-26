-- db_check_slims.sql : pemeriksaan READ-ONLY (hanya SELECT) untuk injeksi judol di database SLiMS.
-- Jalankan:  mysql -u USER -p NAMA_DB < db_check_slims.sql > hasil_slims.txt

SET @kw = 'slot gacor|slot88|slot777|situs slot|rtp slot|togel|sbobet|judi online|judi bola|maxwin|gates of olympus|mahjong ways|sweet bonanza|bandar (togel|slot|bola)|casino online|poker online|pragmatic play|scatter hitam|link alternatif|daftar slot|toto macau|slot demo|bocoran slot';

-- 1) Data bibliografi (sasaran spam SEO: judul, catatan, abstrak dimasuki kata judol)
SELECT 'biblio' AS sumber, biblio_id, LEFT(title, 120) AS judul, LEFT(notes, 150) AS catatan, input_date
FROM biblio WHERE title REGEXP @kw OR notes REGEXP @kw OR title REGEXP 'https?://' OR notes REGEXP '<a |<script|<iframe|https?://'
ORDER BY input_date DESC LIMIT 200;

-- 2) Halaman konten statis (menu Konten) & pengumuman
SELECT 'content' AS sumber, content_id, content_title, path, LEFT(content_desc, 200) AS isi
FROM content WHERE content_desc REGEXP @kw OR content_desc REGEXP '<script|<iframe|eval\\(|base64' OR content_title REGEXP @kw;

-- 3) Pengaturan sistem (nama perpustakaan, deskripsi, HTML tambahan)
SELECT 'setting' AS sumber, setting_name, LEFT(setting_value, 300) AS isi
FROM setting WHERE setting_value REGEXP @kw OR setting_value REGEXP '<script|<iframe|eval\\(|base64|atob\\(';

-- 4) Akun admin: cek yang tidak dikenal / dibuat baru
SELECT 'user_admin' AS sumber, user_id, username, realname, email, `groups`, last_login, last_login_ip, input_date
FROM user ORDER BY input_date DESC LIMIT 50;

-- 5) Anggota dengan data janggal (registrasi spam)
SELECT 'member' AS sumber, member_id, member_name, member_email, member_address, register_date
FROM member WHERE member_name REGEXP @kw OR member_address REGEXP @kw OR member_notes REGEXP @kw
ORDER BY register_date DESC LIMIT 100;
