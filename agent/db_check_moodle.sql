-- db_check_moodle.sql : pemeriksaan READ-ONLY (hanya SELECT) untuk injeksi judol di database Moodle.
-- Ganti awalan tabel `mdl_` sesuai $CFG->prefix di config.php.
-- Jalankan:  mysql -u USER -p NAMA_DB < db_check_moodle.sql > hasil_moodle.txt
-- (PostgreSQL: ganti REGEXP dengan ~* dan hapus backtick)

SET @kw = 'slot gacor|slot88|slot777|situs slot|rtp slot|togel|sbobet|judi online|judi bola|maxwin|gates of olympus|mahjong ways|sweet bonanza|bandar (togel|slot|bola)|casino online|poker online|pragmatic play|scatter hitam|link alternatif|daftar slot|toto macau|slot demo|bocoran slot';

-- 1) TITIK INJEKSI KLASIK: HTML tambahan di seluruh situs & pengaturan tema (muncul di semua halaman)
SELECT 'config' AS sumber, name, LEFT(value, 300) AS isi
FROM mdl_config
WHERE name IN ('additionalhtmlhead','additionalhtmltopofbody','additionalhtmlfooter','customfrontpageinclude','sitepolicyhandler')
   OR (value REGEXP @kw) OR (value REGEXP '<script|<iframe|eval\\(|base64_decode|atob\\(');

SELECT 'config_plugins' AS sumber, plugin, name, LEFT(value, 300) AS isi
FROM mdl_config_plugins
WHERE (value REGEXP @kw) OR (name IN ('customcss','scss','rawscss','footnote','additionalhtml') AND value REGEXP '<script|<iframe|eval\\(|base64|@import url|http')
   OR (plugin LIKE 'theme_%' AND value REGEXP '<script|<iframe|eval\\(|atob\\(');

-- 2) KONTEN (kursus, label, halaman, forum, deskripsi profil, blog)
SELECT 'course' AS sumber, id, fullname, LEFT(summary, 200) AS isi FROM mdl_course WHERE summary REGEXP @kw OR fullname REGEXP @kw OR summary REGEXP '<iframe|<script';
SELECT 'label' AS sumber, id, course, LEFT(intro, 200) AS isi FROM mdl_label WHERE intro REGEXP @kw OR intro REGEXP '<script|<iframe';
SELECT 'page' AS sumber, id, course, name, LEFT(content, 200) AS isi FROM mdl_page WHERE content REGEXP @kw OR content REGEXP '<script|<iframe';
SELECT 'forum_post' AS sumber, id, discussion, LEFT(subject, 100) AS subjek, LEFT(message, 200) AS isi FROM mdl_forum_posts WHERE message REGEXP @kw OR subject REGEXP @kw;
SELECT 'user_desc' AS sumber, id, username, LEFT(description, 200) AS isi FROM mdl_user WHERE description REGEXP @kw OR description REGEXP '<script|<iframe' OR institution REGEXP @kw OR city REGEXP @kw;
SELECT 'block_html' AS sumber, id, blockname, LEFT(configdata, 100) AS isi_base64 FROM mdl_block_instances WHERE blockname='html';   -- configdata base64: decode manual, cek isi
SELECT 'url_resource' AS sumber, id, course, name, externalurl FROM mdl_url WHERE externalurl REGEXP @kw;

-- 3) AKUN ADMIN / ROLE MENCURIGAKAN
SELECT 'site_admins' AS sumber, value AS daftar_id_admin FROM mdl_config WHERE name = 'siteadmins';
SELECT 'user_baru_30hr' AS sumber, id, username, email, FROM_UNIXTIME(timecreated) AS dibuat, FROM_UNIXTIME(lastaccess) AS akses_terakhir
FROM mdl_user WHERE timecreated > UNIX_TIMESTAMP(NOW() - INTERVAL 30 DAY) AND deleted = 0 ORDER BY timecreated DESC LIMIT 100;

-- 4) PLUGIN yang terpasang baru-baru ini (cek plugin yang tidak dikenal)
SELECT 'plugin_baru' AS sumber, plugin, name, value FROM mdl_config_plugins WHERE name = 'version' AND plugin NOT LIKE 'core%' ORDER BY id DESC LIMIT 30;
