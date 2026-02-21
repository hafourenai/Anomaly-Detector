# Anomaly Detector (A-Dect)

**A-Dect** merupakan sistem monitoring keamanan jaringan WiFi berbasis mikrokontroler ESP8266 yang dirancang untuk **mendeteksi** anomali secara real-time, khususnya serangan *deauthentication* dan *Evil Twin* (Access Point palsu).

A-Dect dikembangkan sebagai media pembelajaran dan eksplorasi dalam bidang keamanan jaringan nirkabel. Sistem ini menerapkan prinsip dasar anomaly-based detection, yaitu mengidentifikasi pola lalu lintas WiFi yang menyimpang dari kondisi normal.

## Fitur Utama

- **Deauth Attack Detection**: Mendeteksi upaya pemutusan paksa koneksi perangkat di jaringan Anda.
- **Evil Twin Detection**: Mengidentifikasi titik akses palsu yang mencoba meniru identitas WiFi terpercaya Anda.
- **Telegram Notifications**: Notifikasi instan ke HP Anda saat ancaman terdeteksi.
- **Web Dashboard**: Monitor status keamanan dan kelola daftar WiFi terpercaya (Trusted AP) melalui browser.
- **OLED Display Support**: Informasi status langsung di layar fisik perangkat. (Opsional)
- **Persistent Storage**: Pengaturan dan daftar WiFi terpercaya disimpan aman di memori (EEPROM).

## Persyaratan Perangkat

- **Mikrokontroler**: ESP8266 (NodeMCU v2/v3 atau ESP-12E).
- **Layar (Opsional)**: SSD1306 128x64 OLED (I2C). (Bisa di disable di config.h)
- **Koneksi**: Kabel data Micro USB untuk proses flashing.

## Dashboard

1.  Sambungkan HP atau Laptop Anda ke WiFi yang sama dengan ESP8266.
2.  Buka browser dan ketik alamat IP ESP8266 (Lihat di Serial Monitor atau Layar OLED).
3.  Login 
4.  Melakukan monitoring trafik serangan dan mempercayai (*trust*) jaringan WiFi di sekitar Anda agar tidak dianggap sebagai ancaman.

---

## Catatan
Proyek ini dibuat sebagai **media pembelajaran**. Implementasinya sederhana dan **tidak ditujukan** sebagai sistem keamanan tingkat enterprise.

Pengembangan dilakukan secara eksploratif dengan pendekatan konseptual dan eksperimental. Dalam prosesnya, **pemanfaatan AI** juga digunakan sebagai bagian dari workflow pengembangan untuk membantu riset dan dokumentasi.

Perangkat keras yang digunakan tergolong murah dan hanya terdiri dari satu mikrokontroler **tanpa** modifikasi tambahan. Fokus utama proyek ini adalah pada pemahaman konsep, bukan kompleksitas perangkat.

