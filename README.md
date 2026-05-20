# Recon-CLI v4.0 (Async High Performance Edition)

Recon-CLI adalah utilitas otomasi *Bug Bounty* yang dirancang untuk platform seperti HackerOne dan Bugcrowd. Sistem ini dilengkapi mekanisme *Zero False Positive*, eksekusi *asynchronous* penuh yang sangat cepat, serta pengaturan konkurensi cerdas agar stabil berjalan di laptop biasa.

## Fitur Utama

- 🚀 **Full Async Engine**: Pemindaian berjalan secara paralel berbasis `httpx` dan `asyncio` tanpa tersangkut di *thread blocking*.
- 🛡️ **Bypass & Anti-Block**: Dilengkapi sistem *Smart Exponential Backoff Retry* dan *Dynamic User-Agent Rotation* untuk mengelabui WAF/Rate Limiting.
- 💻 **Resource Friendly**: Parameter `--concurrency` (`-c`) mencegah laptop *freeze* dan jaringan Wi-Fi *drop* karena kelebihan *request*.
- 🎯 **Zero False Positives**: Proses *double* hingga *triple* verifikasi, injeksi *canary tag*, dan deteksi konteks HTML sebelum memastikan sebuah kerentanan benar-benar valid.
- 📊 **Beautiful Reports**: Secara otomatis menghasilkan laporan pemindaian yang memukau dalam bentuk JSON, HTML, dan Markdown.

## Persyaratan (Requirements)

1. **Python 3.8+**
2. Install pustaka Python yang dibutuhkan:
   ```bash
   pip install httpx[http2] urllib3 colorama
   ```
3. *(Opsional namun Sangat Disarankan)* Install *tool* eksternal dari ProjectDiscovery dkk, dan pastikan sudah masuk ke dalam `PATH` sistem Anda:
   - **subfinder**: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
   - **httpx**: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
   - **nuclei**: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
   - **gau**: `go install -v github.com/lc/gau/v2/cmd/gau@latest`

## Cara Penggunaan (Usage)

### 1. Pemindaian Menyeluruh (All-in-One)
Cara paling mudah untuk memindai sebuah domain secara penuh dari A-Z (Recon, Crawl, Vuln Scan, Port Scan, Nuclei, dan Report):

```bash
python recon_cli.py -d example.com --all
```

### 2. Atur Beban Konkurensi Laptop (Sangat Penting)
Jika Anda menggunakan laptop dengan jaringan biasa (bukan VPS), batasi *concurrency* agar koneksi tidak *drop* dan menyebabkan *missed vulnerabilities*:

```bash
python recon_cli.py -d example.com --all -c 30
```
*(Default concurrency jika opsi `-c` tidak diisi adalah 30. Anda dapat menaikkannya ke 100+ jika menggunakan VPS).*

### 3. Pemindaian Khusus (Custom Flags)
Anda dapat memisahkan proses-proses sesuai kebutuhan:

- **Hanya Recon & Reporting** (Cari subdomain dan hosts):
  ```bash
  python recon_cli.py -d example.com --recon --report
  ```
- **Hanya Port Scanning**:
  ```bash
  python recon_cli.py -d example.com --ports -c 50
  ```
- **Fokus mencari kerentanan (XSS, SQLi, SSRF, dsb)**:
  ```bash
  python recon_cli.py -d example.com --vuln
  ```
- **Jalankan Nuclei saja (Severity Tinggi/Kritis)**:
  ```bash
  python recon_cli.py -d example.com --nuclei --nuclei-severity high,critical
  ```

## Daftar Argumen (CLI Options)

| Argumen | Keterangan |
|---------|------------|
| `-d`, `--domain` | *(Wajib)* Target domain utama (contoh: `target.com`). |
| `--all` | Menjalankan seluruh proses (Recon, Vuln, Ports, Crawl, Nuclei, Report). |
| `-c`, `--concurrency` | Batas basis koneksi paralel (*Default*: 30). |
| `--delay` | Jeda waktu (*delay*) antar setiap HTTP request dalam *goroutine* (*Default*: 0.3s). |
| `--recon` | Melakukan enumerasi subdomain & validasi *live hosts*. |
| `--ports` | Melakukan pemindaian *top ports* secara *async*. |
| `--crawl` | Melakukan ekstraksi URL parameter lewat *Wayback Machine* / *Active Crawling*. |
| `--vuln` | Mengaktifkan seluruh modul pencari kerentanan (XSS, SSTI, SQLi, LFI, SSRF, dsb). |
| `--nuclei` | Menjalankan integrasi Nuclei. |
| `--report` | Menyimpan *output* hasil ke dalam file (HTML/JSON/MD). |

> *Catatan: Untuk daftar spesifik setiap modul kerentanan, gunakan `python recon_cli.py -h`*

## Disclaimer
Alat ini dibuat murni **hanya** untuk pengujian keamanan jaringan yang diotorisasi (seperti program *Bug Bounty* resmi). Pengembang tidak bertanggung jawab atas kerugian atau penyalahgunaan dari skrip ini pada sistem tanpa izin.
