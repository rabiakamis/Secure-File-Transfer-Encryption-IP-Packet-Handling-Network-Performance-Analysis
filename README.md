# 🔐 Advanced Secure File Transfer System

Bu proje, Python diliyle geliştirilmiş, **AES şifreleme**, **düşük seviyeli IP işleme** ve **ağ performansı analizi** özelliklerine sahip güvenli bir dosya transfer sistemidir. Sistem, özellikle **ağ bozulmaları ve saldırı senaryolarına karşı dirençli** olacak şekilde tasarlanmıştır.

---

## 🚀 Proje Özellikleri

- ✅ **AES-256 Şifreleme** ile uçtan uca dosya güvenliği
- 🧾 **SHA-256** algoritması ile veri bütünlüğü kontrolü
- 📦 **Scapy** ile düşük seviyeli IP paket üretimi ve işlenmesi
- 🔄 **Man-in-the-Middle (MITM)** saldırı senaryosu simülasyonu
- 📊 **Ağ Performans Analizi** (Transfer süresi, bant genişliği hesaplamaları)
- 🧪 **Clumsy** kullanılarak gerçek dünya senaryolarının test edilmesi

---

## ⚙️ Kullanılan Teknolojiler

- 🐍 Python 3
- 📦 [Scapy](https://scapy.net/)
- 🔐 [PyCryptodome](https://www.pycryptodome.org/)
- 🧪 [Clumsy](https://jagt.github.io/clumsy/) – Ağ bozulmalarını simüle etmek için

---

## 📥 Kurulum

Projeyi çalıştırmadan önce aşağıdaki bağımlılıkları yüklemeniz gerekmektedir:

```bash
pip install scapy pycryptodome
