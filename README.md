# domaincheck

ตรวจโดเมนว่าถูก ISP ไทยบล็อกหรือไม่ ผ่าน DNS resolver ของค่ายเน็ตบ้านไทย (AIS, True, 3BB, NT, Symphony ฯลฯ) พร้อมสถานะทะเบียนโดเมน (RDAP)

## สิ่งที่ตรวจให้
- **สถานะทะเบียน (RDAP)** — จดหรือยัง, วันหมดอายุ, registrar, nameserver (subdomain จะดูทะเบียนของโดเมนหลักให้อัตโนมัติ)
- **คำตอบ DNS จาก resolver ของค่ายเน็ตไทย** แยกผลตามค่าย เทียบกับค่าอ้างอิง 8.8.8.8
- ผลแต่ละ resolver: ถูกบล็อก / NXDOMAIN / ตอบต่าง / ปกติ / ไม่ตอบ / ผิดพลาด
- (ตัวเลือก `--http`) เปิดเว็บจริงได้ไหม รหัสตอบกลับเท่าไร

## ติดตั้ง
ต้องใช้ Python 3.8+ และ dnspython ตัวเดียว

```bash
pip install dnspython
# หรือ
pip install -r requirements.txt
```

## วิธีใช้
```bash
./domaincheck.py x.com
./domaincheck.py x.com www.x.com --summary
./domaincheck.py x.com --http --json out.json
./domaincheck.py --file list.txt          # ไฟล์บรรทัดละโดเมน เช่น x.com
./domaincheck.py --help
```

ตัวเลือกหลัก

| ตัวเลือก | ความหมาย |
|---|---|
| `-f, --file` | ไฟล์รายชื่อโดเมน บรรทัดละโดเมน (`#` = คอมเมนต์) |
| `-r, --resolver-file` | ใช้ resolver เอง (บรรทัดละตัว: `IP [ชื่อค่าย]`) |
| `-j, --jobs` | จำนวนคำขอพร้อมกัน (ค่าเริ่มต้น 6) |
| `-t, --timeout` | หมดเวลาแต่ละคำขอ (วินาที) |
| `--http` | เปิดเว็บจริงด้วย |
| `--summary` | แสดงแค่สรุปตามค่าย |
| `--json PATH` | บันทึกผลทั้งหมดเป็น JSON |
| `--no-rdap` | ข้ามการตรวจทะเบียน |

**รหัสออก:** `0` = ไม่พบการบล็อก, `1` = พบการบล็อก, `2` = ใช้ผิดวิธี

## ข้อจำกัด
- ต้องรันจากเครือข่ายในไทย resolver ของค่ายไทยส่วนใหญ่ไม่ตอบคำขอจากต่างประเทศ (จะขึ้น "ไม่ตอบ")
- เห็นแค่ชั้น DNS ถ้าค่ายบล็อกที่ชั้น HTTP/SNI จะดูปกติจากตรงนี้
- โดเมนที่ใช้ CDN อาจขึ้น "ตอบต่าง" เป็นปกติ ไม่ได้แปลว่าโดนบล็อก
- ยังไม่รองรับโดเมนภาษาไทย (IDN) ให้ใส่เป็น punycode `xn--...` แทน

---

## English

**domaincheck** checks whether a domain is blocked by Thai ISPs by querying the DNS resolvers of major Thai home-internet providers and comparing their answers with 8.8.8.8. It also shows registration status via RDAP and can optionally probe HTTP(S).

```bash
pip install dnspython
./domaincheck.py x.com
./domaincheck.py x.com www.x.com --summary --json out.json
```

Exit code `0` = no blocking found, `1` = blocked by at least one resolver, `2` = usage error. Run it from a Thai network; most Thai ISP resolvers do not answer queries from abroad. It only sees DNS-level blocking.
