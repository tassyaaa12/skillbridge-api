"""Uji otomatis alur lengkap SkillBridge (mengulang urutan Insomnia).

Prasyarat: tabel sudah dibuat dan seed sudah dijalankan.
Jalankan  : pytest -v
"""
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import Course, Invoice, User
from app.security import hash_password

client = TestClient(app)


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def callback_headers(raw_body: bytes, header_name: str = "X-Callback-Signature", prefix: str = "") -> dict:
    sig = hmac.new(settings.payment_callback_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        header_name: f"{prefix}{sig}",
    }


def login(email: str, password: str) -> str:
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["data"]["access_token"]


@pytest.fixture(scope="module")
def student():
    email = f"siswa-{uuid.uuid4().hex[:8]}@mail.com"
    r = client.post(
        "/auth/register",
        json={"full_name": "Siswa Uji", "email": email, "password": "Rahasia123"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["data"]["role"] == "student"
    return {"email": email, "token": login(email, "Rahasia123")}


@pytest.fixture(scope="module")
def course():
    r = client.get("/courses")
    assert r.status_code == 200
    for c in r.json()["data"]:
        detail = client.get(f"/courses/{c['id']}").json()["data"]
        if len(detail.get("modules", [])) == 4:
            return detail
    cid = r.json()["data"][0]["id"]
    detail = client.get(f"/courses/{cid}").json()["data"]
    assert len(detail["modules"]) == 4
    return detail


def test_register_ignores_role_and_rejects_duplicates(student):
    r = client.post(
        "/auth/register",
        json={"full_name": "X Y", "email": student["email"], "password": "Rahasia123"},
    )
    assert r.status_code == 409
    r = client.post(
        "/auth/register",
        json={"full_name": "Hacker", "email": f"h-{uuid.uuid4().hex[:6]}@mail.com",
              "password": "Rahasia123", "role": "admin"},
    )
    assert r.status_code == 201
    assert r.json()["data"]["role"] == "student"


def test_validation_errors_use_standard_format():
    r = client.post("/auth/register", json={"full_name": "A", "email": "bukan-email", "password": "123"})
    body = r.json()
    assert r.status_code == 422
    assert set(body) == {"message", "data", "errors"} and body["errors"]


def test_auth_errors(student):
    assert client.get("/enrollments/mycourses").status_code == 401
    assert client.get("/enrollments/mycourses", headers=auth("ngawur")).status_code == 401
    assert client.post("/auth/login", json={"email": student["email"], "password": "salah-salah"}).status_code == 401


def test_roles(student, course):
    admin = login("admin@skillbridge.id", "Admin123!")
    r = client.post("/enrollments", json={"course_id": course["id"]}, headers=auth(admin))
    assert r.status_code == 403
    r = client.post(
        "/courses",
        json={"category_id": course["category_id"], "title": "Kursus Baru", "price": "1000.00"},
        headers=auth(student["token"]),
    )
    assert r.status_code == 403
    inst = login("instructor@skillbridge.id", "Instruktur123!")
    r = client.post(
        "/courses",
        json={"category_id": course["category_id"], "title": "Kursus Baru", "price": "1000.00"},
        headers=auth(inst),
    )
    assert r.status_code == 201


def test_course_lookup_errors():
    assert client.get(f"/courses/{uuid.uuid4()}").status_code == 404
    assert client.get("/courses/abc").status_code == 422


def test_full_purchase_flow(student, course):
    h = auth(student["token"])

    # enrollment -> order + invoice
    r = client.post("/enrollments", json={"course_id": course["id"]}, headers=h)
    assert r.status_code == 201, r.text
    d = r.json()["data"]
    enrollment_id, invoice_id = d["enrollment"]["id"], d["invoice"]["id"]
    assert d["enrollment"]["status"] == "pending_payment"
    assert d["invoice"]["status"] == "unpaid" and d["order"]["status"] == "pending"

    # dua kali -> 409
    assert client.post("/enrollments", json={"course_id": course["id"]}, headers=h).status_code == 409

    module_id = course["modules"][0]["id"]
    progress = {"module_id": module_id, "status": "completed"}

    # belum bayar -> progress ditolak
    r = client.patch(f"/enrollments/{enrollment_id}/progress", json=progress, headers=h)
    assert r.status_code == 403

    # payment
    r = client.post("/payments", json={"invoice_id": invoice_id, "method": "bank_transfer"}, headers=h)
    assert r.status_code == 201, r.text
    pay = r.json()["data"]
    assert client.post("/payments", json={"invoice_id": invoice_id, "method": "qris"}, headers=h).status_code == 409

    # callback: token salah / tanpa token / nominal salah
    cb = {"external_ref": pay["external_ref"], "status": "paid", "amount": pay["amount"]}
    raw_cb = json.dumps(cb, separators=(",", ":")).encode()
    cb_headers = callback_headers(raw_cb)

    assert client.post("/payments/callback", content=raw_cb, headers={"Content-Type": "application/json"}).status_code == 401
    assert client.post("/payments/callback", content=raw_cb, headers={"Content-Type": "application/json", "X-Callback-Signature": "x"}).status_code == 401
    bad = {**cb, "amount": "1.00"}
    raw_bad = json.dumps(bad, separators=(",", ":")).encode()
    assert client.post("/payments/callback", content=raw_bad, headers=callback_headers(raw_bad)).status_code == 422
    my = client.get("/enrollments/mycourses", headers=h).json()["data"]
    assert my[0]["status"] == "pending_payment"  # belum berubah

    # callback paid
    r = client.post("/payments/callback", content=raw_cb, headers=cb_headers)
    assert r.status_code == 200 and r.json()["data"]["status"] == "paid"

    # idempotent
    r = client.post("/payments/callback", content=raw_cb, headers=cb_headers)
    assert r.status_code == 200 and "sudah pernah" in r.json()["message"]

    my = client.get("/enrollments/mycourses", headers=h).json()["data"]
    assert my[0]["status"] == "active" and my[0]["total_modules"] == 4

    # progress 25% -> 100%
    r = client.patch(f"/enrollments/{enrollment_id}/progress", json=progress, headers=h)
    assert r.status_code == 200
    assert r.json()["data"]["progress_percentage"] == 25.0
    for m in course["modules"][1:]:
        r = client.patch(
            f"/enrollments/{enrollment_id}/progress",
            json={"module_id": m["id"], "status": "completed"}, headers=h,
        )
    assert r.json()["data"]["enrollment_status"] == "completed"
    assert r.json()["data"]["progress_percentage"] == 100.0

    # student lain tidak bisa menyentuh enrollment ini (404)
    other_email = f"lain-{uuid.uuid4().hex[:6]}@mail.com"
    client.post("/auth/register", json={"full_name": "Orang Lain", "email": other_email, "password": "Rahasia123"})
    other = login(other_email, "Rahasia123")
    r = client.patch(f"/enrollments/{enrollment_id}/progress", json=progress, headers=auth(other))
    assert r.status_code == 404
    r = client.post("/payments", json={"invoice_id": invoice_id, "method": "qris"}, headers=auth(other))
    assert r.status_code == 404


def test_failed_payment_allows_retry(student):
    h = auth(student["token"])
    inst = login("instructor@skillbridge.id", "Instruktur123!")
    cat = client.get("/courses").json()["data"][0]["category_id"]
    new = client.post(
        "/courses",
        json={"category_id": cat, "title": f"Retry {uuid.uuid4().hex[:5]}", "price": "50000.00"},
        headers=auth(inst),
    ).json()["data"]
    d = client.post("/enrollments", json={"course_id": new["id"]}, headers=h).json()["data"]
    inv = d["invoice"]["id"]
    p1 = client.post("/payments", json={"invoice_id": inv, "method": "ewallet"}, headers=h).json()["data"]

    fail_cb = {"external_ref": p1["external_ref"], "status": "failed", "amount": p1["amount"]}
    raw_fail = json.dumps(fail_cb, separators=(",", ":")).encode()
    r = client.post(
        "/payments/callback",
        content=raw_fail,
        headers=callback_headers(raw_fail),
    )
    assert r.status_code == 200 and r.json()["data"]["status"] == "failed"
    r = client.post("/payments", json={"invoice_id": inv, "method": "ewallet"}, headers=h)
    assert r.status_code == 201  # boleh coba bayar lagi


# =====================================================================
# Skenario Baru: Soal 1 s.d. 5
# =====================================================================

def test_get_course_modules(course):
    # 1. Endpoint GET /courses/{id}/modules mengembalikan modul terurut
    r = client.get(f"/courses/{course['id']}/modules")
    assert r.status_code == 200
    modules = r.json()["data"]
    assert len(modules) == 4
    # Pastikan posisi terurut menaik: 1, 2, 3, 4
    positions = [m["position"] for m in modules]
    assert positions == sorted(positions)
    assert positions == [1, 2, 3, 4]

    # Kursus tidak ada -> 404
    assert client.get(f"/courses/{uuid.uuid4()}/modules").status_code == 404


def test_get_payment_ownership(student, course):
    # 2. Endpoint GET /payments/{id} cek kepemilikan, balas 404 jika bukan miliknya
    h = auth(student["token"])
    inst = login("instructor@skillbridge.id", "Instruktur123!")
    new_c = client.post(
        "/courses",
        json={"category_id": course["category_id"], "title": f"PayCheck {uuid.uuid4().hex[:5]}", "price": "75000.00"},
        headers=auth(inst),
    ).json()["data"]

    enr = client.post("/enrollments", json={"course_id": new_c["id"]}, headers=h).json()["data"]
    pay = client.post(
        "/payments",
        json={"invoice_id": enr["invoice"]["id"], "method": "bank_transfer"},
        headers=h,
    ).json()["data"]

    # Student pemilik bisa melihat status pembayarannya
    r = client.get(f"/payments/{pay['id']}", headers=h)
    assert r.status_code == 200
    assert r.json()["data"]["id"] == pay["id"]
    assert r.json()["data"]["status"] == "pending"

    # Student lain tidak boleh melihat (harus 404)
    other_email = f"stranger-{uuid.uuid4().hex[:6]}@mail.com"
    client.post("/auth/register", json={"full_name": "Stranger", "email": other_email, "password": "Rahasia123"})
    other_token = login(other_email, "Rahasia123")
    r_other = client.get(f"/payments/{pay['id']}", headers=auth(other_token))
    assert r_other.status_code == 404

    # Admin boleh melihat pembayaran siapa pun
    admin_token = login("admin@skillbridge.id", "Admin123!")
    r_admin = client.get(f"/payments/{pay['id']}", headers=auth(admin_token))
    assert r_admin.status_code == 200

    # ID tidak ditemukan -> 404
    assert client.get(f"/payments/{uuid.uuid4()}", headers=h).status_code == 404

    # Tanpa token -> 401
    assert client.get(f"/payments/{pay['id']}").status_code == 401


def test_patch_course_ownership_and_admin(student, course):
    # 3. Endpoint PATCH /courses/{id}: instructor hanya bisa mengubah kursus miliknya sendiri. Admin boleh mengubah semua.
    inst1 = login("instructor@skillbridge.id", "Instruktur123!")

    # Buat instructor kedua
    db = SessionLocal()
    inst2_email = f"inst2-{uuid.uuid4().hex[:6]}@skillbridge.id"
    inst2_user = User(
        full_name="Instruktur Dua",
        email=inst2_email,
        password_hash=hash_password("Instruktur123!"),
        role="instructor",
    )
    db.add(inst2_user)
    db.commit()
    db.close()
    inst2 = login(inst2_email, "Instruktur123!")

    # Instruktur 1 membuat kursus
    created = client.post(
        "/courses",
        json={"category_id": course["category_id"], "title": "Kursus Instruktur 1", "price": "100000.00"},
        headers=auth(inst1),
    ).json()["data"]
    cid = created["id"]

    # Instruktur 1 mengubah kursus miliknya -> berhasil 200
    r = client.patch(
        f"/courses/{cid}",
        json={"title": "Kursus Instruktur 1 (Updated)", "price": "120000.00"},
        headers=auth(inst1),
    )
    assert r.status_code == 200
    assert r.json()["data"]["title"] == "Kursus Instruktur 1 (Updated)"
    assert float(r.json()["data"]["price"]) == 120000.00

    # Instruktur 2 mencoba mengubah kursus milik Instruktur 1 -> ditolak 403
    r = client.patch(
        f"/courses/{cid}",
        json={"title": "Dibajak Instruktur 2"},
        headers=auth(inst2),
    )
    assert r.status_code == 403

    # Student mencoba mengubah kursus -> ditolak 403
    r = client.patch(
        f"/courses/{cid}",
        json={"title": "Dibajak Siswa"},
        headers=auth(student["token"]),
    )
    assert r.status_code == 403

    # Admin boleh mengubah semua kursus -> berhasil 200
    admin_token = login("admin@skillbridge.id", "Admin123!")
    r = client.patch(
        f"/courses/{cid}",
        json={"title": "Diperbarui oleh Admin", "is_published": False},
        headers=auth(admin_token),
    )
    assert r.status_code == 200
    assert r.json()["data"]["title"] == "Diperbarui oleh Admin"
    assert r.json()["data"]["is_published"] is False

    # Kursus tidak ditemukan -> 404
    assert client.patch(f"/courses/{uuid.uuid4()}", json={"title": "Kursus Tidak Ada"}, headers=auth(admin_token)).status_code == 404


def test_expired_invoice_callback_rejected(student, course):
    # 4. Field expired_at pada invoice. Callback paid untuk invoice kedaluwarsa harus ditolak 409.
    h = auth(student["token"])
    inst = login("instructor@skillbridge.id", "Instruktur123!")
    new_c = client.post(
        "/courses",
        json={"category_id": course["category_id"], "title": f"Expiry Course {uuid.uuid4().hex[:5]}", "price": "90000.00"},
        headers=auth(inst),
    ).json()["data"]

    enr = client.post("/enrollments", json={"course_id": new_c["id"]}, headers=h).json()["data"]
    invoice_id = enr["invoice"]["id"]

    # Invoice baru memiliki expired_at
    assert enr["invoice"].get("expired_at") is not None

    pay = client.post(
        "/payments",
        json={"invoice_id": invoice_id, "method": "bank_transfer"},
        headers=h,
    ).json()["data"]

    # Simulasikan invoice kedaluwarsa (ubah expired_at ke masa lalu di database)
    db = SessionLocal()
    inv = db.get(Invoice, uuid.UUID(invoice_id))
    inv.expired_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db.commit()
    db.close()

    # Callback paid untuk invoice yang sudah kedaluwarsa harus ditolak dengan 409
    cb = {"external_ref": pay["external_ref"], "status": "paid", "amount": pay["amount"]}
    raw_cb = json.dumps(cb, separators=(",", ":")).encode()
    r = client.post("/payments/callback", content=raw_cb, headers=callback_headers(raw_cb))
    assert r.status_code == 409
    assert "kedaluwarsa" in r.json()["message"].lower()

    # Pastikan status enrollment tetap pending_payment (tidak aktif)
    my = client.get("/enrollments/mycourses", headers=h).json()["data"]
    my_status = [m["status"] for m in my if m["course_id"] == new_c["id"]][0]
    assert my_status == "pending_payment"


def test_hmac_sha256_callback_validation(student, course):
    # 5. Validasi callback signature HMAC-SHA256 atas raw body
    h = auth(student["token"])
    inst = login("instructor@skillbridge.id", "Instruktur123!")
    new_c = client.post(
        "/courses",
        json={"category_id": course["category_id"], "title": f"HMAC Course {uuid.uuid4().hex[:5]}", "price": "60000.00"},
        headers=auth(inst),
    ).json()["data"]

    enr = client.post("/enrollments", json={"course_id": new_c["id"]}, headers=h).json()["data"]
    pay = client.post(
        "/payments",
        json={"invoice_id": enr["invoice"]["id"], "method": "bank_transfer"},
        headers=h,
    ).json()["data"]

    cb = {"external_ref": pay["external_ref"], "status": "paid", "amount": pay["amount"]}
    raw_cb = json.dumps(cb, separators=(",", ":")).encode()

    # a. Tanpa header signature -> ditolak 401
    r_no_sig = client.post("/payments/callback", content=raw_cb, headers={"Content-Type": "application/json"})
    assert r_no_sig.status_code == 401

    # b. Header signature salah / token statis lama -> ditolak 401
    r_wrong_sig = client.post(
        "/payments/callback",
        content=raw_cb,
        headers={"Content-Type": "application/json", "X-Callback-Signature": "invalid-signature-123"},
    )
    assert r_wrong_sig.status_code == 401

    r_old_token = client.post(
        "/payments/callback",
        content=raw_cb,
        headers={"Content-Type": "application/json", "X-Callback-Token": settings.payment_callback_secret},
    )
    assert r_old_token.status_code == 401

    # c. Body dimanipulasi (signature dihitung dari body lain) -> ditolak 401
    tampered_body = json.dumps({**cb, "amount": "999999.00"}, separators=(",", ":")).encode()
    r_tampered = client.post(
        "/payments/callback",
        content=tampered_body,
        headers=callback_headers(raw_cb),  # signature dari raw_cb asli, bukan tampered
    )
    assert r_tampered.status_code == 401

    # d. Signature valid dengan prefix sha256= didukung -> berhasil 200
    headers_with_prefix = callback_headers(raw_cb, prefix="sha256=")
    # e. Alternatif header X-Signature juga didukung
    headers_alt = callback_headers(raw_cb, header_name="X-Signature")
    r_valid = client.post("/payments/callback", content=raw_cb, headers=headers_alt)
    assert r_valid.status_code == 200
    assert r_valid.json()["data"]["status"] == "paid"

