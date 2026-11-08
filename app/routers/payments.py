import hashlib
import hmac
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import authorize_role
from app.models import Enrollment, Invoice, Order, Payment, User
from app.schemas import (
    ApiResponse, PaymentCallbackIn, PaymentCreateIn, PaymentOut, ok,
)

router = APIRouter(prefix="/payments", tags=["Payments"])


@router.post("", status_code=201, response_model=ApiResponse[PaymentOut])
def create_payment(
    body: PaymentCreateIn,
    db: Session = Depends(get_db),
    user: User = Depends(authorize_role("student")),
):
    invoice = db.get(Invoice, body.invoice_id)
    order = db.get(Order, invoice.order_id) if invoice else None
    if invoice is None or order.student_id != user.id:
        raise HTTPException(404, "Invoice tidak ditemukan")
    if invoice.status != "unpaid":
        raise HTTPException(409, "Invoice sudah dibayar atau tidak aktif")

    now = datetime.now(timezone.utc)
    if invoice.expired_at:
        exp = invoice.expired_at if invoice.expired_at.tzinfo else invoice.expired_at.replace(tzinfo=timezone.utc)
        if exp < now:
            raise HTTPException(409, "Invoice sudah kedaluwarsa")

    pending = db.scalar(
        select(Payment).where(Payment.invoice_id == invoice.id, Payment.status == "pending")
    )
    if pending:
        raise HTTPException(409, "Masih ada pembayaran yang menunggu untuk invoice ini")

    payment = Payment(
        invoice_id=invoice.id,
        method=body.method,
        amount=invoice.amount,
        external_ref=f"SB-{uuid.uuid4().hex[:12].upper()}",
    )
    db.add(payment)
    db.commit()
    return ok(payment, "Pembayaran dibuat, menunggu konfirmasi gateway")


@router.get("/{payment_id}", response_model=ApiResponse[PaymentOut])
def get_payment(
    payment_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(authorize_role("student", "admin")),
):
    payment = db.get(Payment, payment_id)
    if payment is None:
        raise HTTPException(404, "Pembayaran tidak ditemukan")

    invoice = db.get(Invoice, payment.invoice_id)
    order = db.get(Order, invoice.order_id) if invoice else None
    if order is None or (user.role != "admin" and order.student_id != user.id):
        raise HTTPException(404, "Pembayaran tidak ditemukan")

    return ok(payment)


@router.post("/callback", response_model=ApiResponse[PaymentOut])
async def payment_callback(
    request: Request,
    body: PaymentCallbackIn,
    x_callback_signature: str | None = Header(default=None, alias="X-Callback-Signature"),
    db: Session = Depends(get_db),
):
    # 1) Validasi signature HMAC-SHA256 atas raw body
    raw_body = await request.body()
    signature = (
        x_callback_signature
        or request.headers.get("X-Callback-Signature")
        or request.headers.get("X-Signature")
        or request.headers.get("X-Signature-SHA256")
        or request.headers.get("X-Hub-Signature-256")
        or request.headers.get("X-Callback-Token")
    )
    if not signature:
        raise HTTPException(401, "Callback signature tidak ditemukan")

    sig = signature.removeprefix("sha256=").strip()
    expected = hmac.new(
        settings.payment_callback_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(sig.lower(), expected.lower()):
        raise HTTPException(401, "Callback signature tidak valid")

    # 2) Kunci baris payment agar callback ganda tidak balapan
    payment = db.scalar(
        select(Payment).where(Payment.external_ref == body.external_ref).with_for_update()
    )
    if payment is None:
        raise HTTPException(404, "Pembayaran tidak ditemukan")

    # 3) Idempotent: callback yang sudah diproses tidak diproses ulang
    if payment.status != "pending":
        return ok(payment, "Callback sudah pernah diproses")

    # 4) Nominal harus cocok
    if body.amount != payment.amount:
        raise HTTPException(422, "Nominal callback tidak sesuai dengan tagihan")

    if body.status == "failed":
        payment.status = "failed"
        db.commit()
        return ok(payment, "Pembayaran ditandai gagal")

    # 5) Cek invoice dan kedaluwarsa untuk callback 'paid'
    invoice = db.get(Invoice, payment.invoice_id)
    if invoice is None:
        raise HTTPException(404, "Invoice tidak ditemukan")

    now = datetime.now(timezone.utc)
    if invoice.expired_at:
        exp = invoice.expired_at if invoice.expired_at.tzinfo else invoice.expired_at.replace(tzinfo=timezone.utc)
        if exp < now:
            raise HTTPException(409, "Invoice sudah kedaluwarsa")

    # 6) PAID: update payment, invoice, order, enrollment secara konsisten (1 transaksi)
    payment.status = "paid"
    payment.paid_at = now

    invoice.status = "paid"
    invoice.paid_at = now

    order = db.get(Order, invoice.order_id)
    if order:
        order.status = "paid"

    enrollment = db.scalar(select(Enrollment).where(Enrollment.order_id == order.id)) if order else None
    if enrollment:
        enrollment.status = "active"

    db.commit()  # semua berhasil, atau semua dibatalkan
    return ok(payment, "Pembayaran berhasil, enrollment aktif")
