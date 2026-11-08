from sqlalchemy import text

from app import models  # noqa: F401  (wajib di-import agar model terdaftar)
from app.database import Base, engine

if __name__ == "__main__":
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        conn.execute(
            text("ALTER TABLE invoices ADD COLUMN IF NOT EXISTS expired_at TIMESTAMP WITH TIME ZONE;")
        )
        conn.commit()
    print("Tabel berhasil dibuat.")
