# FastAPI backend for the malicious URL detector

import json
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, DateTime, Float, Integer, String,
    create_engine, func,
)
from sqlalchemy.orm import DeclarativeBase, Session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.voting_classifier import _ensure_loaded, classify_url

DB_DIR = os.path.join(os.path.dirname(__file__), "..", "database")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "classifications.db")
engine = create_engine(
    f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False}
)

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}


class Base(DeclarativeBase):
    pass


class Classification(Base):
    __tablename__ = "classifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String, nullable=False)
    final_result = Column(String, nullable=False)
    final_label = Column(Integer, nullable=False)
    confidence = Column(Float, nullable=False)
    model1_prediction = Column(Integer)
    model2_prediction = Column(Integer)
    model1_proba = Column(Float)
    model2_proba = Column(Float)
    rule_prediction = Column(Integer, nullable=False)
    votes_for_malicious = Column(Integer, nullable=False)
    triggered_rules = Column(String, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    _ensure_loaded()
    yield


app = FastAPI(title="Malicious URL Detector API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)


def _validate_url(raw):
    url = raw.strip()
    if not url:
        raise HTTPException(400, "URL must not be empty")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(400, f"URL exceeds {MAX_URL_LENGTH} characters")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise HTTPException(400, "Only http:// and https:// URLs are supported")
    if not parsed.netloc:
        raise HTTPException(400, "URL must include a valid host")
    return url


def _split_components(result):
    # Pull the two ML preds/probas regardless of which models were selected.
    pred_keys = sorted([k for k in result if k.endswith("_prediction")
                        and k != "rule_prediction"])
    proba_keys = sorted([k for k in result if k.endswith("_proba")])
    pred1 = result.get(pred_keys[0]) if len(pred_keys) > 0 else None
    pred2 = result.get(pred_keys[1]) if len(pred_keys) > 1 else None
    proba1 = result.get(proba_keys[0]) if len(proba_keys) > 0 else None
    proba2 = result.get(proba_keys[1]) if len(proba_keys) > 1 else None
    return pred1, pred2, proba1, proba2


@app.post("/classify")
def classify(req: URLRequest):
    url = _validate_url(req.url)
    result = classify_url(url)
    pred1, pred2, proba1, proba2 = _split_components(result)

    with Session(engine) as session:
        row = Classification(
            url=result["url"],
            final_result=result["final_result"],
            final_label=result["final_label"],
            confidence=result["confidence"],
            model1_prediction=pred1,
            model2_prediction=pred2,
            model1_proba=proba1,
            model2_proba=proba2,
            rule_prediction=result["rule_prediction"],
            votes_for_malicious=result["votes_for_malicious"],
            triggered_rules=json.dumps(result["triggered_rules"]),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        result["id"] = row.id
        result["timestamp"] = row.timestamp.isoformat()

    return result


@app.get("/history")
def history(limit: int = Query(default=50, ge=1, le=200)):
    with Session(engine) as session:
        rows = (
            session.query(Classification)
            .order_by(Classification.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "url": r.url,
                "final_result": r.final_result,
                "final_label": r.final_label,
                "confidence": r.confidence,
                "model1_prediction": r.model1_prediction,
                "model2_prediction": r.model2_prediction,
                "model1_proba": r.model1_proba,
                "model2_proba": r.model2_proba,
                "rule_prediction": r.rule_prediction,
                "votes_for_malicious": r.votes_for_malicious,
                "triggered_rules": json.loads(r.triggered_rules),
                "timestamp": r.timestamp.isoformat(),
            }
            for r in rows
        ]


@app.get("/stats")
def stats():
    with Session(engine) as session:
        total = session.query(func.count(Classification.id)).scalar() or 0
        malicious = (
            session.query(func.count(Classification.id))
            .filter(Classification.final_label == 1)
            .scalar()
            or 0
        )
        # Server-side tier breakdown so dashboard metrics scale with DB size.
        suspicious = (
            session.query(func.count(Classification.id))
            .filter(Classification.final_label == 1)
            .filter(Classification.confidence < 66)
            .scalar()
            or 0
        )
        malicious_high_conf = malicious - suspicious
        benign = total - malicious
        malicious_pct = round(malicious / total * 100, 1) if total else 0.0

        recent_threats = (
            session.query(Classification)
            .filter(Classification.final_label == 1)
            .order_by(Classification.timestamp.desc())
            .limit(5)
            .all()
        )

        return {
            "total_scanned": total,
            "total_malicious": malicious,
            "total_malicious_high_conf": malicious_high_conf,
            "total_suspicious": suspicious,
            "total_benign": benign,
            "malicious_percentage": malicious_pct,
            "recent_threats": [
                {
                    "url": r.url,
                    "confidence": r.confidence,
                    "timestamp": r.timestamp.isoformat(),
                }
                for r in recent_threats
            ],
        }


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
