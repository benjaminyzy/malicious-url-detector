import json
import os
import sys
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.voting_classifier import classify_url

DB_DIR = os.path.join(os.path.dirname(__file__), "..", "database")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "classifications.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


class Base(DeclarativeBase):
    pass


class Classification(Base):
    __tablename__ = "classifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String, nullable=False)
    final_result = Column(String, nullable=False)
    final_label = Column(Integer, nullable=False)
    confidence = Column(Float, nullable=False)
    rf_prediction = Column(Integer)
    xgb_prediction = Column(Integer)
    rule_prediction = Column(Integer, nullable=False)
    votes_for_malicious = Column(Integer, nullable=False)
    triggered_rules = Column(String, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


app = FastAPI(title="Malicious URL Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)


class URLRequest(BaseModel):
    url: str


@app.post("/classify")
def classify(req: URLRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL must not be empty")

    result = classify_url(req.url.strip())

    rf_key = next((k for k in result if k.endswith("_prediction") and "random_forest" in k), None)
    xgb_key = next((k for k in result if k.endswith("_prediction") and "xgboost" in k), None)

    with Session(engine) as session:
        row = Classification(
            url=result["url"],
            final_result=result["final_result"],
            final_label=result["final_label"],
            confidence=result["confidence"],
            rf_prediction=result.get(rf_key),
            xgb_prediction=result.get(xgb_key),
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
def history(limit: int = Query(default=50, le=200)):
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
                "rf_prediction": r.rf_prediction,
                "xgb_prediction": r.xgb_prediction,
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
        total = session.query(func.count(Classification.id)).scalar()
        malicious = session.query(func.count(Classification.id)).filter(Classification.final_label == 1).scalar()
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
            "total_benign": benign,
            "malicious_percentage": malicious_pct,
            "recent_threats": [
                {"url": r.url, "confidence": r.confidence, "timestamp": r.timestamp.isoformat()}
                for r in recent_threats
            ],
        }


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
