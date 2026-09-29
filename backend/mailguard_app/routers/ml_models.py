from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.database import get_db
from mailguard_app.models.ml_model import MLModelRegistry
from mailguard_app.core.dependencies import require_admin
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.ml_models import (
    MLModelResponse,
    MLPredictRequest,
    MLPredictResponse,
    MLRetrainRequest
)
from mailguard_app.ml.predict import predictor
from mailguard_app.ml.model_registry import get_model_registry
from mailguard_app.ml.train_spam_model import train_and_save_spam_model
from mailguard_app.ml.train_phishing_model import train_and_save_phishing_model

router = APIRouter(prefix="/ml-models", tags=["Admin ML Models & Classifier Tuning"])


@router.get("", response_model=List[MLModelResponse])
async def list_registered_models(
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(MLModelRegistry).order_by(MLModelRegistry.created_at.desc())
    models = (await db.execute(stmt)).scalars().all()
    return models


@router.post("/predict", response_model=MLPredictResponse)
async def test_live_prediction(
    payload: MLPredictRequest,
    admin_user: TokenPayload = Depends(require_admin)
):
    result = predictor.predict_all(payload.subject, payload.body)
    return MLPredictResponse(
        spam_score=result["spam_score"],
        phishing_score=result["phishing_score"],
        verdict=result["verdict"],
        heuristics=result["heuristics"]
    )


@router.get("/live-metrics")
async def get_live_model_metrics(
    admin_user: TokenPayload = Depends(require_admin)
):
    """Return real cross-validated metrics by re-evaluating training data."""
    from sklearn.model_selection import cross_val_score
    from mailguard_app.ml.train_spam_model import load_csv_dataset as load_spam_csv, get_supplementary_spam_data
    from mailguard_app.ml.train_phishing_model import load_csv_dataset as load_phish_csv, get_phishing_specific_data

    registry = get_model_registry()
    results = []

    # Spam model metrics — combine CSV + supplementary data
    try:
        csv_t, csv_l = load_spam_csv()
        sup_t, sup_l = get_supplementary_spam_data()
        spam_texts = csv_t + sup_t
        spam_labels = csv_l + sup_l
        spam_acc = cross_val_score(registry.spam_model, spam_texts, spam_labels, cv=5, scoring="accuracy")
        spam_f1 = cross_val_score(registry.spam_model, spam_texts, spam_labels, cv=5, scoring="f1")
        spam_prec = cross_val_score(registry.spam_model, spam_texts, spam_labels, cv=5, scoring="precision")
        spam_rec = cross_val_score(registry.spam_model, spam_texts, spam_labels, cv=5, scoring="recall")
        results.append({
            "model_name": "Spam MultinomialNB",
            "version": "v2.0.0",
            "sample_count": len(spam_texts),
            "accuracy": round(float(spam_acc.mean()) * 100, 1),
            "f1_score": round(float(spam_f1.mean()), 3),
            "precision": round(float(spam_prec.mean()) * 100, 1),
            "recall": round(float(spam_rec.mean()) * 100, 1),
        })
    except Exception as e:
        results.append({
            "model_name": "Spam MultinomialNB",
            "version": "v2.0.0",
            "sample_count": 0,
            "accuracy": 0.0,
            "f1_score": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "error": str(e)
        })

    # Phishing model metrics — combine CSV + supplementary data
    try:
        csv_t2, csv_l2 = load_phish_csv()
        sup_t2, sup_l2 = get_phishing_specific_data()
        phish_texts = csv_t2 + sup_t2
        phish_labels = csv_l2 + sup_l2
        phish_acc = cross_val_score(registry.phishing_model, phish_texts, phish_labels, cv=5, scoring="accuracy")
        phish_f1 = cross_val_score(registry.phishing_model, phish_texts, phish_labels, cv=5, scoring="f1")
        phish_prec = cross_val_score(registry.phishing_model, phish_texts, phish_labels, cv=5, scoring="precision")
        phish_rec = cross_val_score(registry.phishing_model, phish_texts, phish_labels, cv=5, scoring="recall")
        results.append({
            "model_name": "Phishing LogisticRegression",
            "version": "v2.0.0",
            "sample_count": len(phish_texts),
            "accuracy": round(float(phish_acc.mean()) * 100, 1),
            "f1_score": round(float(phish_f1.mean()), 3),
            "precision": round(float(phish_prec.mean()) * 100, 1),
            "recall": round(float(phish_rec.mean()) * 100, 1),
        })
    except Exception as e:
        results.append({
            "model_name": "Phishing LogisticRegression",
            "version": "v2.0.0",
            "sample_count": 0,
            "accuracy": 0.0,
            "f1_score": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "error": str(e)
        })

    return results


@router.post("/retrain")
async def trigger_model_retraining(
    payload: MLRetrainRequest,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    results = {}
    if payload.model_type in ["SPAM", "ALL"]:
        res_spam = train_and_save_spam_model()
        results["spam_model"] = res_spam

    if payload.model_type in ["PHISHING", "ALL"]:
        res_phish = train_and_save_phishing_model()
        results["phishing_model"] = res_phish

    get_model_registry().reload()
    return {
        "status": "success",
        "retrained_models": results
    }
