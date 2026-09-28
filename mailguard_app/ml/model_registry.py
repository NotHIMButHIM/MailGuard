import os
import joblib
from typing import Optional, Any
from mailguard_app.ml.train_spam_model import train_and_save_spam_model
from mailguard_app.ml.train_phishing_model import train_and_save_phishing_model


class ModelRegistry:
    _instance: Optional["ModelRegistry"] = None

    def __init__(self):
        self.spam_model: Optional[Any] = None
        self.phishing_model: Optional[Any] = None
        self.spam_model_path: str = "./ml_models/spam_model.pkl"
        self.phishing_model_path: str = "./ml_models/phishing_model.pkl"
        self.load_models()

    @classmethod
    def get_instance(cls) -> "ModelRegistry":
        if cls._instance is None:
            cls._instance = ModelRegistry()
        return cls._instance

    def load_models(self):
        if not os.path.exists(self.spam_model_path):
            train_and_save_spam_model(self.spam_model_path)
        if not os.path.exists(self.phishing_model_path):
            train_and_save_phishing_model(self.phishing_model_path)

        try:
            self.spam_model = joblib.load(self.spam_model_path)
        except Exception:
            train_and_save_spam_model(self.spam_model_path)
            self.spam_model = joblib.load(self.spam_model_path)

        try:
            self.phishing_model = joblib.load(self.phishing_model_path)
        except Exception:
            train_and_save_phishing_model(self.phishing_model_path)
            self.phishing_model = joblib.load(self.phishing_model_path)

    def reload(self):
        self.load_models()


def get_model_registry() -> ModelRegistry:
    return ModelRegistry.get_instance()
