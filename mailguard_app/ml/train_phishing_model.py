import os
import csv
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score


CSV_DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "ml_models", "email.csv")


def load_csv_dataset():
    """Load the 5,500+ entry SMS Spam Collection CSV and relabel for phishing detection.
    
    Many SMS spam messages exhibit phishing characteristics (credential harvesting,
    urgency tactics, deceptive links), making this dataset useful for phishing
    detection when combined with phishing-specific hand-crafted samples.
    """
    texts = []
    labels = []
    csv_path = os.path.abspath(CSV_DATASET_PATH)

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            category = row.get("Category", "").strip().lower()
            message = row.get("Message", "").strip()
            if not message:
                continue
            if category == "spam":
                texts.append(message)
                labels.append(1)
            elif category == "ham":
                texts.append(message)
                labels.append(0)

    return texts, labels


def get_phishing_specific_data():
    """Hand-crafted phishing-specific samples covering corporate and enterprise attack patterns."""
    texts = [
        # ===== PHISHING (label=1) =====
        # Credential harvesting
        "Urgent action required: Update your Microsoft Office 365 credentials to prevent account termination.",
        "Your Google Workspace storage is 99% full. Log in to your portal to purchase extra storage.",
        "IT Support Notice: Click here to authenticate your VPN session certificate immediately.",
        "Payroll department update: Direct deposit banking information must be re-confirmed.",
        "Security Alert: Your PayPal account has been limited due to suspicious unauthorized transactions.",
        "HR Notice: Mandatory employee survey. Sign in with your company email and password.",
        "Your Apple ID has been locked for security reasons. Confirm your identity immediately.",
        "Wire Transfer Notification: A transfer of $45,000 is pending your confirmation. Click to approve.",
        "Shared document on OneDrive: Click to view confidential financial appraisal.",
        # Corporate impersonation
        "From the CEO: I need you to process an urgent wire transfer. Keep this confidential.",
        "IT Security Team: Your account credentials expire in 2 hours. Reset immediately at this link.",
        "Human Resources Department: Review your updated compensation package at this portal.",
        "Helpdesk Support Ticket #48291: Your password reset request. Click to set new password.",
        "Office 365 Admin: Your mailbox has been flagged for unusual activity. Verify ownership.",
        # Banking phishing
        "Your Chase bank account shows suspicious activity. Login now to secure your account.",
        "Wells Fargo Alert: A payment of $3,245 was sent from your account. If unauthorized, click here.",
        "Bank of America: Confirm your identity to prevent account closure. Verify in 24 hours.",
        "HSBC Security: Your online banking access has been temporarily disabled. Reactivate now.",
        # Service impersonation
        "Netflix: Your billing information could not be verified. Update payment to avoid interruption.",
        "Amazon Prime membership expiring! Click here to renew at our special discounted rate.",
        "Your DHL shipment is on hold. Enter customs verification details to release package.",
        "Spotify Premium: Your subscription payment failed. Update card details immediately.",
        # Technical phishing
        "GitHub: Your repository access token has expired. Regenerate it here to maintain access.",
        "AWS notification: Your account may be compromised. Reset root credentials immediately.",
        "Your domain registration expires tomorrow. Renew now to prevent website shutdown.",
        "FINAL NOTICE: Your email account will be permanently deleted in 12 hours. Verify now.",
        "Action Required: Suspicious login from Moscow, Russia. Confirm if this was you.",
        "Multi-factor authentication setup required by company policy. Complete enrollment now.",
        "System Administrator: All employees must validate their network credentials by end of day.",
        "Password expired: Your corporate directory password must be changed within 1 hour.",
        "Docusign: Please sign the confidential document by clicking the secure link below.",
        "Zoom: Your scheduled meeting recording is available. Login to view the video.",
        "Slack notification: Urgent message from your manager. Sign in to read the confidential note.",
        "Jira ticket assigned: Critical production outage. Login to view incident details now.",
        "Google Drive: A shared document requires your authentication. Sign in to view.",
        "IRS Notice: You have an outstanding tax refund of $2,847. Submit bank details for deposit.",
        "Social Security Administration: Your SSN has been suspended. Call immediately to verify.",
        "Microsoft Teams: You have been mentioned in a channel. Login to respond.",
        "Your webmail certificate has expired. Re-authenticate to continue accessing your email.",
        "Compliance team requires your immediate signature on updated privacy agreement.",

        # ===== LEGITIMATE (label=0) =====
        "Hi Team, please find the minutes from yesterday's retrospective meeting attached.",
        "Let me know if you are free for a quick sync at 3 PM today regarding the client feedback.",
        "The build has completed successfully on Jenkins and deployed to the QA environment.",
        "Please check the updated design specifications in Figma when you have a moment.",
        "Reminder that the office will be closed on Monday for the national holiday.",
        "Here is the summary of the quarterly OKR achievements across engineering teams.",
        "Can you approve the pull request for the database migration when you get a chance?",
        "Thank you for your assistance with the customer onboarding process earlier today.",
        "The team meeting agenda has been updated with the items discussed on Slack.",
        "Please submit your travel expense reports before Friday for timely reimbursement.",
        "Good morning, the daily standup will cover sprint progress and upcoming blockers.",
        "I've finished reviewing the architecture decision record. My comments are inline.",
        "The staging environment has been refreshed with last night's production snapshot.",
        "Congratulations to the DevOps team for achieving zero-downtime deployments this quarter!",
        "The user acceptance testing phase begins next Monday. Please prepare your test cases.",
        "Updated the wiki page with the new API endpoint documentation.",
        "The load testing results show the API handles 10K concurrent requests without degradation.",
        "Thank you for the excellent customer demo today. The client was very impressed.",
        "Weekly engineering newsletter: New Kubernetes cluster is now available for testing.",
        "I will be out of office next Tuesday for a medical appointment. John will cover for me.",
        "The security training completion rate has reached 95%. Great job team!",
        "Hi, here are the benchmark results comparing the two database solutions.",
        "Reminder: Team happy hour this Thursday at 5 PM at the rooftop lounge.",
        "The feature flag for dark mode has been enabled in the development environment.",
        "Monthly infrastructure cost optimization report is attached for your review.",
        "Hi, I've prepared the onboarding checklist for the three new engineers starting Monday.",
        "The mobile app release candidate has been submitted to the App Store for review.",
        "Good news: The client approved our proposal. We can begin the implementation phase.",
        "Here is the proposed timeline for the legacy system migration project.",
        "The A/B testing results for the new checkout flow are ready in the analytics dashboard.",
        "Please review the incident postmortem for last week's service disruption.",
        "The backup restoration test completed successfully. Recovery time was under 30 minutes.",
        "Morning update: Deployment to production is planned for tonight at 11 PM EST.",
        "The contract renewal documents have been forwarded to the legal department for review.",
        "I've scheduled one-on-ones with each team member for career development conversations.",
        "The open source library contribution guidelines have been updated. Please review.",
        "Reminder: Complete your self-assessment for the annual performance review cycle.",
        "The data center migration checkpoint meeting is set for next Thursday.",
        "Thanks for organizing the knowledge sharing session. The feedback was overwhelmingly positive.",
        "Hi everyone, attached are the updated API documentation and changelog.",
        "The third-party integration test results look good. All endpoints responded correctly.",
    ]
    # Count actual phishing samples (lines 52-93 = 40 phishing, then legitimate)
    # Use a safer approach: count by splitting
    phishing_count = 40
    legitimate_count = len(texts) - phishing_count
    labels = [1] * phishing_count + [0] * legitimate_count
    return texts, labels


def train_and_save_phishing_model(output_path: str = "./ml_models/phishing_model.pkl") -> dict:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Load primary CSV dataset (spam messages share traits with phishing)
    try:
        csv_texts, csv_labels = load_csv_dataset()
    except FileNotFoundError:
        csv_texts, csv_labels = [], []

    # Load phishing-specific hand-crafted data
    phish_texts, phish_labels = get_phishing_specific_data()

    # Combine datasets
    texts = csv_texts + phish_texts
    labels = csv_labels + phish_labels

    if len(texts) < 10:
        raise RuntimeError("Insufficient training data. Ensure email.csv exists in ml_models/.")

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            lowercase=True,
            max_features=15000,
            min_df=2,
            sublinear_tf=True
        )),
        ("classifier", LogisticRegression(C=1.0, max_iter=500, class_weight="balanced"))
    ])

    # Compute real cross-validated metrics
    try:
        cv_accuracy = cross_val_score(pipeline, texts, labels, cv=5, scoring="accuracy")
        cv_f1 = cross_val_score(pipeline, texts, labels, cv=5, scoring="f1")
        cv_precision = cross_val_score(pipeline, texts, labels, cv=5, scoring="precision")
        cv_recall = cross_val_score(pipeline, texts, labels, cv=5, scoring="recall")
        metrics = {
            "accuracy": round(float(cv_accuracy.mean()), 4),
            "f1_score": round(float(cv_f1.mean()), 4),
            "precision": round(float(cv_precision.mean()), 4),
            "recall": round(float(cv_recall.mean()), 4),
        }
    except Exception:
        metrics = {"accuracy": 0.0, "f1_score": 0.0, "precision": 0.0, "recall": 0.0}

    # Final fit on all data
    pipeline.fit(texts, labels)
    joblib.dump(pipeline, output_path)

    return {
        "model_name": "phishing_logistic_regression",
        "file_path": output_path,
        "sample_count": len(texts),
        "csv_samples": len(csv_texts),
        "supplementary_samples": len(phish_texts),
        "status": "trained",
        "metrics": metrics
    }


if __name__ == "__main__":
    result = train_and_save_phishing_model()
    print(result)
