import os
from typing import Dict, Any


class OCREngine:
    def extract_text_from_image(self, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            return {"extracted_text": "", "status": "file_not_found"}

        extracted_text = ""
        try:
            from PIL import Image
            import pytesseract
            img = Image.open(file_path)
            extracted_text = pytesseract.image_to_string(img)
            return {
                "extracted_text": extracted_text.strip(),
                "status": "success",
                "length": len(extracted_text)
            }
        except Exception:
            return {
                "extracted_text": "",
                "status": "ocr_unavailable_or_non_image",
                "length": 0
            }


ocr_engine = OCREngine()
