"""
=============================================================================
PII Shield — OCR Pipeline for Unstructured Media
=============================================================================
Extracts text from images (ID cards, screenshots, scanned documents)
using Tesseract OCR + OpenCV preprocessing, then feeds the extracted
text through the Presidio PII detection pipeline.

Pipeline:
  1. Load image with OpenCV
  2. Preprocess: grayscale → denoise → adaptive threshold → deskew
  3. Run Tesseract OCR to extract text
  4. Pass extracted text through Presidio analyzer
  5. Return redacted text

BONUS — Conceptual Image Redaction:
  For drawing black bounding boxes over PII in the original image,
  Presidio provides an ImageRedactorEngine. The conceptual approach:
  
  1. Use Presidio's ImageRedactorEngine with a configured OCR engine
  2. The engine internally:
     a. Runs OCR to get text + bounding box coordinates
     b. Maps Presidio NER results back to bounding box positions
     c. Draws filled black rectangles over detected PII regions
  3. Output: A new image with PII visually redacted
  
  Code sketch (requires presidio-image-redactor package):
  
      from presidio_image_redactor import ImageRedactorEngine
      from PIL import Image
      
      engine = ImageRedactorEngine()
      image = Image.open("id_card.png")
      redacted_image = engine.redact(image, fill=(0, 0, 0))  # Black boxes
      redacted_image.save("id_card_redacted.png")
  
  This approach is used in production for redacting scanned passports,
  driver's licenses, and medical records.
=============================================================================
"""

import logging
import os

logger = logging.getLogger(__name__)

# Cached EasyOCR reader (model loading is expensive — only do it once)
_easyocr_reader = None

def _get_easyocr_reader():
    global _easyocr_reader
    if _easyocr_reader is None:
        import easyocr
        _easyocr_reader = easyocr.Reader(["en"], gpu=False, verbose=False)
        logger.info("EasyOCR reader initialised (cached for reuse)")
    return _easyocr_reader


def preprocess_image(filepath: str):
    """
    Preprocess an image for optimal OCR accuracy using OpenCV.
    
    Steps:
      1. Convert to grayscale (removes color noise)
      2. Apply bilateral filter (removes noise while preserving edges)
      3. Apply adaptive thresholding (handles uneven lighting)
      4. Optional: morphological operations to clean up
    
    Returns:
        Preprocessed image (numpy array) ready for Tesseract
    """
    import cv2

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Image file not found: {filepath}")

    # Load image
    image = cv2.imread(filepath)
    if image is None:
        raise ValueError(f"Could not read image: {filepath}")

    # Step 1: Convert to grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Step 2: Denoise while preserving edges
    denoised = cv2.bilateralFilter(gray, 11, 17, 17)

    # Step 3: Adaptive thresholding for uneven lighting
    # (common in phone photos of ID cards)
    thresh = cv2.adaptiveThreshold(
        denoised, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        blockSize=11,
        C=2,
    )

    logger.info("Image preprocessed: %s (%dx%d)", 
                os.path.basename(filepath), thresh.shape[1], thresh.shape[0])
    return thresh


def extract_text_from_image(filepath: str) -> str:
    """
    Extract text from an image using Tesseract OCR, falling back to EasyOCR
    if Tesseract is not installed.
    """
    # Try Tesseract first
    _tess_err = None
    try:
        import pytesseract
        from config import TESSERACT_CMD

        if TESSERACT_CMD:
            pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD

        preprocessed = preprocess_image(filepath)
        custom_config = r"--oem 3 --psm 6"
        text = pytesseract.image_to_string(preprocessed, config=custom_config)
        logger.info("OCR (Tesseract) extracted %d characters from %s", len(text), os.path.basename(filepath))
        return text.strip()
    except Exception as tess_err:
        _tess_err = tess_err
        logger.warning("Tesseract unavailable (%s), trying EasyOCR...", tess_err)

    # Fallback: EasyOCR (pure Python, no system binary needed)
    try:
        reader = _get_easyocr_reader()
        results = reader.readtext(filepath, detail=0)
        text = "\n".join(results)
        logger.info("OCR (EasyOCR) extracted %d characters from %s", len(text), os.path.basename(filepath))
        return text.strip()
    except Exception as easy_err:
        logger.error("EasyOCR also failed: %s", easy_err)
        raise RuntimeError(
            f"No OCR engine available. Install Tesseract or easyocr. "
            f"Tesseract error: {_tess_err}, EasyOCR error: {easy_err}"
        )


def process_image_for_pii(
    filepath: str,
    analyze_fn,
    anonymize_fn,
) -> dict:
    """
    Full OCR-to-PII pipeline for image files.
    
    Args:
        filepath: Path to image file (PNG, JPG, etc.)
        analyze_fn: Function(text) -> List[RecognizerResult]
        anonymize_fn: Function(text, results) -> str
        
    Returns:
        dict with:
          - extracted_text: Raw OCR output
          - entities_found: Number of PII entities detected
          - redacted_text: Text with PII masked/replaced
    """
    # Step 1: Extract text via OCR
    extracted_text = extract_text_from_image(filepath)

    if not extracted_text:
        logger.warning("No text extracted from image: %s", filepath)
        return {
            "extracted_text": "",
            "entities_found": 0,
            "redacted_text": "",
        }

    # Step 2: Run Presidio analysis
    results = analyze_fn(extracted_text)

    # Step 3: Anonymize
    redacted_text = anonymize_fn(extracted_text, results) if results else extracted_text

    return {
        "extracted_text": extracted_text,
        "entities_found": len(results),
        "redacted_text": redacted_text,
    }
