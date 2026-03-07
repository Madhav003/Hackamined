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

Image Redaction:
  The redact_image_pii() function draws black bounding boxes over PII
  in the original image using pytesseract word-level boxes + Presidio
  analyzer, without requiring presidio-image-redactor.
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

    # Step 2: Fast denoise (GaussianBlur is much faster than bilateralFilter)
    denoised = cv2.GaussianBlur(gray, (3, 3), 0)

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


def redact_image_pii(image_path: str, output_path: str, analyzer) -> str:
    """
    OCR the image, find PII with Presidio, draw black boxes over PII words.
    Returns the output_path where the sanitized image was saved.
    """
    import pytesseract
    from PIL import Image, ImageDraw
    from config import TESSERACT_CMD

    if TESSERACT_CMD:
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD

    img = Image.open(image_path).convert("RGB")

    # Resize if too large for speed
    max_dim = 1500
    if max(img.size) > max_dim:
        ratio = max_dim / max(img.size)
        img = img.resize((int(img.size[0]*ratio), int(img.size[1]*ratio)), Image.LANCZOS)

    # Get word-level bounding boxes
    data = pytesseract.image_to_data(img, config="--oem 1 --psm 6", output_type=pytesseract.Output.DICT)

    # Build full text and track each word's position in the string
    words = []
    full_text = ""
    for i, word in enumerate(data["text"]):
        if not word.strip():
            full_text += " "
            continue
        start = len(full_text)
        full_text += word
        end = len(full_text)
        full_text += " "
        words.append({
            "word": word,
            "start": start,
            "end": end,
            "x": data["left"][i],
            "y": data["top"][i],
            "w": data["width"][i],
            "h": data["height"][i],
        })

    # Run Presidio on the full text
    results = analyzer.analyze(text=full_text, language="en")

    # Draw black boxes over words that fall inside any PII span
    draw = ImageDraw.Draw(img)
    for entity in results:
        for word_info in words:
            if word_info["end"] > entity.start and word_info["start"] < entity.end:
                x, y, w, h = word_info["x"], word_info["y"], word_info["w"], word_info["h"]
                draw.rectangle([x, y, x+w, y+h], fill=(0, 0, 0))

    img.save(output_path)
    return output_path


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
        custom_config = r"--oem 1 --psm 6"
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
