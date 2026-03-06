"""
Audio PII Sanitization Handler
================================
Transcribes audio via Whisper (word-level timestamps), detects PII with
Presidio, and overlays a 1 kHz beep on each PII segment using pydub.
"""

import math
import os
import struct
import traceback


def _generate_beep(duration_ms, freq=1000, sample_rate=44100, volume_dbfs=-10):
    """Generate a sine-wave beep as a pydub AudioSegment."""
    from pydub import AudioSegment

    n_samples = int(sample_rate * duration_ms / 1000)
    samples = []
    amplitude = 32767 * (10 ** (volume_dbfs / 20))
    for i in range(n_samples):
        sample = int(amplitude * math.sin(2 * math.pi * freq * i / sample_rate))
        samples.append(struct.pack("<h", max(-32768, min(32767, sample))))

    raw = b"".join(samples)
    return AudioSegment(
        data=raw,
        sample_width=2,
        frame_rate=sample_rate,
        channels=1,
    )


def _ensure_ffmpeg():
    """Point pydub to the imageio-ffmpeg binary so it works without system PATH."""
    try:
        import imageio_ffmpeg
        ffmpeg_path = imageio_ffmpeg.get_ffmpeg_exe()
        from pydub import AudioSegment
        AudioSegment.converter = ffmpeg_path
        AudioSegment.ffprobe = ffmpeg_path  # pydub uses this for probing too
    except ImportError:
        pass  # fallback to system ffmpeg


def process_audio_file(audio_path, sanitize_text_fn, output_dir, doc_id):
    """
    Full audio PII sanitization pipeline.

    Args:
        audio_path:        Path to the input audio file (.mp3, .wav, etc.)
        sanitize_text_fn:  Callable(text) -> masked_text  (your existing Presidio wrapper)
        output_dir:        Directory to write the sanitized .mp3 file.
        doc_id:            Document ID for naming the output file.

    Returns:
        dict with keys: status, sanitized_path, transcript, masked_text,
                        entities, entity_count, threat_level, risk_score, ...
    """
    try:
        _ensure_ffmpeg()
        from pydub import AudioSegment
        import whisper

        # ---- 1. Transcribe with word-level timestamps ----
        print(f"[AUDIO] Loading Whisper model for {os.path.basename(audio_path)}...")
        model = whisper.load_model("base")
        result = model.transcribe(audio_path, word_timestamps=True)

        # Collect all words with their timestamps
        words = []
        for segment in result.get("segments", []):
            for w in segment.get("words", []):
                words.append({
                    "word": w["word"].strip(),
                    "start": int(w["start"] * 1000),  # ms
                    "end": int(w["end"] * 1000),       # ms
                })

        full_transcript = result.get("text", "").strip()
        print(f"[AUDIO] Transcribed {len(words)} words: {full_transcript[:120]}...")

        # ---- 2. Detect PII via existing Presidio pipeline ----
        masked_text = sanitize_text_fn(full_transcript)

        # Figure out which words were redacted by comparing positions
        pii_intervals = []
        cursor = 0
        for w in words:
            # Find this word's approximate position in the original transcript
            pos = full_transcript.find(w["word"], cursor)
            if pos == -1:
                pos = cursor
            word_end_pos = pos + len(w["word"])

            # Check if this region is masked in the output
            # (the masked_text will have [REDACTED...] in place of the original word)
            corresponding_masked = masked_text[pos:word_end_pos] if pos < len(masked_text) else ""
            if "[REDACTED" in masked_text[max(0, pos - 5):word_end_pos + 20]:
                pii_intervals.append({"start": w["start"], "end": w["end"], "word": w["word"]})

            cursor = word_end_pos

        # More reliable: rebuild a word-position map and check masked_text directly
        if not pii_intervals:
            # Fallback: walk through masked_text looking for [REDACTED*] tags
            # and correlate back to word timestamps by position ratio
            import re
            redacted_spans = [(m.start(), m.end()) for m in re.finditer(r'\[REDACTED[^\]]*\]', masked_text)]
            if redacted_spans and words:
                text_len = len(full_transcript)
                for rs, re_ in redacted_spans:
                    ratio_start = rs / text_len if text_len else 0
                    ratio_end = re_ / text_len if text_len else 0
                    for w in words:
                        w_ratio = full_transcript.find(w["word"]) / text_len if text_len else 0
                        if abs(w_ratio - ratio_start) < 0.05 or (ratio_start <= w_ratio <= ratio_end):
                            pii_intervals.append({"start": w["start"], "end": w["end"], "word": w["word"]})

        # Deduplicate
        seen = set()
        unique_intervals = []
        for iv in pii_intervals:
            key = (iv["start"], iv["end"])
            if key not in seen:
                seen.add(key)
                unique_intervals.append(iv)
        pii_intervals = unique_intervals

        print(f"[AUDIO] Found {len(pii_intervals)} PII word(s) to beep over")

        # ---- 3. Load audio and overlay beeps ----
        audio = AudioSegment.from_file(audio_path)

        for iv in pii_intervals:
            beep_duration = iv["end"] - iv["start"]
            if beep_duration < 50:
                beep_duration = 50  # minimum 50ms beep
            beep = _generate_beep(beep_duration)
            # Match the audio's channel count and sample rate
            if audio.channels > 1:
                beep = beep.set_channels(audio.channels)
            beep = beep.set_frame_rate(audio.frame_rate)
            # Overlay the beep at the exact timestamp
            audio = audio.overlay(beep, position=iv["start"], gain_during_overlay=-40)

        # ---- 4. Export sanitized audio ----
        out_name = f"{doc_id}_sanitized.mp3"
        sanitized_path = os.path.join(output_dir, out_name)
        audio.export(sanitized_path, format="mp3")
        print(f"[AUDIO] Sanitized audio saved: {sanitized_path}")

        entity_count = len(pii_intervals)
        threat_level = "HIGH" if entity_count >= 5 else "MEDIUM" if entity_count >= 1 else "LOW"

        return {
            "status": "completed",
            "sanitized_path": sanitized_path,
            "transcript": full_transcript,
            "masked_text": masked_text,
            "entities": [{"word": iv["word"], "start_ms": iv["start"], "end_ms": iv["end"]} for iv in pii_intervals],
            "entity_count": entity_count,
            "threat_level": threat_level,
            "risk_score": min(entity_count * 15, 100),
            "entity_breakdown": {"AUDIO_PII": entity_count},
            "recommended_actions": (
                [f"Review {entity_count} redacted audio segment(s)"] if entity_count else
                ["No PII detected in audio"]
            ),
        }

    except Exception as e:
        print(f"[AUDIO] ERROR processing {audio_path}: {e}")
        traceback.print_exc()
        return {
            "status": "error",
            "error": str(e),
            "transcript": "",
            "masked_text": "",
            "entities": [],
            "entity_count": 0,
            "threat_level": "LOW",
            "risk_score": 0,
            "entity_breakdown": {},
            "recommended_actions": [f"Audio processing failed: {e}"],
        }
