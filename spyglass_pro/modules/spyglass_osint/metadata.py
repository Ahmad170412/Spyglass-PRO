import hashlib
import importlib.util
import json
import os
from datetime import datetime

from .utils import _EXIFTOOL, _run_text


def extract(path):
    """Extract metadata from a file. Returns a structured dict."""
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    result = _file_info(path)

    if _EXIFTOOL:
        meta = _exiftool_extract(path)
        if meta:
            result.update(meta)
            _reconcile_file_type(path, result)
            return result

    # No exiftool — try Python fallbacks per type
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jpg", ".jpeg", ".tiff", ".tif", ".png", ".webp"):
        img = _pillow_exif(path)
        if img:
            result.update(img)
    elif ext == ".pdf":
        pdf = _pdf_meta(path)
        if pdf:
            result.update(pdf)
    elif ext in (".docx", ".xlsx", ".pptx"):
        ooxml = _ooxml_meta(path)
        if ooxml:
            result.update(ooxml)

    return result


# Extension -> (file type name, MIME type). ExifTool only recognises a
# fixed set of formats and labels everything else (source code, markdown,
# yaml, json, logs, ...) as TXT/text/plain, so those need their own entry.
_FILE_TYPES = {
    # Text / source code
    ".txt": ("TXT", "text/plain"), ".md": ("Markdown", "text/markdown"),
    ".py": ("Python", "text/x-python"), ".js": ("JavaScript", "text/javascript"),
    ".ts": ("TypeScript", "text/x-typescript"), ".rb": ("Ruby", "text/x-ruby"),
    ".go": ("Go", "text/x-go"), ".rs": ("Rust", "text/x-rust"),
    ".c": ("C", "text/x-c"), ".h": ("C Header", "text/x-c"),
    ".cpp": ("C++", "text/x-c++"), ".hpp": ("C++ Header", "text/x-c++"),
    ".java": ("Java", "text/x-java"), ".kt": ("Kotlin", "text/x-kotlin"),
    ".swift": ("Swift", "text/x-swift"), ".php": ("PHP", "text/x-php"),
    ".sh": ("Shell", "text/x-sh"), ".bash": ("Shell", "text/x-sh"),
    ".zsh": ("Shell", "text/x-sh"), ".ps1": ("PowerShell", "text/x-powershell"),
    ".sql": ("SQL", "text/x-sql"), ".r": ("R", "text/x-r"),
    ".lua": ("Lua", "text/x-lua"), ".pl": ("Perl", "text/x-perl"),
    ".css": ("CSS", "text/css"), ".html": ("HTML", "text/html"),
    ".htm": ("HTML", "text/html"), ".xml": ("XML", "text/xml"),
    ".json": ("JSON", "application/json"), ".yaml": ("YAML", "text/yaml"),
    ".yml": ("YAML", "text/yaml"), ".csv": ("CSV", "text/csv"),
    ".log": ("LOG", "text/plain"), ".ini": ("INI", "text/plain"),
    ".cfg": ("Config", "text/plain"), ".conf": ("Config", "text/plain"),
    ".rtf": ("RTF", "application/rtf"), ".srt": ("SubRip", "application/x-subrip"),
    ".vtt": ("WebVTT", "text/vtt"), ".tex": ("LaTeX", "text/x-tex"),
    # Images
    ".jpg": ("JPEG", "image/jpeg"), ".jpeg": ("JPEG", "image/jpeg"),
    ".png": ("PNG", "image/png"), ".gif": ("GIF", "image/gif"),
    ".webp": ("WEBP", "image/webp"), ".tif": ("TIFF", "image/tiff"),
    ".tiff": ("TIFF", "image/tiff"), ".bmp": ("BMP", "image/bmp"),
    ".ico": ("ICO", "image/x-icon"), ".cur": ("CUR", "image/x-icon"),
    ".heic": ("HEIC", "image/heic"), ".heif": ("HEIF", "image/heif"),
    ".svg": ("SVG", "image/svg+xml"), ".psd": ("PSD", "image/vnd.adobe.photoshop"),
    ".ai": ("AI", "application/postscript"), ".eps": ("EPS", "application/postscript"),
    ".cr2": ("CR2", "image/x-canon-cr2"), ".cr3": ("CR3", "image/x-canon-cr3"),
    ".nef": ("NEF", "image/x-nikon-nef"), ".arw": ("ARW", "image/x-sony-arw"),
    ".dng": ("DNG", "image/x-adobe-dng"), ".orf": ("ORF", "image/x-olympus-orf"),
    ".rw2": ("RW2", "image/x-panasonic-rw2"), ".raf": ("RAF", "image/x-fuji-raf"),
    # Documents
    ".pdf": ("PDF", "application/pdf"), ".doc": ("DOC", "application/msword"),
    ".docx": ("DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ".xls": ("XLS", "application/vnd.ms-excel"),
    ".xlsx": ("XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ".ppt": ("PPT", "application/vnd.ms-powerpoint"),
    ".pptx": ("PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    ".odt": ("ODT", "application/vnd.oasis.opendocument.text"),
    ".ods": ("ODS", "application/vnd.oasis.opendocument.spreadsheet"),
    ".odp": ("ODP", "application/vnd.oasis.opendocument.presentation"),
    ".epub": ("EPUB", "application/epub+zip"),
    ".pages": ("PAGES", "application/x-iwork-pages-sffpages"),
    ".numbers": ("NUMBERS", "application/x-iwork-numbers-sffnumbers"),
    ".key": ("KEY", "application/x-iwork-keynote-sffkey"),
    # Audio / video
    ".mp3": ("MP3", "audio/mpeg"), ".wav": ("WAV", "audio/wav"),
    ".aiff": ("AIFF", "audio/aiff"), ".aif": ("AIFF", "audio/aiff"),
    ".flac": ("FLAC", "audio/flac"), ".m4a": ("M4A", "audio/mp4"),
    ".aac": ("AAC", "audio/aac"), ".ogg": ("OGG", "application/ogg"),
    ".wma": ("WMA", "audio/x-ms-wma"), ".opus": ("OPUS", "audio/ogg"),
    ".mp4": ("MP4", "video/mp4"), ".m4v": ("M4V", "video/x-m4v"),
    ".mov": ("MOV", "video/quicktime"), ".avi": ("AVI", "video/x-msvideo"),
    ".mkv": ("MKV", "video/x-matroska"), ".webm": ("WEBM", "video/webm"),
    ".flv": ("FLV", "video/x-flv"), ".wmv": ("WMV", "video/x-ms-wmv"),
    ".mpg": ("MPEG", "video/mpeg"), ".mpeg": ("MPEG", "video/mpeg"),
    ".m2ts": ("MPEG-TS", "video/mp2t"),
    ".3gp": ("3GP", "video/3gpp"),
    # Archives / system
    ".zip": ("ZIP", "application/zip"), ".rar": ("RAR", "application/vnd.rar"),
    ".tar": ("TAR", "application/x-tar"), ".gz": ("GZ", "application/gzip"),
    ".bz2": ("BZ2", "application/x-bzip2"), ".xz": ("XZ", "application/x-xz"),
    ".7z": ("7Z", "application/x-7z-compressed"),
    ".dmg": ("DMG", "application/x-apple-diskimage"),
    ".iso": ("ISO", "application/x-iso9660-image"),
    ".exe": ("EXE", "application/x-msdownload"),
    ".dll": ("DLL", "application/x-msdownload"),
    ".apk": ("APK", "application/vnd.android.package-archive"),
}

# `.ts` is TypeScript source far more often than an MPEG transport stream
# in this tool's world, so the table says TypeScript. A genuine stream is
# still safe: exiftool sniffs its magic and reports M2TS/MPEG-TS (never the
# TXT fallback), and the reconciler below only flips an MPEG-TS label when
# the bytes are demonstrably text without the 0x47 sync pattern.


def _file_info(path):
    st = os.stat(path)
    hashes = _compute_hashes(path)
    # Local-time display is intentional for file timestamps.
    created = (
        datetime.fromtimestamp(st.st_birthtime).isoformat()  # noqa: DTZ006
        if hasattr(st, "st_birthtime") else "N/A"
    )
    return {
        "file_name": os.path.basename(path),
        "file_size": _human_size(st.st_size),
        "file_type": _mime_type(path),
        "created": created,
        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),  # noqa: DTZ006
        "accessed": datetime.fromtimestamp(st.st_atime).isoformat(),  # noqa: DTZ006
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
    }


def _compute_hashes(path):
    """Compute MD5 and SHA256 fingerprints of a file (identification, not auth)."""
    md5_hash = hashlib.md5()  # noqa: S324 - non-cryptographic fingerprint
    sha256_hash = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        return {"md5": md5_hash.hexdigest(), "sha256": sha256_hash.hexdigest()}
    except Exception:
        return {"md5": "N/A", "sha256": "N/A"}


def _exiftool_extract(path):
    """Full metadata via exiftool — the gold standard."""
    try:
        r = _run_text(
            [_EXIFTOOL, "-j", "-G", path],
            timeout=30,
        )
        data = json.loads(r.stdout.strip())
        if isinstance(data, list) and data:
            return _clean_exiftool(data[0])
    except Exception:
        pass
    return {}


_CURATED = {
    # File
    "FileSize", "FileType", "FileTypeExtension", "MIMEType",
    "ImageWidth", "ImageHeight", "Megapixels", "Duration",
    # Image
    "Make", "Model", "Software", "Orientation", "XResolution", "YResolution",
    "ISO", "Aperture", "FNumber", "ExposureTime", "FocalLength",
    "Flash", "WhiteBalance", "ColorSpace",
    # Timestamps
    "DateTimeOriginal", "CreateDate", "ModifyDate", "DateCreated",
    "ProfileDateTime", "CreationDate",
    # GPS
    "GPSLatitude", "GPSLatitudeRef", "GPSLongitude", "GPSLongitudeRef",
    "GPSAltitude", "GPSAltitudeRef", "GPSPosition", "GPSDateTime",
    # Documents
    "Author", "Creator", "Producer", "Title", "Subject",
    "Description", "Keywords", "LastModifiedBy", "RevisionNumber",
    "Company", "Manager", "Category", "Language", "Pages",
    # Audio/Video
    "Artist", "Album", "Track", "Genre", "SampleRate", "Channels", "AudioBitrate",
    # Network / forensic
    "UserComment", "Warning",
}

_IGNORE_VALUES = {"N/A", "-", "unknown", "Unspecified", "", "none", "None"}


def _clean_exiftool(raw):
    """Return only curated fields + GPS, with clean names."""
    out = {}
    gps = {}

    for key, val in raw.items():
        if val is None or val == "":
            continue
        s = str(val).strip()
        if s in _IGNORE_VALUES:
            continue
        short = key.split(":")[-1] if ":" in key else key

        # Collect GPS subfields separately
        if short.startswith("GPS") and short != "GPSPosition":
            gps[short] = s
            continue

        if short not in _CURATED:
            continue

        out[short] = s

    if gps:
        out["GPS"] = gps
    return out


def _pillow_exif(path):
    """Image EXIF via Pillow."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return {}

    try:
        img = Image.open(path)
        exif = img._getexif()
        if not exif:
            return {}
        out = {}
        gps = {}
        for tag_id, val in exif.items():
            name = TAGS.get(tag_id, tag_id)
            if isinstance(val, bytes):
                try:
                    val = val.decode("utf-8", errors="replace").strip()
                except Exception:  # noqa: S112 - skip undecodable tag values
                    continue
            if name == "GPSInfo":
                for k, v in val.items():
                    gps_tag = {0: "GPSLatitudeRef", 1: "GPSLatitude",
                               2: "GPSLongitudeRef", 3: "GPSLongitude",
                               4: "GPSAltitudeRef", 5: "GPSAltitude"}.get(k, str(k))
                    gps[gps_tag] = v
                continue
            if isinstance(val, (int, float)):
                out[name] = val
            else:
                s = str(val).strip()
                if s and s != "N/A":
                    out[name] = s
        if gps:
            out["GPS"] = gps
        return out
    except Exception:
        return {}


def _pdf_meta(path):
    """PDF metadata via PyPDF2, falling back to pdfminer."""
    try:
        import PyPDF2
    except ImportError:
        if importlib.util.find_spec("pdfminer") is not None:
            return _pdfminer_meta(path)
        return {}
    try:
        with open(path, "rb") as f:
            r = PyPDF2.PdfReader(f)
            info = r.metadata
            if info:
                return {k: str(v) for k, v in info.items() if v}
    except Exception:
        pass
    return {}


def _pdfminer_meta(path):
    try:
        from pdfminer.pdfdocument import PDFDocument
        from pdfminer.pdfparser import PDFParser
        with open(path, "rb") as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)
            return {k: str(v) for k, v in (doc.info[0] if doc.info else {}).items() if v}
    except Exception:
        return {}


def _ooxml_meta(path):
    """Office Open XML metadata (docx/xlsx/pptx) via python-docx/openpyxl."""
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".docx":
            import docx
            d = docx.Document(path)
            p = d.core_properties
        elif ext == ".xlsx":
            import openpyxl
            wb = openpyxl.load_workbook(path)
            p = wb.properties
        else:
            return {}
        out = {}
        for attr in ("author", "category", "comments", "content_status", "created",
                      "creator", "description", "identifier", "keywords", "language",
                      "last_modified_by", "last_printed", "modified", "revision",
                      "subject", "title", "version"):
            val = getattr(p, attr, None)
            if val:
                out[attr.replace("_", " ").title()] = str(val)
        return out
    except Exception:
        return {}


def _human_size(b):
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def _mime_type(path):
    ext = os.path.splitext(path)[1].lower()
    return _FILE_TYPES.get(ext, ("", "application/octet-stream"))[1]


def _reconcile_file_type(path, result):
    """Fix exiftool's generic TXT fallback.

    ExifTool content-sniffs anything outside its format list and reports
    TXT/txt/text/plain — wrong for .py, .md, .json, .yaml, .log and every
    other code file. When the real extension maps to a known type, trust it
    over that fallback. Everything else keeps exiftool's content-based
    detection, so a zip disguised as .txt still reports as ZIP.

    Two sharper edges of the same problem:

    * ``.ts`` is TypeScript source or an MPEG transport stream and exiftool
      cannot tell them apart (it labels both MPEG-TS). A null byte or
      undecodable bytes means binary, so the stream label stands; anything
      else is source code.
    * An empty (or otherwise unreadable-to-exiftool) file yields no FileType
      at all. With no content signal either way, the extension table is the
      only honest answer — better "Python" than a blank type line.
    """
    ext = os.path.splitext(path)[1].lower()
    known = _FILE_TYPES.get(ext)
    if not known:
        return
    if result.get("FileType") == "TXT" and result.get("MIMEType") == "text/plain":
        name, mime = known
        result["FileType"] = name
        result["FileTypeExtension"] = ext.lstrip(".")
        result["MIMEType"] = mime
        return
    if ext == ".ts" and result.get("FileType") == "MPEG-TS" \
            and not _is_transport_stream(path) and _looks_like_text(path):
        result["FileType"] = "TypeScript"
        result["FileTypeExtension"] = "ts"
        result["MIMEType"] = "text/x-typescript"
        return
    if not result.get("FileType"):
        name, mime = known
        result["FileType"] = name
        result["FileTypeExtension"] = ext.lstrip(".")
        result["MIMEType"] = mime


def _looks_like_text(path, sample=8192):
    """True when a file's first bytes decode as text with no null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample)
    except OSError:
        return False
    if not chunk:
        return True  # empty: no binary signal, extension decides
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _is_transport_stream(path):
    """True when bytes carry the MPEG-TS sync pattern (0x47 every 188 bytes).

    Real transport streams start each 188-byte packet with a sync byte, so
    two aligned sync bytes all but settle it. A TypeScript file beginning
    with 0x47 bytes in exactly those spots is not a thing.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
    except OSError:
        return False
    return len(chunk) > 188 and chunk[0] == 0x47 and chunk[188] == 0x47
