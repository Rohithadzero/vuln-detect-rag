from dataclasses import asdict

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.concurrency import run_in_threadpool

from models.schemas import LinkSanitizeRequest, SanitizeItemResult, SanitizeResponse
from services import sanitizer

router = APIRouter()

# Per-file and per-request caps. Screening is done in memory, so an unbounded
# upload is a denial-of-service vector, not a feature.
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILES = 20


def _to_schema(result) -> SanitizeItemResult:
    return SanitizeItemResult.model_validate(asdict(result))


@router.post("/sanitize/files", response_model=SanitizeResponse)
async def sanitize_files(files: list[UploadFile] = File(...)):
    """Screen uploaded files for threats. Nothing is stored server-side."""
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=400, detail=f"At most {MAX_FILES} files per request.")

    results = []
    for upload in files:
        data = await upload.read()
        if len(data) > MAX_FILE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"{upload.filename} exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit.",
            )
        result = await run_in_threadpool(sanitizer.scan_file, upload.filename or "unnamed", data)
        results.append(_to_schema(result))

    return SanitizeResponse(results=results)


@router.post("/sanitize/links", response_model=SanitizeResponse)
async def sanitize_links(request: LinkSanitizeRequest):
    """Screen URLs for threats. The URLs themselves are not fetched."""
    urls = [u for u in request.urls if u and u.strip()]
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs supplied.")

    results = []
    for url in urls:
        result = await run_in_threadpool(sanitizer.scan_link, url.strip())
        results.append(_to_schema(result))

    return SanitizeResponse(results=results)
