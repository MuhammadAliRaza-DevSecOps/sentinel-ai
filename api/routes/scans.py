# api/routes/scans.py
# Scan-related API endpoints
# Yeh file sari /api/v1/scans/* routes handle karta hai

import uuid
import time
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from loguru import logger

from ..database import get_db, ScanResult, Finding as DBFinding
from ..models.scan_models import (
    TriggerScanRequest, ScanResultResponse, ScanListItem,
    FindingResponse, RiskSummary, TrendDataPoint
)

# Router banao — prefix aur tags main.py mein set hain
router = APIRouter()


# ─────────────────────────────────────────────
# Background task — actual scan run karta hai
# ─────────────────────────────────────────────
async def run_scan_task(
    scan_id: str,
    request: TriggerScanRequest,
    db: AsyncSession
):
    """
    Yeh function background mein run hota hai.
    FastAPI ka BackgroundTasks use karte hain —
    API turant 200 return karta hai, scan peeche chalta rahta hai.
    """
    start_time = time.time()
    logger.info(f"Background scan shuru: {scan_id}")

    all_findings = []
    tool_counts = {}

    try:
        # Import scanner classes
        from scanner import SASTScanner, SCAScanner, SecretScanner, ContainerScanner

        # Request ke hisaab se scanners run karo
        if request.scan_type.value in ["full", "secret"]:
            logger.info("Secret scan...")
            scanner = SecretScanner()
            result = scanner.scan(request.target_path)
            all_findings.extend(result["findings"])
            tool_counts["secret"] = result["tool_counts"]

        if request.scan_type.value in ["full", "sast"]:
            logger.info("SAST scan...")
            scanner = SASTScanner()
            result = scanner.scan(request.target_path)
            all_findings.extend(result["findings"])
            tool_counts["sast"] = result["tool_counts"]

        if request.scan_type.value in ["full", "sca"]:
            logger.info("SCA scan...")
            scanner = SCAScanner()
            result = scanner.scan(f"{request.target_path}/requirements.txt")
            all_findings.extend(result["findings"])
            tool_counts["sca"] = result["tool_counts"]

        if request.scan_type.value in ["full", "container"] and request.image_name:
            logger.info("Container scan...")
            scanner = ContainerScanner()
            result = scanner.scan(request.image_name)
            all_findings.extend(result["findings"])
            tool_counts["container"] = result["tool_counts"]

        # Risk calculate karo
        from scanner import ScoringEngine
        scoring = ScoringEngine()
        risk = scoring.calculate_pipeline_risk(all_findings)

        duration_ms = int((time.time() - start_time) * 1000)

        # DB mein save karo
        # Findings ko dict mein convert karo (JSON storage ke liye)
        findings_for_json = []
        for f in all_findings:
            findings_for_json.append({
                "finding_id": f.finding_id,
                "scanner":    f.scanner,
                "vuln_type":  f.vuln_type,
                "file_path":  f.file_path,
                "line_number":f.line_number,
                "description":f.description,
                "severity":   f.severity.value,
                "cvss_score": f.cvss_score,
                "remediation":f.remediation,
            })

        # ScanResult object update karo
        scan_record = await db.get(ScanResult, scan_id)
        if scan_record:
            scan_record.risk_level     = risk["risk_level"]
            scan_record.risk_score     = risk["risk_score"]
            scan_record.count_critical = risk["counts"]["critical"]
            scan_record.count_high     = risk["counts"]["high"]
            scan_record.count_medium   = risk["counts"]["medium"]
            scan_record.count_low      = risk["counts"]["low"]
            scan_record.count_info     = risk["counts"]["info"]
            scan_record.findings_json  = findings_for_json
            scan_record.tool_counts    = tool_counts
            scan_record.duration_ms    = duration_ms
            await db.commit()

        logger.info(f"Scan complete: {scan_id} — {risk['risk_level']} in {duration_ms}ms")

    except Exception as e:
        logger.error(f"Scan failed: {scan_id} — {e}")
        # Error bhi DB mein save karo
        scan_record = await db.get(ScanResult, scan_id)
        if scan_record:
            scan_record.risk_level = "ERROR"
            scan_record.tool_counts = {"error": str(e)}
            await db.commit()


# ─────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────

@router.post("/trigger", status_code=202)
async def trigger_scan(
    request: TriggerScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Nayi scan trigger karo.
    202 Accepted = request accept ki, kaam peeche ho raha hai
    
    Returns: scan_id jisse baad mein status check kar sako
    """
    # Scan record create karo (status: "running")
    scan_id = str(uuid.uuid4())
    
    scan_record = ScanResult(
        id=scan_id,
        scan_type=request.scan_type.value,
        target_path=request.target_path,
        branch=request.branch or "unknown",
        commit_sha=request.commit_sha or "unknown",
        risk_level="RUNNING",
        triggered_by=request.triggered_by,
        tool_counts={},
        findings_json=[],
    )
    
    db.add(scan_record)
    await db.commit()

    # Background mein scan run karo — endpoint turant return karta hai
    background_tasks.add_task(run_scan_task, scan_id, request, db)

    logger.info(f"Scan queued: {scan_id}")
    
    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Scan background mein chal raha hai",
        "poll_url": f"/api/v1/scans/{scan_id}",
    }


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """
    Specific scan ka result lo.
    Pipeline/frontend isko poll karta hai status check ke liye.
    """
    scan = await db.get(ScanResult, scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} nahi mila")
    
    return {
        "id":           scan.id,
        "scan_type":    scan.scan_type,
        "target_path":  scan.target_path,
        "branch":       scan.branch,
        "commit_sha":   scan.commit_sha,
        "risk_level":   scan.risk_level,
        "risk_score":   scan.risk_score,
        "counts": {
            "critical": scan.count_critical,
            "high":     scan.count_high,
            "medium":   scan.count_medium,
            "low":      scan.count_low,
            "info":     scan.count_info,
        },
        "findings":     scan.findings_json,
        "tool_counts":  scan.tool_counts,
        "created_at":   scan.created_at.isoformat() if scan.created_at else None,
        "duration_ms":  scan.duration_ms,
        "triggered_by": scan.triggered_by,
    }


@router.get("/", response_model=List[dict])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    risk_level: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """
    Saari scans list karo, newest pehle.
    
    query params:
    - limit: kitni scans return karni hain
    - offset: pagination ke liye
    - risk_level: "PASS", "FAIL", "WARN" filter
    """
    query = select(ScanResult).order_by(desc(ScanResult.created_at))
    
    if risk_level:
        query = query.where(ScanResult.risk_level == risk_level.upper())
    
    query = query.limit(limit).offset(offset)
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    return [
        {
            "id":            s.id,
            "scan_type":     s.scan_type,
            "risk_level":    s.risk_level,
            "risk_score":    s.risk_score,
            "count_critical": s.count_critical,
            "count_high":    s.count_high,
            "count_medium":  s.count_medium,
            "count_low":     s.count_low,
            "created_at":    s.created_at.isoformat() if s.created_at else None,
            "branch":        s.branch,
            "triggered_by":  s.triggered_by,
            "duration_ms":   s.duration_ms,
        }
        for s in scans
    ]


@router.get("/trends/summary")
async def get_trends(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    """
    Last N days ke trends return karo.
    Dashboard ke line chart ke liye use hota hai.
    """
    since = datetime.utcnow() - timedelta(days=days)
    
    query = (
        select(ScanResult)
        .where(ScanResult.created_at >= since)
        .where(ScanResult.risk_level != "RUNNING")
        .order_by(ScanResult.created_at)
    )
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    # Daily aggregation
    from collections import defaultdict
    daily = defaultdict(lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, 
        "pass": 0, "fail": 0, "total_scans": 0
    })
    
    for scan in scans:
        day = scan.created_at.strftime("%Y-%m-%d") if scan.created_at else "unknown"
        daily[day]["critical"]    += scan.count_critical
        daily[day]["high"]        += scan.count_high
        daily[day]["medium"]      += scan.count_medium
        daily[day]["low"]         += scan.count_low
        daily[day]["total_scans"] += 1
        if scan.risk_level == "PASS":
            daily[day]["pass"] += 1
        elif scan.risk_level == "FAIL":
            daily[day]["fail"] += 1
    
    return {
        "days": days,
        "total_scans": len(scans),
        "daily": [
            {"date": date, **data}
            for date, data in sorted(daily.items())
        ],
        "summary": {
            "total_critical": sum(s.count_critical for s in scans),
            "total_high":     sum(s.count_high for s in scans),
            "pass_rate":      (
                sum(1 for s in scans if s.risk_level == "PASS") / len(scans) * 100
                if scans else 0
            ),
        }
    }


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Scan delete karo."""
    scan = await db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan nahi mila")
    await db.delete(scan)
    await db.commit()
    return None