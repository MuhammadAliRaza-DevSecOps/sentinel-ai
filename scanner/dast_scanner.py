# scanner/dast_scanner.py
# DAST = Dynamic Application Security Testing
# "Dynamic" = running application pe attack simulate karte hain
# OWASP ZAP use karta hai — industry standard free tool

import json
import subprocess
import time
import requests
from loguru import logger
from .scoring_engine import Finding, Severity, ScoringEngine


class DASTScanner:
    """
    OWASP ZAP (Zed Attack Proxy) use karta hai.
    
    ZAP kya karta hai:
    1. Spider — saare pages/endpoints dhundta hai
    2. Active Scan — actual attacks karta hai (SQLi, XSS, etc.)
    3. Passive Scan — traffic monitor karta hai without attacking
    
    IMPORTANT: Sirf apne OWN applications pe use karo.
    Kisi aur ki website pe karna illegal hai.
    """

    def __init__(self, zap_host: str = "localhost", zap_port: int = 8090):
        self.scoring_engine = ScoringEngine()
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_api_url = f"http://{zap_host}:{zap_port}"
        self.api_key = "devsecops-zap-key"  # ZAP API key

    def _is_zap_running(self) -> bool:
        """Check karo ke ZAP chal raha hai ya nahi."""
        try:
            resp = requests.get(
                f"{self.zap_api_url}/JSON/core/view/version/",
                params={"apikey": self.api_key},
                timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False

    def start_zap(self) -> bool:
        """ZAP daemon mode mein start karo."""
        if self._is_zap_running():
            logger.info("ZAP already chal raha hai")
            return True

        logger.info("ZAP start kar raha hai...")
        
        # ZAP daemon mode mein start karo
        # -daemon: background mein chale
        # -port: API ke liye port
        # -config: API key set karo
        command = [
            "zap.sh",
            "-daemon",
            "-port", str(self.zap_port),
            "-config", f"api.key={self.api_key}",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ]

        try:
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            logger.error("ZAP install nahi hai. Docker alternative use karo:")
            logger.error("docker run -d -p 8090:8090 owasp/zap2docker-stable zap.sh -daemon -port 8090")
            return False

        # ZAP ko start hone ka time do
        for i in range(30):  # 30 seconds wait
            time.sleep(2)
            if self._is_zap_running():
                logger.info("ZAP ready!")
                return True
            logger.debug(f"ZAP ka wait kar raha hai... ({i*2}s)")

        logger.error("ZAP start nahi hua timeout ke baad")
        return False

    def spider_target(self, target_url: str) -> int:
        """
        ZAP Spider run karo — saare links dhundta hai.
        Returns: scan_id
        """
        logger.info(f"Spider shuru: {target_url}")
        
        resp = requests.get(
            f"{self.zap_api_url}/JSON/spider/action/scan/",
            params={"apikey": self.api_key, "url": target_url, "maxChildren": 10},
        )
        scan_id = int(resp.json()["scan"])
        
        # Spider complete hone ka wait karo
        while True:
            time.sleep(2)
            progress = requests.get(
                f"{self.zap_api_url}/JSON/spider/view/status/",
                params={"apikey": self.api_key, "scanId": scan_id},
            ).json()["status"]
            
            logger.debug(f"Spider progress: {progress}%")
            
            if int(progress) >= 100:
                break

        logger.info("Spider complete!")
        return scan_id

    def active_scan(self, target_url: str) -> int:
        """
        Active scan karo — ZAP actual attacks karta hai.
        Returns: scan_id
        """
        logger.info(f"Active scan shuru: {target_url}")
        
        resp = requests.get(
            f"{self.zap_api_url}/JSON/ascan/action/scan/",
            params={
                "apikey": self.api_key,
                "url": target_url,
                "recurse": True,      # Saare sub-pages bhi scan karo
                "inScopeOnly": True,  # Sirf target scope mein
            },
        )
        scan_id = int(resp.json()["scan"])

        while True:
            time.sleep(5)
            progress = requests.get(
                f"{self.zap_api_url}/JSON/ascan/view/status/",
                params={"apikey": self.api_key, "scanId": scan_id},
            ).json()["status"]
            
            logger.debug(f"Active scan progress: {progress}%")
            
            if int(progress) >= 100:
                break

        logger.info("Active scan complete!")
        return scan_id

    def get_alerts(self, target_url: str) -> list[Finding]:
        """
        ZAP se saare alerts le aao aur Finding objects banao.
        """
        resp = requests.get(
            f"{self.zap_api_url}/JSON/core/view/alerts/",
            params={"apikey": self.api_key, "baseurl": target_url, "count": 500},
        )
        
        alerts = resp.json().get("alerts", [])
        findings = []

        # ZAP risk levels: High=3, Medium=2, Low=1, Informational=0
        zap_severity_map = {
            "High":          Severity.HIGH,
            "Medium":        Severity.MEDIUM,
            "Low":           Severity.LOW,
            "Informational": Severity.INFO,
        }

        for alert in alerts:
            severity = zap_severity_map.get(alert.get("risk", "Low"), Severity.LOW)
            
            finding = Finding(
                scanner="zap_dast",
                vuln_type=alert.get("pluginId", "unknown") + "_" + 
                          alert.get("name", "unknown").lower().replace(" ", "_"),
                file_path=alert.get("url", "unknown"),  # DAST mein URL hai file path ki jagah
                line_number=None,
                description=(
                    f"{alert.get('name', '')}: {alert.get('description', '')[:300]}. "
                    f"Evidence: {alert.get('evidence', 'N/A')[:100]}"
                ),
                severity=severity,
                remediation=alert.get("solution", "OWASP guidelines follow karo"),
                raw_output=alert,
            )
            
            finding = self.scoring_engine.calculate_score(finding)
            findings.append(finding)

        return findings

    def scan(self, target_url: str) -> dict:
        """
        Complete DAST scan:
        1. ZAP start karo
        2. Spider run karo
        3. Active scan run karo
        4. Alerts collect karo
        """
        # ZAP available nahi hai to Docker alternative suggest karo
        if not self.start_zap():
            logger.warning("ZAP unavailable — DAST scan skip")
            return {
                "scanner": "dast",
                "findings": [],
                "risk": {"risk_level": "SKIP", "reason": "ZAP not available"},
                "note": "docker run -d -p 8090:8090 owasp/zap2docker-stable"
            }

        try:
            self.spider_target(target_url)
            self.active_scan(target_url)
            findings = self.get_alerts(target_url)
            risk = self.scoring_engine.calculate_pipeline_risk(findings)

            return {
                "scanner": "dast",
                "findings": findings,
                "risk": risk,
                "target": target_url,
            }
        except Exception as e:
            logger.error(f"DAST scan error: {e}")
            return {"scanner": "dast", "findings": [], "risk": {}, "error": str(e)}