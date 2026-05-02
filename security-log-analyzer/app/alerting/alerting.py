"""
Alerting System
Sends webhook and email alerts for critical/high risk threats
"""
import sqlite3
import json
import logging
import smtplib
import uuid
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, List
import requests
from app.config import (
    ALERT_WEBHOOK_URL,
    WEBHOOK_TIMEOUT,
    ALERT_EMAIL_TO,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASS,
    DATABASE_PATH
)

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages security alerts via webhook and email"""
    
    def __init__(self, db_path: str = None):
        """
        Initialize alert manager
        
        Args:
            db_path: Path to SQLite database (defaults to DATABASE_PATH from config)
        """
        self.db_path = db_path or DATABASE_PATH
        self._init_database()
    
    def _init_database(self):
        """Initialize alerts table in SQLite"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                risk_factors TEXT,
                query TEXT,
                recommended_action TEXT,
                source_ip TEXT,
                webhook_sent INTEGER DEFAULT 0,
                email_sent INTEGER DEFAULT 0
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Alert database initialized")
    
    def should_alert(self, result: Dict[str, Any]) -> bool:
        """
        Determine if an alert should be fired
        
        Args:
            result: Classification result dict
            
        Returns:
            True if risk_level is 'high' or 'critical'
        """
        risk_level = result.get('risk_level', '').lower()
        return risk_level in ['high', 'critical']
    
    def build_payload(self, result: Dict[str, Any], query: str) -> Dict[str, Any]:
        """
        Build alert payload from classification result
        
        Args:
            result: Classification result dict
            query: User query that triggered the analysis
            
        Returns:
            Alert payload dict
        """
        # Generate unique alert ID
        alert_id = str(uuid.uuid4())
        
        # Extract source IP from result metadata
        source_ip = "unknown"
        if 'source_ip' in result:
            source_ip = result['source_ip']
        elif 'supporting_logs' in result and result['supporting_logs']:
            # Try to extract IP from first log
            first_log = result['supporting_logs'][0]
            if isinstance(first_log, dict) and 'metadata' in first_log:
                metadata = first_log['metadata']
                if 'source_ip' in metadata:
                    source_ip = metadata['source_ip']
                elif 'source_ips' in metadata and metadata['source_ips']:
                    source_ip = metadata['source_ips'][0]
        
        # Generate recommended action based on attack type
        attack_type = result.get('attack_type', 'unknown')
        recommended_action = self._get_recommended_action(attack_type, source_ip)
        
        # Build payload
        payload = {
            'alert_id': alert_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'attack_type': attack_type,
            'risk_score': result.get('risk_score', 0),
            'risk_level': result.get('risk_level', 'unknown'),
            'severity': result.get('severity', 'unknown'),
            'summary': result.get('summary', 'Security threat detected'),
            'risk_factors': result.get('risk_factors', []),
            'query': query,
            'recommended_action': recommended_action,
            'source_ip': source_ip
        }
        
        return payload
    
    def _get_recommended_action(self, attack_type: str, source_ip: str) -> str:
        """
        Get recommended action based on attack type
        
        Args:
            attack_type: Type of attack detected
            source_ip: Source IP address
            
        Returns:
            Recommended action string
        """
        actions = {
            'brute_force': f"Block source IP {source_ip} immediately. Enable account lockout after 3 failed attempts. Implement multi-factor authentication.",
            'ddos': f"Enable rate limiting. Block source IP {source_ip}. Contact ISP for upstream filtering. Scale infrastructure if needed.",
            'suspicious_login': f"Force password reset for affected accounts. Review recent activity from IP {source_ip}. Enable login notifications.",
            'normal': "Continue monitoring. No immediate action required."
        }
        
        return actions.get(attack_type, f"Investigate activity from IP {source_ip}. Review logs and take appropriate action.")
    
    def send_webhook(self, alert_payload: Dict[str, Any]) -> bool:
        """
        Send alert via webhook
        
        Args:
            alert_payload: Alert data to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not ALERT_WEBHOOK_URL:
            logger.debug("Webhook URL not configured, skipping webhook alert")
            return False
        
        try:
            response = requests.post(
                ALERT_WEBHOOK_URL,
                json=alert_payload,
                timeout=WEBHOOK_TIMEOUT,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code in [200, 201, 202, 204]:
                logger.info(f"Webhook alert sent successfully: {alert_payload['alert_id']}")
                return True
            else:
                logger.warning(f"Webhook returned status {response.status_code}: {response.text[:100]}")
                return False
                
        except requests.exceptions.Timeout:
            logger.warning(f"Webhook timeout after {WEBHOOK_TIMEOUT}s")
            return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Webhook failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending webhook: {str(e)}")
            return False
    
    def send_email(self, alert_payload: Dict[str, Any]) -> bool:
        """
        Send alert via email using SMTP
        
        Args:
            alert_payload: Alert data to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        # Check if email is configured
        if not all([ALERT_EMAIL_TO, SMTP_USER, SMTP_PASS]):
            logger.debug("Email not fully configured, skipping email alert")
            return False
        
        try:
            # Build email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 Security Alert: {alert_payload['attack_type'].upper()} - {alert_payload['risk_level'].upper()}"
            msg['From'] = SMTP_USER
            msg['To'] = ALERT_EMAIL_TO
            
            # Create plain text body
            text_body = self._build_email_body(alert_payload)
            msg.attach(MIMEText(text_body, 'plain'))
            
            # Send email
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            
            logger.info(f"Email alert sent successfully: {alert_payload['alert_id']}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.warning("SMTP authentication failed - check credentials")
            return False
        except smtplib.SMTPException as e:
            logger.warning(f"SMTP error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email: {str(e)}")
            return False
    
    def _build_email_body(self, alert_payload: Dict[str, Any]) -> str:
        """Build plain text email body"""
        risk_factors_str = "\n".join(f"  - {factor}" for factor in alert_payload['risk_factors'])
        
        body = f"""
SECURITY ALERT
{'='*60}

Alert ID: {alert_payload['alert_id']}
Timestamp: {alert_payload['timestamp']}

THREAT DETAILS
{'='*60}
Attack Type: {alert_payload['attack_type'].upper()}
Risk Level: {alert_payload['risk_level'].upper()}
Risk Score: {alert_payload['risk_score']}/100
Severity: {alert_payload['severity'].upper()}
Source IP: {alert_payload['source_ip']}

SUMMARY
{'='*60}
{alert_payload['summary']}

RISK FACTORS
{'='*60}
{risk_factors_str if risk_factors_str else '  None'}

RECOMMENDED ACTION
{'='*60}
{alert_payload['recommended_action']}

QUERY
{'='*60}
{alert_payload['query']}

{'='*60}
This is an automated alert from Security Log Analyzer.
"""
        return body
    
    def _save_to_database(
        self,
        alert_payload: Dict[str, Any],
        webhook_sent: bool,
        email_sent: bool
    ) -> bool:
        """
        Save alert to SQLite database
        
        Args:
            alert_payload: Alert data
            webhook_sent: Whether webhook was sent successfully
            email_sent: Whether email was sent successfully
            
        Returns:
            True if saved successfully
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Convert risk_factors list to JSON string
            risk_factors_json = json.dumps(alert_payload['risk_factors'])
            
            cursor.execute("""
                INSERT INTO alerts (
                    alert_id, timestamp, attack_type, risk_score, risk_level,
                    severity, summary, risk_factors, query, recommended_action,
                    source_ip, webhook_sent, email_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_payload['alert_id'],
                alert_payload['timestamp'],
                alert_payload['attack_type'],
                alert_payload['risk_score'],
                alert_payload['risk_level'],
                alert_payload['severity'],
                alert_payload['summary'],
                risk_factors_json,
                alert_payload['query'],
                alert_payload['recommended_action'],
                alert_payload['source_ip'],
                1 if webhook_sent else 0,
                1 if email_sent else 0
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Alert saved to database: {alert_payload['alert_id']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save alert to database: {str(e)}")
            return False
    
    def fire(self, result: Dict[str, Any], query: str) -> Optional[Dict[str, Any]]:
        """
        Master method to fire an alert
        
        Checks if alert should be sent, builds payload, sends via webhook and email,
        saves to database, and returns the payload.
        
        Args:
            result: Classification result dict
            query: User query
            
        Returns:
            Alert payload if alert was fired, None otherwise
        """
        # Check if we should alert
        if not self.should_alert(result):
            logger.debug(f"Alert not triggered - risk level: {result.get('risk_level', 'unknown')}")
            return None
        
        # Build alert payload
        alert_payload = self.build_payload(result, query)
        
        logger.info(f"Firing alert: {alert_payload['alert_id']} - {alert_payload['attack_type']} ({alert_payload['risk_level']})")
        
        # Send webhook
        webhook_sent = self.send_webhook(alert_payload)
        
        # Send email
        email_sent = self.send_email(alert_payload)
        
        # Save to database
        self._save_to_database(alert_payload, webhook_sent, email_sent)
        
        return alert_payload
    
    def get_recent_alerts(self, limit: int = 50, risk_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent alerts from database
        
        Args:
            limit: Maximum number of alerts to return
            risk_level: Optional filter by risk level
            
        Returns:
            List of alert dicts
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if risk_level:
                cursor.execute("""
                    SELECT alert_id, timestamp, attack_type, risk_score, risk_level,
                           severity, summary, risk_factors, query, recommended_action,
                           source_ip, webhook_sent, email_sent
                    FROM alerts
                    WHERE risk_level = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (risk_level, limit))
            else:
                cursor.execute("""
                    SELECT alert_id, timestamp, attack_type, risk_score, risk_level,
                           severity, summary, risk_factors, query, recommended_action,
                           source_ip, webhook_sent, email_sent
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            
            # Convert to list of dicts
            alerts = []
            for row in rows:
                alert = {
                    'alert_id': row[0],
                    'timestamp': row[1],
                    'attack_type': row[2],
                    'risk_score': row[3],
                    'risk_level': row[4],
                    'severity': row[5],
                    'summary': row[6],
                    'risk_factors': json.loads(row[7]) if row[7] else [],
                    'query': row[8],
                    'recommended_action': row[9],
                    'source_ip': row[10],
                    'webhook_sent': bool(row[11]),
                    'email_sent': bool(row[12])
                }
                alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to retrieve alerts: {str(e)}")
            return []
