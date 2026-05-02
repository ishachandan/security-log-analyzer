"""
Risk Scoring Engine
Assigns risk scores (0-100) based on multiple security factors
"""
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime


class RiskEngine:
    """Calculates risk scores for security events"""
    
    def __init__(self):
        """Initialize risk engine with scoring weights"""
        # Base scores for attack types
        self.attack_base_scores = {
            'brute_force': 40,
            'ddos': 45,
            'suspicious_login': 35,
            'normal': 0
        }
        
        # Severity multipliers
        self.severity_scores = {
            'critical': 25,
            'high': 20,
            'medium': 10,
            'low': 5,
            'info': 0
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            'critical': 80,
            'high': 60,
            'medium': 40,
            'low': 20
        }
    
    def calculate_risk(
        self,
        logs: List[Dict[str, Any]],
        classification: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score
        
        Args:
            logs: List of log entries with metadata
            classification: Attack classification result
            
        Returns:
            Risk assessment with score, level, and factors
        """
        if not logs:
            return {
                'risk_score': 0,
                'risk_level': 'low',
                'risk_factors': []
            }
        
        risk_score = 0
        risk_factors = []
        
        # FACTOR 1: Attack type base score
        attack_type = classification.get('attack_type', 'normal')
        base_score = self.attack_base_scores.get(attack_type, 0)
        if base_score > 0:
            risk_score += base_score
            risk_factors.append(f"Attack type: {attack_type} (+{base_score})")
        
        # FACTOR 2: Event frequency
        frequency_score = self._calculate_frequency_score(logs, classification)
        if frequency_score > 0:
            risk_score += frequency_score
            risk_factors.append(f"High frequency: {classification.get('event_count', 'N/A')} events (+{frequency_score})")
        
        # FACTOR 3: Severity of logs
        severity_score = self._calculate_severity_score(logs)
        if severity_score > 0:
            risk_score += severity_score
            risk_factors.append(f"Log severity (+{severity_score})")
        
        # FACTOR 4: Unique IPs involved
        ip_score = self._calculate_ip_diversity_score(logs)
        if ip_score > 0:
            risk_score += ip_score
            risk_factors.append(f"IP diversity (+{ip_score})")
        
        # FACTOR 5: Success after failures (CRITICAL SIGNAL)
        success_after_failure_score = self._detect_success_after_failures(logs)
        if success_after_failure_score > 0:
            risk_score += success_after_failure_score
            risk_factors.append(f"Success after failures (+{success_after_failure_score})")
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        risk_level = self._get_risk_level(risk_score)
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'scoring_breakdown': {
                'attack_base': base_score,
                'frequency': frequency_score,
                'severity': severity_score,
                'ip_diversity': ip_score,
                'success_after_failure': success_after_failure_score
            }
        }
    
    def _calculate_frequency_score(
        self,
        logs: List[Dict[str, Any]],
        classification: Dict[str, Any]
    ) -> int:
        """Calculate score based on event frequency"""
        # Try multiple sources for event count
        event_count = 0
        
        # 1. Use request_count or attempt_count from classification (most accurate)
        event_count = classification.get('request_count', 0)
        if event_count == 0:
            event_count = classification.get('attempt_count', 0)
        
        # 2. Use event_count from classification
        if event_count == 0:
            event_count = classification.get('event_count', 0)
        
        # 3. Sum up log_count from all chunks
        if event_count == 0:
            for log in logs:
                metadata = log.get('metadata', {})
                event_count += metadata.get('log_count', 0)
        
        # 4. Fallback to number of chunks (least accurate)
        if event_count == 0:
            event_count = len(logs)
        
        # Higher frequency = higher risk
        if event_count >= 100:
            return 20
        elif event_count >= 50:
            return 15
        elif event_count >= 20:
            return 10
        elif event_count >= 10:
            return 5
        
        return 0
    
    def _calculate_severity_score(self, logs: List[Dict[str, Any]]) -> int:
        """Calculate score based on log severity"""
        severities = []
        
        for log in logs:
            metadata = log.get('metadata', {})
            text = log.get('text', '').lower()
            
            # Check multiple locations for severity
            severity = metadata.get('severity', '')
            if not severity:
                severity = metadata.get('dominant_severity', '')
            if not severity:
                # Check severities list
                sev_list = metadata.get('severities', [])
                if sev_list:
                    severity = sev_list[0]
            
            # Extract from text if not in metadata
            if not severity:
                if 'critical' in text:
                    severity = 'critical'
                elif 'error' in text or 'failed' in text:
                    severity = 'high'
                elif 'warning' in text or 'warn' in text:
                    severity = 'medium'
            
            if severity:
                severities.append(severity.lower())
        
        if not severities:
            return 0
        
        # Get highest severity
        if 'critical' in severities:
            return self.severity_scores['critical']
        elif 'high' in severities:
            return self.severity_scores['high']
        elif 'medium' in severities:
            return self.severity_scores['medium']
        elif 'low' in severities:
            return self.severity_scores['low']
        
        return 0
    
    def _calculate_ip_diversity_score(self, logs: List[Dict[str, Any]]) -> int:
        """Calculate score based on number of unique IPs"""
        unique_ips = set()
        
        for log in logs:
            metadata = log.get('metadata', {})
            
            # Collect source IPs
            source_ips = metadata.get('source_ips', [])
            if source_ips:
                unique_ips.update(source_ips)
            elif metadata.get('source_ip'):
                unique_ips.add(metadata['source_ip'])
        
        ip_count = len(unique_ips)
        
        # Many IPs = distributed attack = higher risk
        if ip_count >= 50:
            return 15
        elif ip_count >= 20:
            return 10
        elif ip_count >= 10:
            return 5
        
        return 0
    
    def _detect_success_after_failures(self, logs: List[Dict[str, Any]]) -> int:
        """
        Detect successful login after failed attempts (CRITICAL SIGNAL)
        This indicates a successful breach after brute force
        """
        failed_attempts = []
        successful_logins = []
        
        for log in logs:
            text = log.get('text', '')
            text_lower = text.lower()
            metadata = log.get('metadata', {})
            
            # Get timestamp
            timestamp_str = metadata.get('timestamp', '')
            if not timestamp_str:
                time_range = metadata.get('time_range', {})
                timestamp_str = time_range.get('start', '')
            
            timestamp = None
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except:
                    pass
            
            # Get source IP
            source_ips = metadata.get('source_ips', [])
            if not source_ips and metadata.get('source_ip'):
                source_ips = [metadata['source_ip']]
            
            # Check for failed login
            is_failed = any(kw in text_lower for kw in ['failed', 'failure', 'denied', 'invalid', 'incorrect'])
            is_login = any(kw in text_lower for kw in ['login', 'auth', 'ssh', 'password'])
            
            if is_failed and is_login:
                for ip in source_ips:
                    failed_attempts.append({
                        'ip': ip,
                        'timestamp': timestamp,
                        'text': text
                    })
            
            # Check for successful login
            is_success = any(kw in text_lower for kw in ['success', 'accepted', 'authenticated', 'logged in'])
            if is_success and is_login:
                for ip in source_ips:
                    successful_logins.append({
                        'ip': ip,
                        'timestamp': timestamp,
                        'text': text
                    })
        
        # Check if any successful login came from same IP as failures
        if failed_attempts and successful_logins:
            failed_ips = {f['ip'] for f in failed_attempts if f['ip']}
            success_ips = {s['ip'] for s in successful_logins if s['ip']}
            
            # Same IP with both failures and success = CRITICAL
            if failed_ips & success_ips:
                return 30  # High score - indicates successful breach
        
        return 0
    
    def _get_risk_level(self, risk_score: int) -> str:
        """Convert risk score to risk level"""
        if risk_score >= self.risk_thresholds['critical']:
            return 'critical'
        elif risk_score >= self.risk_thresholds['high']:
            return 'high'
        elif risk_score >= self.risk_thresholds['medium']:
            return 'medium'
        elif risk_score >= self.risk_thresholds['low']:
            return 'low'
        else:
            return 'low'
    
    def calculate_batch_risk(
        self,
        log_groups: List[List[Dict[str, Any]]],
        classifications: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Calculate risk for multiple log groups
        
        Args:
            log_groups: List of log groups
            classifications: Corresponding classifications
            
        Returns:
            List of risk assessments
        """
        results = []
        
        for logs, classification in zip(log_groups, classifications):
            risk = self.calculate_risk(logs, classification)
            results.append(risk)
        
        return results
    
    def get_risk_summary(
        self,
        risk_assessments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate summary of risk assessments
        
        Args:
            risk_assessments: List of risk assessment results
            
        Returns:
            Summary statistics
        """
        if not risk_assessments:
            return {
                'total_assessed': 0,
                'average_risk_score': 0,
                'risk_distribution': {},
                'high_risk_count': 0
            }
        
        risk_levels = defaultdict(int)
        total_score = 0
        
        for assessment in risk_assessments:
            risk_levels[assessment['risk_level']] += 1
            total_score += assessment['risk_score']
        
        avg_score = total_score / len(risk_assessments)
        high_risk = sum(1 for a in risk_assessments if a['risk_level'] in ['high', 'critical'])
        
        return {
            'total_assessed': len(risk_assessments),
            'average_risk_score': round(avg_score, 1),
            'risk_distribution': dict(risk_levels),
            'high_risk_count': high_risk,
            'critical_count': risk_levels.get('critical', 0)
        }
