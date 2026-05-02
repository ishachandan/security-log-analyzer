"""
Attack Classification Module
Classifies logs into attack types using hybrid approach (rules + LLM)
Includes risk scoring for comprehensive threat assessment
"""
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import re
from .risk_engine import RiskEngine


class AttackClassifier:
    """Classifies security logs into attack types"""
    
    def __init__(self, llm_analyzer=None):
        """
        Initialize attack classifier
        
        Args:
            llm_analyzer: Optional LogAnalyzer instance for LLM-assisted classification
        """
        self.llm_analyzer = llm_analyzer
        self.risk_engine = RiskEngine()
        
        # Thresholds for time-window based detection
        self.brute_force_threshold = 5  # Failed attempts
        self.brute_force_window = 60  # 60 seconds (strict)
        self.ddos_threshold = 100  # Requests
        self.ddos_window = 10  # 10 seconds (strict)
        self.suspicious_login_window = 600  # 10 minutes
    
    def classify(
        self,
        logs: List[Dict[str, Any]],
        use_llm: bool = True
    ) -> Dict[str, Any]:
        """
        Classify logs into attack types with risk scoring
        
        Args:
            logs: List of log entries with text and metadata
            use_llm: Whether to use LLM for explanation enhancement
            
        Returns:
            Classification result with attack type, confidence, reason, risk score
        """
        if not logs:
            return {
                'attack_type': 'normal',
                'confidence': 1.0,
                'reason': 'No logs to analyze',
                'risk_score': 0,
                'risk_level': 'low'
            }
        
        # STEP 1: Rule-based detection (AUTHORITATIVE)
        rule_result = self._rule_based_classification(logs)
        
        # STEP 2: Calculate risk score
        risk_assessment = self.risk_engine.calculate_risk(logs, rule_result)
        
        # STEP 3: LLM explanation enhancement (ONLY for explanation, NOT classification)
        # LLM CANNOT override attack_type - only provides better explanation
        if use_llm and self.llm_analyzer and rule_result['attack_type'] != 'normal':
            llm_explanation = self._get_llm_explanation(logs, rule_result)
            # Use LLM explanation if better, but KEEP rule-based attack_type
            if llm_explanation and len(llm_explanation) > len(rule_result.get('reason', '')):
                rule_result['reason'] = llm_explanation
                rule_result['llm_enhanced'] = True
        
        # Merge classification with risk assessment
        final_result = {
            **rule_result,
            'risk_score': risk_assessment['risk_score'],
            'risk_level': risk_assessment['risk_level'],
            'risk_factors': risk_assessment['risk_factors']
        }
        
        return final_result
    
    def _rule_based_classification(
        self,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Rule-based attack detection
        
        Detects:
        - brute_force: Multiple failed logins from same IP
        - ddos: High frequency requests
        - suspicious_login: Login from unusual IP after failures
        """
        # Extract log data and preserve metadata
        log_data = []
        for log in logs:
            text = log.get('text', '')
            metadata = log.get('metadata', {})
            
            log_data.append({
                'text': text,
                'timestamp': metadata.get('timestamp', ''),
                'source_ip': metadata.get('source_ip', ''),
                'severity': metadata.get('severity', ''),
                'message': text,
                'metadata': metadata  # PRESERVE FULL METADATA
            })
        
        # Check for brute force
        brute_force_result = self._detect_brute_force(log_data)
        if brute_force_result['detected']:
            return brute_force_result
        
        # Check for DDoS
        ddos_result = self._detect_ddos(log_data)
        if ddos_result['detected']:
            return ddos_result
        
        # Check for suspicious login
        suspicious_result = self._detect_suspicious_login(log_data)
        if suspicious_result['detected']:
            return suspicious_result
        
        # No attack detected
        return {
            'attack_type': 'normal',
            'confidence': 0.8,
            'reason': 'No attack patterns detected in logs',
            'detected': False
        }
    
    def _detect_brute_force(
        self,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Detect brute force attacks with TIME-WINDOW analysis
        
        Pattern: ≥5 failed login attempts from same IP within 60 seconds
        Uses sliding window approach with actual timestamp analysis
        """
        # Extract all failed login events with timestamps
        failed_events = []
        
        for log in logs:
            text = log.get('text', '')
            text_lower = text.lower()
            metadata = log.get('metadata', {})
            
            # Check for failed login indicators
            is_failed = any(kw in text_lower for kw in ['failed', 'failure', 'denied', 'invalid', 'incorrect'])
            is_login = any(kw in text_lower for kw in ['login', 'auth', 'ssh', 'password'])
            
            if not (is_failed and is_login):
                continue
            
            # Get source IPs
            source_ips = metadata.get('source_ips', [])
            if not source_ips and metadata.get('source_ip'):
                source_ips = [metadata.get('source_ip')]
            if not source_ips:
                # Extract from text as fallback
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, text)
                if found_ips:
                    source_ips = found_ips[:1]
            
            # Get occurrence count
            occurrence_count = metadata.get('occurrence_count', 1)
            max_occurrence = metadata.get('max_occurrence_count', 1)
            total_occurrences = metadata.get('total_occurrences', 1)
            count = max(occurrence_count, max_occurrence, total_occurrences)
            
            # Extract timestamps from individual logs in chunk
            chunk_logs = log.get('logs', [])
            if chunk_logs:
                # Process each individual log in the chunk
                for chunk_log in chunk_logs:
                    timestamp_str = chunk_log.get('timestamp', '')
                    if timestamp_str:
                        try:
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            for source_ip in source_ips:
                                if source_ip:
                                    failed_events.append({
                                        'ip': source_ip,
                                        'timestamp': timestamp,
                                        'text': text,
                                        'count': chunk_log.get('occurrence_count', 1)
                                    })
                        except:
                            pass
            else:
                # Fallback: use chunk-level timestamp
                timestamp_str = metadata.get('timestamp', '')
                if not timestamp_str:
                    # Use time_range if available
                    time_range = metadata.get('time_range', {})
                    timestamp_str = time_range.get('start', '')
                
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        for source_ip in source_ips:
                            if source_ip:
                                failed_events.append({
                                    'ip': source_ip,
                                    'timestamp': timestamp,
                                    'text': text,
                                    'count': count
                                })
                    except:
                        # No valid timestamp - use current time as fallback
                        for source_ip in source_ips:
                            if source_ip:
                                failed_events.append({
                                    'ip': source_ip,
                                    'timestamp': datetime.utcnow(),
                                    'text': text,
                                    'count': count
                                })
        
        if not failed_events:
            return {'detected': False}
        
        # Group by IP and apply sliding window
        ip_events = defaultdict(list)
        for event in failed_events:
            ip_events[event['ip']].append(event)
        
        # Check each IP with sliding window
        for ip, events in ip_events.items():
            # Sort by timestamp
            events.sort(key=lambda x: x['timestamp'])
            
            # Apply sliding window
            for i in range(len(events)):
                window_start = events[i]['timestamp']
                window_end = window_start + timedelta(seconds=self.brute_force_window)
                
                # Count events within window
                events_in_window = []
                total_attempts = 0
                
                for event in events[i:]:
                    if event['timestamp'] <= window_end:
                        events_in_window.append(event)
                        total_attempts += event['count']
                    else:
                        break
                
                # Check threshold
                if total_attempts >= self.brute_force_threshold:
                    # Calculate actual time span
                    if len(events_in_window) > 1:
                        time_span = (events_in_window[-1]['timestamp'] - events_in_window[0]['timestamp']).total_seconds()
                    else:
                        time_span = 0
                    
                    return {
                        'attack_type': 'brute_force',
                        'confidence': 0.9,
                        'reason': f'Detected {total_attempts} failed login attempts from IP {ip} within {int(time_span)} seconds',
                        'detected': True,
                        'source_ip': ip,
                        'attempt_count': total_attempts,
                        'time_window': f'{int(time_span)} seconds',
                        'event_count': len(events_in_window)
                    }
        
        return {'detected': False}
    
    def _detect_ddos(
        self,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Detect DDoS attacks with TIME-WINDOW analysis
        
        Pattern: ≥100 requests within 10 seconds (single IP or distributed)
        Uses sliding window approach
        """
        # Extract all request events with timestamps
        request_events = []
        
        for log in logs:
            text = log.get('text', '')
            metadata = log.get('metadata', {})
            
            # Get source IPs
            source_ips = metadata.get('source_ips', [])
            if not source_ips and metadata.get('source_ip'):
                source_ips = [metadata.get('source_ip')]
            if not source_ips:
                # Extract from text
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, text)
                if found_ips:
                    source_ips = found_ips[:1]
            
            # Get occurrence count
            occurrence_count = metadata.get('occurrence_count', 1)
            max_occurrence = metadata.get('max_occurrence_count', 1)
            total_occurrences = metadata.get('total_occurrences', 1)
            count = max(occurrence_count, max_occurrence, total_occurrences)
            
            # Extract timestamps from individual logs in chunk
            chunk_logs = log.get('logs', [])
            if chunk_logs:
                for chunk_log in chunk_logs:
                    timestamp_str = chunk_log.get('timestamp', '')
                    if timestamp_str:
                        try:
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            for source_ip in source_ips:
                                if source_ip:
                                    request_events.append({
                                        'ip': source_ip,
                                        'timestamp': timestamp,
                                        'count': chunk_log.get('occurrence_count', 1)
                                    })
                        except:
                            pass
            else:
                # Fallback: use chunk-level timestamp
                timestamp_str = metadata.get('timestamp', '')
                if not timestamp_str:
                    time_range = metadata.get('time_range', {})
                    timestamp_str = time_range.get('start', '')
                
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        for source_ip in source_ips:
                            if source_ip:
                                request_events.append({
                                    'ip': source_ip,
                                    'timestamp': timestamp,
                                    'count': count
                                })
                    except:
                        pass
        
        if not request_events:
            return {'detected': False}
        
        # Sort all events by timestamp
        request_events.sort(key=lambda x: x['timestamp'])
        
        # Check for single-source DDoS using sliding window
        ip_events = defaultdict(list)
        for event in request_events:
            ip_events[event['ip']].append(event)
        
        for ip, events in ip_events.items():
            events.sort(key=lambda x: x['timestamp'])
            
            # Sliding window
            for i in range(len(events)):
                window_start = events[i]['timestamp']
                window_end = window_start + timedelta(seconds=self.ddos_window)
                
                total_requests = 0
                events_in_window = []
                
                for event in events[i:]:
                    if event['timestamp'] <= window_end:
                        events_in_window.append(event)
                        total_requests += event['count']
                    else:
                        break
                
                if total_requests >= self.ddos_threshold:
                    time_span = (events_in_window[-1]['timestamp'] - events_in_window[0]['timestamp']).total_seconds() if len(events_in_window) > 1 else 0
                    
                    return {
                        'attack_type': 'ddos',
                        'confidence': 0.9,
                        'reason': f'Detected {total_requests} requests from IP {ip} within {int(time_span)} seconds',
                        'detected': True,
                        'source_ip': ip,
                        'request_count': total_requests,
                        'time_window': f'{int(time_span)} seconds',
                        'event_count': len(events_in_window)
                    }
        
        # Check for distributed DDoS (many IPs, high volume in short time)
        if len(request_events) >= self.ddos_threshold:
            # Use sliding window on all events
            for i in range(len(request_events)):
                window_start = request_events[i]['timestamp']
                window_end = window_start + timedelta(seconds=self.ddos_window)
                
                events_in_window = []
                total_requests = 0
                unique_ips = set()
                
                for event in request_events[i:]:
                    if event['timestamp'] <= window_end:
                        events_in_window.append(event)
                        total_requests += event['count']
                        unique_ips.add(event['ip'])
                    else:
                        break
                
                if total_requests >= self.ddos_threshold and len(unique_ips) > 5:
                    time_span = (events_in_window[-1]['timestamp'] - events_in_window[0]['timestamp']).total_seconds() if len(events_in_window) > 1 else 0
                    
                    return {
                        'attack_type': 'ddos',
                        'confidence': 0.85,
                        'reason': f'Detected {total_requests} requests from {len(unique_ips)} IPs within {int(time_span)} seconds (distributed DDoS)',
                        'detected': True,
                        'unique_ips': len(unique_ips),
                        'request_count': total_requests,
                        'time_window': f'{int(time_span)} seconds',
                        'event_count': len(events_in_window)
                    }
        
        return {'detected': False}
    
    def _detect_suspicious_login(
        self,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Detect suspicious login patterns
        
        Pattern: Successful login from unusual IP after failed attempts
        """
        failed_ips = set()
        successful_logins = []
        
        for log in logs:
            text_lower = log['text'].lower()
            source_ip = log.get('source_ip', '')
            
            # Track failed logins
            if any(keyword in text_lower for keyword in ['failed', 'failure', 'denied']):
                if any(keyword in text_lower for keyword in ['login', 'auth']):
                    if source_ip:
                        failed_ips.add(source_ip)
            
            # Track successful logins
            if any(keyword in text_lower for keyword in ['success', 'accepted', 'authenticated']):
                if any(keyword in text_lower for keyword in ['login', 'auth']):
                    if source_ip:
                        successful_logins.append((source_ip, log))
        
        # Check for successful login from different IP after failures
        for success_ip, log in successful_logins:
            if failed_ips and success_ip not in failed_ips:
                return {
                    'attack_type': 'suspicious_login',
                    'confidence': 0.7,
                    'reason': f'Successful login from IP {success_ip} after failed attempts from other IPs',
                    'detected': True,
                    'success_ip': success_ip,
                    'failed_ips': list(failed_ips)
                }
        
        return {'detected': False}
    
    def _get_llm_explanation(
        self,
        logs: List[Dict[str, Any]],
        rule_result: Dict[str, Any]
    ) -> str:
        """
        Use LLM to generate better explanation (NOT to override classification)
        
        Args:
            logs: Log entries
            rule_result: Result from rule-based classification
            
        Returns:
            Enhanced explanation string
        """
        # Prepare context with actual log data
        log_texts = []
        for log in logs[:5]:  # Limit to 5 logs
            text = log.get('text', '')[:150]
            log_texts.append(text)
        
        context = "\n".join(f"{i+1}. {text}" for i, text in enumerate(log_texts))
        
        # Create prompt that ONLY asks for explanation
        prompt = f"""You are a security analyst. Explain this detected attack in 1-2 sentences.

DETECTED ATTACK: {rule_result['attack_type']}
DETECTION REASON: {rule_result.get('reason', '')}

ACTUAL LOGS:
{context}

CRITICAL RULES:
- Use ONLY information from the logs above
- Reference specific IPs, timestamps, or patterns you see
- Do NOT invent or hallucinate any IPs or data
- Keep explanation concise (1-2 sentences)

Provide a clear explanation of why this is a {rule_result['attack_type']} attack:"""
        
        try:
            response = self.llm_analyzer._call_llm(prompt)
            # Clean up response
            explanation = response.strip()
            # Remove any JSON formatting if present
            if explanation.startswith('{'):
                return rule_result.get('reason', '')
            return explanation[:200]  # Limit length
        except Exception as e:
            # Fall back to rule-based reason
            return rule_result.get('reason', '')
    
    def _within_time_window(
        self,
        logs: List[Dict[str, Any]],
        window_seconds: int
    ) -> bool:
        """Check if logs are within time window"""
        if len(logs) < 2:
            return True
        
        timestamps = []
        for log in logs:
            ts_str = log.get('timestamp', '')
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    timestamps.append(ts)
                except:
                    pass
        
        if len(timestamps) < 2:
            return True
        
        timestamps.sort()
        time_diff = (timestamps[-1] - timestamps[0]).total_seconds()
        
        return time_diff <= window_seconds
    
    def classify_batch(
        self,
        log_groups: List[List[Dict[str, Any]]],
        use_llm: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Classify multiple log groups
        
        Args:
            log_groups: List of log groups to classify
            use_llm: Whether to use LLM refinement
            
        Returns:
            List of classification results
        """
        results = []
        
        for logs in log_groups:
            result = self.classify(logs, use_llm=use_llm)
            results.append(result)
        
        return results
    
    def get_attack_summary(
        self,
        classifications: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate summary of attack classifications
        
        Args:
            classifications: List of classification results
            
        Returns:
            Summary statistics
        """
        attack_counts = defaultdict(int)
        total_confidence = 0.0
        
        for classification in classifications:
            attack_type = classification['attack_type']
            attack_counts[attack_type] += 1
            total_confidence += classification['confidence']
        
        avg_confidence = total_confidence / len(classifications) if classifications else 0
        
        return {
            'total_analyzed': len(classifications),
            'attack_distribution': dict(attack_counts),
            'average_confidence': round(avg_confidence, 3),
            'attacks_detected': sum(1 for c in classifications if c['attack_type'] != 'normal')
        }
