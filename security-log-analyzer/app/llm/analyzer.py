"""
LLM Analysis Module
Uses local Phi-2 model via Ollama for log analysis with strict output validation
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import logging
from .prompt_builder import PromptBuilder
from .output_validator import OutputValidator

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Analyzes logs using local LLM"""
    
    def __init__(
        self,
        model_name: str = "phi",
        base_url: str = "http://localhost:11434",
        timeout: int = 120
    ):
        """
        Initialize log analyzer
        
        Args:
            model_name: Ollama model name (default: phi)
            base_url: Ollama API base URL
            timeout: Request timeout in seconds
        """
        self.model_name = model_name
        self.base_url = base_url
        self.timeout = timeout
        self.client = None
        self.validator = OutputValidator()
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Ollama client"""
        import ollama
        print(f"🔄 Initializing Ollama client: {self.model_name}...")
        self.client = ollama.Client(host=self.base_url)
        print(f"✅ Ollama client initialized: {self.model_name}")
    
    def analyze_logs(
        self,
        query: str,
        retrieved_logs: List[Dict[str, Any]],
        attack_type: Optional[str] = None,
        risk_score: Optional[int] = None,
        risk_level: Optional[str] = None,
        filters_applied: Optional[str] = None,
        max_context_length: int = 2000
    ) -> Dict[str, Any]:
        """
        Analyze retrieved logs using LLM (EXPLANATION ONLY)
        
        Args:
            query: User's natural language query
            retrieved_logs: Logs retrieved from vector store
            attack_type: Detected attack type from classifier (AUTHORITATIVE)
            risk_score: Calculated risk score (AUTHORITATIVE)
            risk_level: Calculated risk level (AUTHORITATIVE)
            filters_applied: Human-readable filter summary
            max_context_length: Maximum context length for LLM
            
        Returns:
            Analysis results with summary and recommendations (attack_type preserved)
        """
        if not retrieved_logs:
            return {
                'summary': 'No logs found matching the query.',
                'attack_type': 'normal',
                'threat_detected': False,
                'severity': 'low',
                'risk_score': 0,
                'risk_level': 'low',
                'evidence': [],
                'supporting_logs': [],
                'recommendations': []
            }
        
        # Build structured prompt using PromptBuilder
        prompt = PromptBuilder.build_analysis_prompt(
            query=query,
            logs=retrieved_logs,
            attack_type=attack_type,
            filters_applied=filters_applied
        )
        
        # Get LLM response
        response_text = self._call_llm(prompt)
        
        # STEP 1: Try to parse JSON response
        analysis = self._parse_json_response(response_text, retrieved_logs)
        
        # STEP 2: Validate the parsed response
        is_valid, errors = self.validator.validate(analysis)
        
        validation_used = not is_valid
        fallback_used = False
        
        if not is_valid:
            logger.warning(f"LLM response validation failed: {errors}")
            
            # STEP 3: Try to repair the response
            repaired = self.validator.repair(response_text)
            
            if repaired:
                # Validate repaired response
                is_valid_repaired, repair_errors = self.validator.validate(repaired)
                if is_valid_repaired:
                    logger.info("Successfully repaired LLM response")
                    analysis = repaired
                else:
                    logger.warning(f"Repaired response still invalid: {repair_errors}")
                    # STEP 4: Use fallback
                    fallback_used = True
                    classifier_result = {
                        'attack_type': attack_type or 'normal',
                        'confidence': 0.8,
                        'reason': 'LLM response validation failed, using rule-based classification'
                    }
                    risk_result = {
                        'risk_score': risk_score or 0,
                        'risk_level': risk_level or 'low'
                    }
                    analysis = self.validator.fallback(classifier_result, risk_result, retrieved_logs)
            else:
                # STEP 4: Repair failed, use fallback
                logger.warning("Could not repair LLM response, using fallback")
                fallback_used = True
                classifier_result = {
                    'attack_type': attack_type or 'normal',
                    'confidence': 0.8,
                    'reason': 'LLM response unrecoverable, using rule-based classification'
                }
                risk_result = {
                    'risk_score': risk_score or 0,
                    'risk_level': risk_level or 'low'
                }
                analysis = self.validator.fallback(classifier_result, risk_result, retrieved_logs)
        
        # ENFORCE SINGLE SOURCE OF TRUTH (even if validation passed)
        # Rule-based classifier is AUTHORITATIVE for attack_type
        if attack_type:
            analysis['attack_type'] = attack_type
            analysis['threat_detected'] = (attack_type != 'normal')
        
        # Risk score and level are AUTHORITATIVE from risk engine
        if risk_score is not None:
            analysis['risk_score'] = risk_score
        if risk_level:
            analysis['risk_level'] = risk_level
        
        # Align severity with risk_level (CONSISTENCY ENFORCEMENT)
        analysis['severity'] = self._align_severity_with_risk(risk_level or analysis.get('risk_level', 'low'))
        
        # Validate response consistency
        analysis = self._validate_response_consistency(analysis)
        
        # Add validation tracking flags (if not already set by fallback)
        if 'validation_used' not in analysis:
            analysis['validation_used'] = validation_used
        if 'fallback_used' not in analysis:
            analysis['fallback_used'] = fallback_used
        
        return analysis
    
    def detect_anomalies(
        self,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Detect anomalies in logs
        
        Args:
            logs: List of log entries
            
        Returns:
            Anomaly detection results
        """
        if not logs:
            return {
                'anomalies_detected': False,
                'anomaly_count': 0,
                'anomalies': []
            }
        
        # Build structured prompt using PromptBuilder
        prompt = PromptBuilder.build_anomaly_detection_prompt(logs)
        
        # Get LLM response
        response = self._call_llm(prompt)
        
        # Parse anomalies (try JSON first)
        anomalies = self._parse_json_anomalies(response, logs)
        
        return anomalies
    
    def classify_threat(
        self,
        log_text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Classify threat level of a log entry
        
        Args:
            log_text: Log text to classify
            metadata: Optional metadata
            
        Returns:
            Threat classification
        """
        prompt = f"""Classify the threat level of this security log:

Log: {log_text}

Classify as:
- CRITICAL: Immediate security threat
- HIGH: Serious security concern
- MEDIUM: Potential security issue
- LOW: Minor concern or informational

Provide classification and brief reasoning."""
        
        response = self._call_llm(prompt)
        classification = self._parse_threat_classification(response)
        
        return classification
    
    def generate_summary(
        self,
        logs: List[Dict[str, Any]],
        focus: str = "security"
    ) -> str:
        """
        Generate summary of logs
        
        Args:
            logs: List of logs to summarize
            focus: Focus area (security, performance, errors)
            
        Returns:
            Summary text
        """
        if not logs:
            return "No logs to summarize."
        
        context = self._prepare_context(logs, 1500)
        
        prompt = f"""Summarize these {focus} logs concisely:

{context}

Provide a brief summary highlighting key points."""
        
        response = self._call_llm(prompt)
        return response.strip()
    
    def _call_llm(self, prompt: str) -> str:
        """Call Ollama LLM"""
        try:
            response = self.client.generate(
                model=self.model_name,
                prompt=prompt,
                options={
                    'temperature': 0.3,  # Lower temperature for more focused responses
                    'num_predict': 500   # Limit response length
                }
            )
            return response['response']
        except Exception as e:
            print(f"Error calling LLM: {e}")
            return "Error generating analysis."
    
    def _parse_json_response(
        self,
        response: str,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Parse JSON response from LLM with fallback to heuristic parsing"""
        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                parsed = json.loads(json_str)
                
                # Validate required fields
                result = {
                    'summary': parsed.get('summary', ''),
                    'attack_type': parsed.get('attack_type', 'normal'),
                    'severity': parsed.get('severity', 'low'),
                    'threat_detected': parsed.get('threat_detected', False),
                    'evidence': parsed.get('evidence', []),
                    'recommendations': parsed.get('recommendations', []),
                    'supporting_logs': [log.get('text', '') for log in logs[:3]],
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                return result
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Fallback to heuristic parsing
        return self._parse_analysis_heuristic(response, logs)
    
    def _parse_analysis_heuristic(
        self,
        response: str,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fallback heuristic parsing when JSON fails"""
        response_lower = response.lower()
        
        # Detect threat
        threat_keywords = ['threat', 'attack', 'malicious', 'suspicious', 'breach', 'intrusion']
        threat_detected = any(keyword in response_lower for keyword in threat_keywords)
        
        # Determine severity
        if 'critical' in response_lower:
            severity = 'critical'
        elif 'high' in response_lower:
            severity = 'high'
        elif 'medium' in response_lower:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Determine attack type
        if 'brute' in response_lower or 'brute force' in response_lower:
            attack_type = 'brute_force'
        elif 'ddos' in response_lower or 'denial of service' in response_lower:
            attack_type = 'ddos'
        elif 'suspicious login' in response_lower:
            attack_type = 'suspicious_login'
        else:
            attack_type = 'normal'
        
        # Extract recommendations
        recommendations = []
        lines = response.split('\n')
        for line in lines:
            if 'recommend' in line.lower() or 'should' in line.lower() or 'action' in line.lower():
                clean_line = line.strip().lstrip('-•*').strip()
                if len(clean_line) > 10:
                    recommendations.append(clean_line)
        
        return {
            'summary': response.strip(),
            'attack_type': attack_type,
            'threat_detected': threat_detected,
            'severity': severity,
            'evidence': [],
            'supporting_logs': [log.get('text', '') for log in logs[:3]],
            'recommendations': recommendations[:3] if recommendations else ['Monitor for similar patterns'],
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _parse_json_anomalies(
        self,
        response: str,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Parse JSON anomaly response with fallback"""
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                parsed = json.loads(json_str)
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Fallback to heuristic
        response_lower = response.lower()
        anomaly_keywords = ['anomaly', 'unusual', 'suspicious', 'abnormal']
        anomalies_detected = any(keyword in response_lower for keyword in anomaly_keywords)
        
        return {
            'anomalies_detected': anomalies_detected,
            'anomaly_count': len(logs) if anomalies_detected else 0,
            'analysis': response.strip(),
            'anomalies': [log.get('text', '') for log in logs[:5]] if anomalies_detected else []
        }
    
    def _parse_threat_classification(self, response: str) -> Dict[str, Any]:
        """Parse threat classification response"""
        response_lower = response.lower()
        
        if 'critical' in response_lower:
            level = 'critical'
        elif 'high' in response_lower:
            level = 'high'
        elif 'medium' in response_lower:
            level = 'medium'
        else:
            level = 'low'
        
        return {
            'threat_level': level,
            'reasoning': response.strip(),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _align_severity_with_risk(self, risk_level: str) -> str:
        """
        Align severity with risk level for consistency
        
        Args:
            risk_level: Risk level from risk engine
            
        Returns:
            Aligned severity level
        """
        # Mapping: risk_level -> severity
        mapping = {
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        }
        return mapping.get(risk_level, 'low')
    
    def _validate_response_consistency(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and fix response consistency
        
        Ensures:
        - attack_type matches threat_detected
        - severity aligns with risk_level
        - No contradictions in the response
        
        Args:
            analysis: Analysis result to validate
            
        Returns:
            Validated and corrected analysis
        """
        attack_type = analysis.get('attack_type', 'normal')
        
        # FIX 1: threat_detected must match attack_type
        analysis['threat_detected'] = (attack_type != 'normal')
        
        # FIX 2: severity must align with risk_level
        risk_level = analysis.get('risk_level', 'low')
        analysis['severity'] = self._align_severity_with_risk(risk_level)
        
        # FIX 3: Ensure risk_score exists
        if 'risk_score' not in analysis:
            analysis['risk_score'] = 0
        
        # FIX 4: Ensure risk_level exists
        if 'risk_level' not in analysis:
            analysis['risk_level'] = 'low'
        
        # FIX 5: Validate summary doesn't contradict attack_type
        summary = analysis.get('summary', '')
        if attack_type == 'normal' and any(word in summary.lower() for word in ['attack', 'threat', 'malicious', 'breach']):
            # Summary contradicts normal classification - fix it
            analysis['summary'] = 'No suspicious activity detected in the analyzed logs.'
        
        return analysis
    
    def _mock_analysis(
        self,
        query: str,
        logs: List[Dict[str, Any]]
    ) -> str:
        """Mock analysis for testing"""
        severity_counts = {}
        for log in logs:
            sev = log.get('metadata', {}).get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        summary = f"Analysis of {len(logs)} logs for query: '{query}'. "
        summary += f"Severity distribution: {severity_counts}. "
        
        # Check for high severity
        if severity_counts.get('high', 0) > 0 or severity_counts.get('critical', 0) > 0:
            summary += "HIGH severity issues detected. Immediate attention recommended."
            return summary
        
        summary += "No critical issues detected."
        return summary
    
    def _mock_anomaly_detection(self, logs: List[Dict[str, Any]]) -> str:
        """Mock anomaly detection"""
        return f"Analyzed {len(logs)} logs. No significant anomalies detected in this sample."
    
    def _mock_threat_classification(
        self,
        log_text: str,
        metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Mock threat classification"""
        if metadata and metadata.get('severity') in ['high', 'critical']:
            level = 'high'
            reasoning = "HIGH threat level detected based on severity indicators."
        else:
            level = 'low'
            reasoning = "LOW threat level. Log appears normal."
        
        return {
            'threat_level': level,
            'reasoning': reasoning,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _mock_summary(self, logs: List[Dict[str, Any]], focus: str) -> str:
        """Mock summary generation"""
        return f"Summary of {len(logs)} {focus} logs: Mixed severity levels observed. No immediate action required."
