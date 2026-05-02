"""
Output Validator for LLM Responses
Validates, repairs, and provides fallback for LLM JSON output
"""
import json
import re
from typing import Dict, Any, Tuple, List, Optional
import logging

logger = logging.getLogger(__name__)


class OutputValidator:
    """Validates and repairs LLM JSON output with fallback to rule-based results"""
    
    # Required fields in LLM response
    REQUIRED_FIELDS = [
        'summary',
        'severity',
        'threat_detected',
        'evidence',
        'recommendations'
    ]
    
    # Valid enum values
    VALID_SEVERITIES = ['low', 'medium', 'high', 'critical']
    VALID_ATTACK_TYPES = ['normal', 'brute_force', 'ddos', 'suspicious_login']
    
    def __init__(self):
        """Initialize validator"""
        pass
    
    def validate(self, response: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate LLM response structure and values
        
        Args:
            response: Parsed JSON response from LLM
            
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []
        
        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in response:
                errors.append(f"Missing required field: {field}")
        
        # Validate severity enum
        if 'severity' in response:
            severity = response['severity']
            if isinstance(severity, str):
                severity = severity.lower()
            if severity not in self.VALID_SEVERITIES:
                errors.append(f"Invalid severity value: {severity}. Must be one of {self.VALID_SEVERITIES}")
        
        # Validate attack_type enum (if present)
        if 'attack_type' in response:
            attack_type = response['attack_type']
            if isinstance(attack_type, str):
                attack_type = attack_type.lower()
            if attack_type not in self.VALID_ATTACK_TYPES:
                errors.append(f"Invalid attack_type value: {attack_type}. Must be one of {self.VALID_ATTACK_TYPES}")
        
        # Validate threat_detected is boolean
        if 'threat_detected' in response:
            if not isinstance(response['threat_detected'], bool):
                errors.append(f"threat_detected must be boolean, got: {type(response['threat_detected']).__name__}")
        
        # Validate evidence is list
        if 'evidence' in response:
            if not isinstance(response['evidence'], list):
                errors.append(f"evidence must be list, got: {type(response['evidence']).__name__}")
        
        # Validate recommendations is list
        if 'recommendations' in response:
            if not isinstance(response['recommendations'], list):
                errors.append(f"recommendations must be list, got: {type(response['recommendations']).__name__}")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def repair(self, raw_text: str) -> Optional[Dict[str, Any]]:
        """
        Attempt to extract and repair valid JSON from messy LLM output
        
        Handles:
        - Extra text before/after JSON
        - Trailing commas
        - Missing closing braces
        - Single quotes instead of double quotes
        - Unquoted keys
        
        Args:
            raw_text: Raw text response from LLM
            
        Returns:
            Parsed dict if successful, None if unrecoverable
        """
        if not raw_text or not isinstance(raw_text, str):
            logger.warning("repair: Invalid input - empty or not string")
            return None
        
        # Try direct JSON parse first
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError:
            pass
        
        # REPAIR STEP 1: Extract JSON from surrounding text
        # Look for content between first { and last }
        json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if not json_match:
            # Try to find opening brace and extract to end
            start_idx = raw_text.find('{')
            if start_idx >= 0:
                json_text = raw_text[start_idx:]
            else:
                logger.warning("repair: No JSON structure found in text")
                return None
        else:
            json_text = json_match.group(0)
        
        # REPAIR STEP 2: Fix common JSON issues
        
        # Remove trailing commas before closing braces/brackets
        json_text = re.sub(r',(\s*[}\]])', r'\1', json_text)
        
        # Replace single quotes with double quotes (but not in content)
        # This is a simple heuristic - replace ' with " around keys and simple values
        json_text = re.sub(r"'([^']*)'(\s*:)", r'"\1"\2', json_text)  # Keys
        json_text = re.sub(r":\s*'([^']*)'", r': "\1"', json_text)  # String values
        
        # Fix unquoted keys (simple pattern)
        json_text = re.sub(r'(\w+)(\s*:)', r'"\1"\2', json_text)
        
        # Fix already quoted keys that got double-quoted
        json_text = re.sub(r'""(\w+)""', r'"\1"', json_text)
        
        # Try parsing after repairs
        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            logger.warning(f"repair: JSON still invalid after repairs: {e}")
        
        # REPAIR STEP 3: Try to fix missing closing braces
        open_braces = json_text.count('{')
        close_braces = json_text.count('}')
        if open_braces > close_braces:
            json_text += '}' * (open_braces - close_braces)
            try:
                return json.loads(json_text)
            except json.JSONDecodeError:
                pass
        
        # REPAIR STEP 4: Last resort - extract key-value pairs manually
        try:
            return self._manual_json_extract(raw_text)
        except Exception as e:
            logger.warning(f"repair: Manual extraction failed: {e}")
            return None
    
    def _manual_json_extract(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Manually extract key-value pairs from text as last resort
        
        Args:
            text: Raw text
            
        Returns:
            Dict with extracted fields or None
        """
        result = {}
        
        # Extract summary
        summary_match = re.search(r'"summary"\s*:\s*"([^"]*)"', text, re.IGNORECASE)
        if summary_match:
            result['summary'] = summary_match.group(1)
        
        # Extract severity
        severity_match = re.search(r'"severity"\s*:\s*"(\w+)"', text, re.IGNORECASE)
        if severity_match:
            result['severity'] = severity_match.group(1).lower()
        
        # Extract threat_detected
        threat_match = re.search(r'"threat_detected"\s*:\s*(true|false)', text, re.IGNORECASE)
        if threat_match:
            result['threat_detected'] = threat_match.group(1).lower() == 'true'
        
        # Extract attack_type
        attack_match = re.search(r'"attack_type"\s*:\s*"(\w+)"', text, re.IGNORECASE)
        if attack_match:
            result['attack_type'] = attack_match.group(1).lower()
        
        # Extract evidence array (simplified)
        evidence_match = re.search(r'"evidence"\s*:\s*\[(.*?)\]', text, re.DOTALL | re.IGNORECASE)
        if evidence_match:
            evidence_text = evidence_match.group(1)
            # Extract quoted strings
            evidence_items = re.findall(r'"([^"]*)"', evidence_text)
            result['evidence'] = evidence_items if evidence_items else []
        else:
            result['evidence'] = []
        
        # Extract recommendations array (simplified)
        rec_match = re.search(r'"recommendations"\s*:\s*\[(.*?)\]', text, re.DOTALL | re.IGNORECASE)
        if rec_match:
            rec_text = rec_match.group(1)
            rec_items = re.findall(r'"([^"]*)"', rec_text)
            result['recommendations'] = rec_items if rec_items else []
        else:
            result['recommendations'] = []
        
        # Only return if we got at least summary
        if 'summary' in result:
            return result
        
        return None
    
    def fallback(
        self,
        classifier_result: Dict[str, Any],
        risk_result: Dict[str, Any],
        retrieved_logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Build valid response from rule-based classifier and risk engine results
        
        Args:
            classifier_result: Result from rule-based classifier
            risk_result: Result from risk engine
            retrieved_logs: Retrieved log entries
            
        Returns:
            Valid response dict with all required fields
        """
        attack_type = classifier_result.get('attack_type', 'normal')
        risk_level = risk_result.get('risk_level', 'low')
        risk_score = risk_result.get('risk_score', 0)
        
        # Build summary from classifier reason
        reason = classifier_result.get('reason', 'Analysis completed')
        if attack_type == 'normal':
            summary = 'No suspicious activity detected in the analyzed logs.'
        else:
            summary = f"Detected {attack_type.replace('_', ' ')} attack. {reason}"
        
        # Extract evidence from logs
        evidence = []
        for log in retrieved_logs[:3]:
            text = log.get('text', '')
            if text:
                evidence.append(text[:100])  # First 100 chars
        
        if not evidence:
            evidence = [reason]
        
        # Generate recommendations based on attack type
        recommendations = self._generate_recommendations(attack_type, risk_level)
        
        # Build response with consistency
        response = {
            'summary': summary,
            'attack_type': attack_type,
            'threat_detected': (attack_type != 'normal'),
            'severity': self._align_severity_with_risk(risk_level),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'evidence': evidence,
            'recommendations': recommendations,
            'supporting_logs': [log.get('text', '')[:200] for log in retrieved_logs[:3]],
            'confidence': classifier_result.get('confidence', 0.8),
            'fallback_used': True,
            'validation_used': True
        }
        
        return response
    
    def _generate_recommendations(self, attack_type: str, risk_level: str) -> List[str]:
        """Generate recommendations based on attack type and risk level"""
        recommendations = []
        
        if attack_type == 'brute_force':
            recommendations.append('Implement account lockout after failed login attempts')
            recommendations.append('Enable multi-factor authentication')
            recommendations.append('Monitor and block suspicious IP addresses')
            if risk_level in ['high', 'critical']:
                recommendations.append('Immediately investigate compromised accounts')
        
        elif attack_type == 'ddos':
            recommendations.append('Enable rate limiting on affected endpoints')
            recommendations.append('Configure DDoS protection at network level')
            recommendations.append('Scale infrastructure to handle traffic spike')
            if risk_level in ['high', 'critical']:
                recommendations.append('Contact ISP for upstream filtering')
        
        elif attack_type == 'suspicious_login':
            recommendations.append('Verify legitimacy of login from unusual location')
            recommendations.append('Force password reset for affected accounts')
            recommendations.append('Review recent account activity')
        
        else:  # normal
            recommendations.append('Continue monitoring for anomalies')
            recommendations.append('Maintain current security posture')
        
        return recommendations
    
    def _align_severity_with_risk(self, risk_level: str) -> str:
        """Align severity with risk level for consistency"""
        mapping = {
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        }
        return mapping.get(risk_level, 'low')
