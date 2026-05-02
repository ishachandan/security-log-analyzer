"""
Prompt Builder for LLM Analysis
Generates structured, specific prompts for security log analysis
"""

from typing import List, Dict, Any, Optional
from datetime import datetime


class PromptBuilder:
    """Builds structured prompts for LLM-based log analysis"""
    
    @staticmethod
    def build_analysis_prompt(
        query: str,
        logs: List[Dict[str, Any]],
        attack_type: Optional[str] = None,
        filters_applied: Optional[str] = None
    ) -> str:
        """
        Build a structured prompt for log analysis
        
        Args:
            query: User's natural language query
            logs: Retrieved log entries with metadata
            attack_type: Detected attack type from classifier
            filters_applied: Human-readable filter summary
            
        Returns:
            Structured prompt string
        """
        # Build log details section
        log_details = []
        for i, log in enumerate(logs[:10], 1):  # Limit to top 10
            metadata = log.get('metadata', {})
            text = log.get('text', '')
            
            log_entry = f"Log {i}:\n"
            log_entry += f"  Content: {text}\n"
            
            if 'timestamp' in metadata:
                log_entry += f"  Time: {metadata['timestamp']}\n"
            if 'source_ip' in metadata:
                log_entry += f"  IP: {metadata['source_ip']}\n"
            if 'severity' in metadata:
                log_entry += f"  Severity: {metadata['severity']}\n"
            if 'log_type' in metadata:
                log_entry += f"  Type: {metadata['log_type']}\n"
            if 'status_code' in metadata:
                log_entry += f"  Status: {metadata['status_code']}\n"
            if 'user' in metadata:
                log_entry += f"  User: {metadata['user']}\n"
                
            log_details.append(log_entry)
        
        logs_section = "\n".join(log_details)
        
        # Build context section
        context_parts = []
        if filters_applied:
            context_parts.append(f"Filters Applied: {filters_applied}")
        if attack_type and attack_type != "normal":
            context_parts.append(f"Detected Attack Pattern: {attack_type}")
        
        context_section = "\n".join(context_parts) if context_parts else "No filters applied"
        
        # Build the prompt
        prompt = f"""You are a cybersecurity analyst. The system has ALREADY classified these logs using rule-based time-window detection.

USER QUERY: {query}

CONTEXT:
{context_section}

RETRIEVED LOGS:
{logs_section}

YOUR TASK: Explain the detected pattern using specific details from the logs above.

DETECTED CLASSIFICATION: {attack_type if attack_type else 'normal'}

CRITICAL RULES:
1. DO NOT change or override the attack type - it is ALREADY determined by authoritative rule-based analysis
2. Your ONLY job is to EXPLAIN WHY this classification was made using log evidence
3. Reference specific log details (IPs, timestamps, users, status codes) from the RETRIEVED LOGS section
4. DO NOT use generic phrases like "may indicate", "could be", "suggests possible"
5. DO NOT invent or hallucinate any data not present in the logs above
6. Provide concrete evidence from the actual logs shown above
7. Assign severity based on the attack type: brute_force/ddos=high, suspicious_login=medium, normal=low

OUTPUT FORMAT (strict JSON):
{{
  "summary": "Specific explanation of WHY the system detected {attack_type if attack_type else 'normal'} with actual log references",
  "severity": "critical | high | medium | low",
  "threat_detected": {str(attack_type != 'normal' and attack_type is not None).lower()},
  "evidence": [
    "Specific evidence item 1 with actual IPs/timestamps from logs above",
    "Specific evidence item 2 with actual data from logs above"
  ],
  "recommendations": [
    "Specific action 1 based on the detected pattern",
    "Specific action 2"
  ]
}}

Respond ONLY with valid JSON. No additional text."""

        return prompt
    
    @staticmethod
    def build_anomaly_detection_prompt(logs: List[Dict[str, Any]]) -> str:
        """
        Build prompt for anomaly detection
        
        Args:
            logs: Log entries to analyze for anomalies
            
        Returns:
            Structured prompt for anomaly detection
        """
        # Extract key patterns
        ips = set()
        users = set()
        status_codes = set()
        
        for log in logs:
            metadata = log.get('metadata', {})
            if 'source_ip' in metadata:
                ips.add(metadata['source_ip'])
            if 'user' in metadata:
                users.add(metadata['user'])
            if 'status_code' in metadata:
                status_codes.add(str(metadata['status_code']))
        
        log_summary = f"""
Total Logs: {len(logs)}
Unique IPs: {len(ips)} ({', '.join(list(ips)[:5])})
Unique Users: {len(users)} ({', '.join(list(users)[:5])})
Status Codes: {', '.join(sorted(status_codes))}
"""
        
        # Build detailed log list
        log_details = []
        for i, log in enumerate(logs[:15], 1):
            metadata = log.get('metadata', {})
            text = log.get('text', '')
            log_details.append(f"{i}. {text} | IP: {metadata.get('source_ip', 'N/A')} | Severity: {metadata.get('severity', 'N/A')}")
        
        logs_text = "\n".join(log_details)
        
        prompt = f"""You are a cybersecurity analyst detecting anomalies in security logs.

LOG SUMMARY:
{log_summary}

DETAILED LOGS:
{logs_text}

TASK:
Identify anomalies and suspicious patterns in these logs. Look for:
- Unusual access patterns (repeated failures, unusual times)
- Suspicious IP addresses or users
- Error spikes or unusual status codes
- Potential security threats

CRITICAL RULES:
- Reference SPECIFIC IPs, users, timestamps, and patterns from the logs
- DO NOT use vague language
- Provide concrete evidence with actual data points

OUTPUT FORMAT (strict JSON):
{{
  "anomalies_detected": true or false,
  "anomaly_count": number,
  "anomalies": [
    {{
      "type": "anomaly type",
      "severity": "critical | high | medium | low",
      "description": "Specific description with actual IPs/users/data",
      "affected_entities": ["IP or user or resource"],
      "evidence": ["Specific log references"]
    }}
  ],
  "summary": "Overall assessment with specific findings"
}}

Respond ONLY with valid JSON."""

        return prompt
