"""
SentinelCorp Local Demonstration Knowledge Base
Provides synthetic company information for the SentinelCorp AI Assistant.
"""

from typing import Dict, Any, Optional, Tuple

SENTINELCORP_KNOWLEDGE_BASE = {
    "company_overview": (
        "SentinelCorp is an enterprise cybersecurity technology company specializing in "
        "AI security, cloud protection, and web application firewalls."
    ),
    "annual_leave_policy": (
        "SentinelCorp provides 24 days of paid annual leave per calendar year for full-time employees. "
        "Leave requests must be submitted through the HR Portal at least 5 business days in advance. "
        "Employees can carry forward up to 5 unused leave days to the next year."
    ),
    "working_hours": (
        "Standard working hours at SentinelCorp are Monday to Friday, 9:00 AM to 5:00 PM (Local Time), "
        "with a 1-hour lunch break. Core collaboration hours are 10:00 AM to 4:00 PM."
    ),
    "employee_benefits": (
        "SentinelCorp offers comprehensive health, dental, and vision insurance, a 401(k) matching plan "
        "up to 6%, wellness allowances ($500/year), and continuous learning professional development stipends."
    ),
    "it_support_policy": (
        "IT Support is available 24/7 via the IT Helpdesk Portal or by emailing support@sentinelcorp.internal. "
        "Critical hardware issues receive priority resolution within 2 hours. Password resets and access "
        "requests are processed within 1 business hour."
    ),
    "salary_payroll_policy": (
        "SentinelCorp operates structured salary bands per grade level reviewed annually during Q4 performance appraisals. "
        "Payroll is processed on the 25th of each month via direct bank deposit. Individual compensation details remain strictly confidential."
    ),
    "security_incident_policy": (
        "Employees must report suspected security incidents, phishing attempts, or unauthorized access to security@sentinelcorp.internal immediately. "
        "Security incident response team triage is active 24/7."
    ),
    "hr_portal_url": (
        "The official SentinelCorp HR and Employee Self-Service portal is located internally at https://hr.sentinelcorp.internal."
    ),
    "hr_guidelines": (
        "All HR inquiries, performance review documents, and benefit updates can be accessed via "
        "the SentinelCorp Employee Self-Service portal. Remote work options are governed by team manager approval."
    )
}


class KnowledgeBaseService:
    def __init__(self):
        self.kb = SENTINELCORP_KNOWLEDGE_BASE
        self.general_knowledge_phrases = [
            "what is prompt injection", "prompt injection", "authentication versus authorization",
            "authentication and authorization", "what is machine learning", "machine learning",
            "what is an api", "an api", "what is phishing", "phishing", "what is a firewall",
            "multi-factor authentication", "explain encryption", "cybersecurity concepts"
        ]
        self.specific_unsupported_facts = [
            "wifi password", "wi-fi password", "cafeteria password", "cafeteria wi-fi",
            "database server address", "internal database server", "exact database address",
            "employee directory location", "internal employee directory", "directory location"
        ]

    def is_general_knowledge(self, prompt: str) -> bool:
        """Identifies non-company-specific general cybersecurity and technical queries."""
        prompt_lower = prompt.lower()
        # If explicitly asking about SentinelCorp internal resources, it's company-specific
        if "sentinelcorp" in prompt_lower or "internal" in prompt_lower:
            if not any(gk in prompt_lower for gk in ["what is prompt injection", "authentication versus authorization", "what is phishing"]):
                return False

        return any(gk in prompt_lower for gk in self.general_knowledge_phrases)

    def get_company_context(self, prompt: str) -> Tuple[Optional[str], bool, str]:
        """
        Retrieves matching SentinelCorp knowledge context for a prompt.
        Returns (context_str, is_grounded_match, classification_type).
        Classification types: 'GENERAL_KNOWLEDGE', 'COMPANY_SPECIFIC', 'UNGROUNDED_COMPANY_FACT'.
        """
        prompt_lower = prompt.lower()

        # Check for non-company general knowledge
        if self.is_general_knowledge(prompt):
            return None, True, "GENERAL_KNOWLEDGE"

        # Check for specific ungrounded company facts (e.g. cafeteria Wi-Fi password, database server IP)
        if any(fact in prompt_lower for fact in self.specific_unsupported_facts):
            return None, False, "UNGROUNDED_COMPANY_FACT"

        matched_sections = []

        if any(w in prompt_lower for w in ["leave", "vacation", "annual leave", "pto"]):
            matched_sections.append(f"Leave Policy: {self.kb['annual_leave_policy']}")
        if any(w in prompt_lower for w in ["working hours", "hours", "timing", "schedule"]):
            matched_sections.append(f"Working Hours: {self.kb['working_hours']}")
        if any(w in prompt_lower for w in ["benefit", "benefits", "health", "401k", "insurance"]):
            matched_sections.append(f"Employee Benefits: {self.kb['employee_benefits']}")
        if any(w in prompt_lower for w in ["it support", "helpdesk", "password reset", "password-reset"]):
            matched_sections.append(f"IT Support Policy: {self.kb['it_support_policy']}")
        if any(w in prompt_lower for w in ["payroll", "monthly payroll", "salary policy", "payroll policy"]):
            matched_sections.append(f"Salary & Payroll Policy: {self.kb['salary_payroll_policy']}")
        if any(w in prompt_lower for w in ["security incident", "phishing"]):
            matched_sections.append(f"Security Incident Policy: {self.kb['security_incident_policy']}")
        if any(w in prompt_lower for w in ["hr portal", "portal url", "hr url"]):
            matched_sections.append(f"HR Portal URL: {self.kb['hr_portal_url']}")
        if any(w in prompt_lower for w in ["company", "about", "overview", "sentinelcorp"]):
            matched_sections.append(f"Company Overview: {self.kb['company_overview']}")

        if matched_sections:
            return "\n\n".join(matched_sections), True, "COMPANY_SPECIFIC"

        # General corporate fallback context
        if any(w in prompt_lower for w in ["policy", "guidelines", "hr", "support"]):
            return f"Company Overview: {self.kb['company_overview']}\nGeneral HR Guidelines: {self.kb['hr_guidelines']}", True, "COMPANY_SPECIFIC"

        # Out-of-KB query
        return None, False, "UNGROUNDED_COMPANY_FACT"
