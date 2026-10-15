"""Module registry: one place that lists every tool and its menu position."""

from .agent_tool_auditor import AgentToolAuditor
from .ai_analyst import AiSecurityAnalyst
from .ai_chatbot_guard import AiChatbotGuard
from .chat_log_auditor import ChatLogAuditor
from .email_header_analyzer import EmailHeaderAnalyzer
from .file_integrity import FileIntegrityMonitor
from .guard_kit import GuardIntegrationKit
from .ioc_extractor import IocExtractor
from .jwt_inspector import JwtInspector
from .llm_redteam import LlmRedTeam
from .log_analyzer import LogAnalyzer
from .osint_aggregator import OsintAggregator
from .password_auditor import PasswordAuditor
from .phishing_url_classifier import PhishingUrlClassifier
from .prompt_injection_detector import PromptInjectionDetector
from .rag_poison_scanner import RagPoisonScanner
from .secrets_scanner import SecretsScanner
from .system_prompt_auditor import SystemPromptAuditor
from .vuln_report_summarizer import VulnReportSummarizer
from .web_security_check import WebSecurityChecker

ORDERED = [
    LogAnalyzer, PromptInjectionDetector, VulnReportSummarizer, OsintAggregator, PhishingUrlClassifier,
    AiChatbotGuard, LlmRedTeam, SystemPromptAuditor, RagPoisonScanner, AgentToolAuditor, ChatLogAuditor, GuardIntegrationKit,
    AiSecurityAnalyst,
    SecretsScanner, WebSecurityChecker, EmailHeaderAnalyzer, JwtInspector, IocExtractor, PasswordAuditor, FileIntegrityMonitor,
]
CATEGORIES = ["Detection & Analysis", "AI Security", "Security Utilities"]


def build() -> dict:
    """Return {menu_key: module_instance} numbered 1..N in registry order."""
    return {str(i): cls() for i, cls in enumerate(ORDERED, 1)}
