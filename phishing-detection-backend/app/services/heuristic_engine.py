import re
from urllib.parse import urlparse

class PhishingHeuristicEngine:
    """
    Evaluates three independent risk vectors:
      1. Homoglyph / lookalike character spoofing
      2. Excessive subdomain nesting (URL inputs only)
      3. High-urgency social-engineering language

    Each vector contributes a capped score to a combined 0-100 total.
    The vector contributing the most points is reported as the
    "dominant_vector" for analyst triage.
    """

    # Scoring weights central configuration
    WEIGHT_HOMOGLYPH = 40
    WEIGHT_SUBDOMAIN = 25
    WEIGHT_URGENCY_PER_HIT = 10
    WEIGHT_URGENCY_MAX = 30

    # Threat classification thresholds
    THRESHOLD_SUSPICIOUS = 30
    THRESHOLD_MALICIOUS = 60

    # Defensive cap to mitigate ReDoS-style resource exhaustion
    MAX_INPUT_LENGTH = 4096

    # Matches characters from scripts commonly used in IDN homograph attacks
    # (Cyrillic, Greek, Latin Extended) that visually resemble standard Latin letters.
    HOMOGLYPH_PATTERN = re.compile(
        r"[\u0400-\u04FF\u0370-\u03FF\u1E00-\u1EFF]"
    )

    # Common ASCII character-substitution tricks within domain-like tokens
    SUSPICIOUS_SUBSTITUTIONS = [
        re.compile(r"rn", re.IGNORECASE),        # 'rn' looks like 'm'
        re.compile(r"vv"),                        # 'vv' looks like 'w'
        re.compile(r"(?<=[a-z])\d|\d(?=[a-z])"),  # digit fused with letters, e.g., payp4l
    ]

    # High-urgency social-engineering phrases
    URGENCY_KEYWORDS = [
        re.compile(r"action required", re.IGNORECASE),
        re.compile(r"unauthorized login", re.IGNORECASE),
        re.compile(r"verify immediate(?:ly)?", re.IGNORECASE),
        re.compile(r"account (?:has been )?suspended", re.IGNORECASE),
        re.compile(r"confirm your (?:identity|account|password)", re.IGNORECASE),
        re.compile(r"urgent(?:ly)? (?:required|requested|action)", re.IGNORECASE),
    ]

    def analyze_input(self, raw_input: str) -> dict:
        """
        Run all heuristic checks against `raw_input` and return a
        structured risk assessment.
        """
        if not isinstance(raw_input, str):
            raise TypeError("raw_input must be a string")

        cleaned_input = raw_input.strip()
        if not cleaned_input:
            raise ValueError("raw_input cannot be empty or whitespace-only")

        # Truncate oversized payloads as a safety baseline
        cleaned_input = cleaned_input[: self.MAX_INPUT_LENGTH]

        score = 0
        vector_scores: dict[str, int] = {}

        # 1. Homoglyph / lookalike character check
        homoglyph_hit, homoglyph_detail = self._check_homoglyphs(cleaned_input)
        if homoglyph_hit:
            score += self.WEIGHT_HOMOGLYPH
            vector_scores["Homoglyph / Lookalike Domain Spoofing"] = self.WEIGHT_HOMOGLYPH

        # 2. Excessive subdomain count check
        subdomain_count, subdomain_flagged = self._check_subdomains(cleaned_input)
        if subdomain_flagged:
            score += self.WEIGHT_SUBDOMAIN
            vector_scores["Excessive Subdomain Nesting"] = self.WEIGHT_SUBDOMAIN

        # 3. High-urgency keyword check
        urgency_hits, urgency_score = self._check_urgency_keywords(cleaned_input)
        if urgency_score:
            score += urgency_score
            vector_scores["High-Urgency Social Engineering Language"] = urgency_score

        # Clamp total score between 0 and 100
        score = max(0, min(score, 100))

        # Determine threat classification status
        if score >= self.THRESHOLD_MALICIOUS:
            threat_status = "malicious"
        elif score >= self.THRESHOLD_SUSPICIOUS:
            threat_status = "suspicious"
        else:
            threat_status = "safe"

        # Isolate dominant vector (the rule contributing the highest score)
        if vector_scores:
            dominant_vector = max(vector_scores, key=vector_scores.get)
        else:
            dominant_vector = "No significant threat indicators detected"

        return {
            "score": score,
            "threat_status": threat_status,
            "dominant_vector": dominant_vector,
            "details": {
                "homoglyph_detected": homoglyph_hit,
                "homoglyph_detail": homoglyph_detail,
                "subdomain_count": subdomain_count,
                "subdomain_flagged": subdomain_flagged,
                "urgency_keywords_found": urgency_hits,
                "vector_scores": vector_scores,
            },
        }

    def _check_homoglyphs(self, text: str) -> tuple[bool, str | None]:
        match = self.HOMOGLYPH_PATTERN.search(text)
        if match:
            return True, f"Non-Latin lookalike character detected: '{match.group()}'"

        # Restrict substitution checks to domain-like tokens to avoid false positives on standard words
        for token in re.findall(r"[a-zA-Z0-9\-]{4,}\.[a-zA-Z]{2,}", text):
            for pattern in self.SUSPICIOUS_SUBSTITUTIONS:
                if pattern.search(token):
                    return True, f"Suspicious character substitution in token: '{token}'"

        return False, None

    def _check_subdomains(self, text: str) -> tuple[int, bool]:
        hostname = self._extract_hostname(text)
        if not hostname:
            return 0, False

        labels = hostname.split(".")
        subdomain_count = max(0, len(labels) - 2)

        return subdomain_count, subdomain_count > 2

    def _check_urgency_keywords(self, text: str) -> tuple[list[str], int]:
        hits = []
        for pattern in self.URGENCY_KEYWORDS:
            match = pattern.search(text)
            if match:
                hits.append(match.group())

        raw_score = len(hits) * self.WEIGHT_URGENCY_PER_HIT
        return hits, min(raw_score, self.WEIGHT_URGENCY_MAX)

    @staticmethod
    def _extract_hostname(text: str) -> str | None:
        candidate = text.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", candidate):
            candidate = "http://" + candidate

        try:
            parsed = urlparse(candidate)
            hostname = parsed.hostname
        except ValueError:
            return None

        if hostname and "." in hostname:
            return hostname.lower()

        return None