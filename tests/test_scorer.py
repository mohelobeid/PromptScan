"""Tests for the risk scorer module."""

import pytest

from promptscan.analyzer import VulnerabilityMatch
from promptscan.scorer import RiskScorer


class TestRiskScorer:
    """Test suite for RiskScorer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scorer = RiskScorer()

    def test_scorer_initialization(self):
        """Test that scorer initializes correctly."""
        assert self.scorer is not None

    def test_calculate_risk_score_no_vulnerabilities(self):
        """Test risk score calculation with no vulnerabilities."""
        score = self.scorer.calculate_risk_score([], 10)
        assert score == 0.0

    def test_calculate_risk_score_with_vulnerabilities(self):
        """Test risk score calculation with vulnerabilities."""
        vulnerabilities = [
            VulnerabilityMatch(
                vulnerability_type="System Prompt Leak",
                severity="HIGH",
                confidence=0.8,
                evidence="Test evidence",
                payload_used="Test payload",
                response_excerpt="Test excerpt"
            ),
            VulnerabilityMatch(
                vulnerability_type="Jailbreak",
                severity="CRITICAL",
                confidence=0.9,
                evidence="Test evidence",
                payload_used="Test payload",
                response_excerpt="Test excerpt"
            )
        ]

        score = self.scorer.calculate_risk_score(vulnerabilities, 10)
        
        assert 0.0 <= score <= 10.0
        assert score > 0.0  # Should have some risk

    def test_risk_score_range(self):
        """Test that risk scores are always in valid range."""
        # Test with various vulnerability combinations
        test_cases = [
            [],  # No vulnerabilities
            [VulnerabilityMatch("Test", "LOW", 0.3, "e", "p", "r")],
            [VulnerabilityMatch("Test", "CRITICAL", 0.9, "e", "p", "r")] * 5,
        ]

        for vulnerabilities in test_cases:
            score = self.scorer.calculate_risk_score(vulnerabilities, 10)
            assert 0.0 <= score <= 10.0

    def test_get_severity_level_critical(self):
        """Test severity level classification for critical scores."""
        assert self.scorer.get_severity_level(9.5) == "CRITICAL"
        assert self.scorer.get_severity_level(8.0) == "CRITICAL"

    def test_get_severity_level_high(self):
        """Test severity level classification for high scores."""
        assert self.scorer.get_severity_level(7.5) == "HIGH"
        assert self.scorer.get_severity_level(6.0) == "HIGH"

    def test_get_severity_level_medium(self):
        """Test severity level classification for medium scores."""
        assert self.scorer.get_severity_level(5.5) == "MEDIUM"
        assert self.scorer.get_severity_level(4.0) == "MEDIUM"

    def test_get_severity_level_low(self):
        """Test severity level classification for low scores."""
        assert self.scorer.get_severity_level(3.5) == "LOW"
        assert self.scorer.get_severity_level(2.0) == "LOW"

    def test_get_severity_level_minimal(self):
        """Test severity level classification for minimal scores."""
        assert self.scorer.get_severity_level(1.5) == "MINIMAL"
        assert self.scorer.get_severity_level(0.0) == "MINIMAL"

    def test_get_recommendation_critical(self):
        """Test recommendation for critical risk level."""
        recommendation = self.scorer.get_recommendation(9.0)
        assert "IMMEDIATE ACTION REQUIRED" in recommendation
        assert len(recommendation) > 50

    def test_get_recommendation_high(self):
        """Test recommendation for high risk level."""
        recommendation = self.scorer.get_recommendation(7.0)
        assert "HIGH PRIORITY" in recommendation
        assert len(recommendation) > 50

    def test_get_recommendation_medium(self):
        """Test recommendation for medium risk level."""
        recommendation = self.scorer.get_recommendation(5.0)
        assert "MODERATE RISK" in recommendation
        assert len(recommendation) > 50

    def test_get_recommendation_low(self):
        """Test recommendation for low risk level."""
        recommendation = self.scorer.get_recommendation(3.0)
        assert "LOW RISK" in recommendation
        assert len(recommendation) > 50

    def test_get_recommendation_minimal(self):
        """Test recommendation for minimal risk level."""
        recommendation = self.scorer.get_recommendation(1.0)
        assert "MINIMAL RISK" in recommendation
        assert len(recommendation) > 50

    def test_calculate_category_scores(self):
        """Test calculation of individual category scores."""
        vulnerabilities = [
            VulnerabilityMatch(
                vulnerability_type="System Prompt Leak",
                severity="HIGH",
                confidence=0.8,
                evidence="Test",
                payload_used="Test",
                response_excerpt="Test"
            ),
            VulnerabilityMatch(
                vulnerability_type="System Prompt Leak",
                severity="MEDIUM",
                confidence=0.6,
                evidence="Test",
                payload_used="Test",
                response_excerpt="Test"
            ),
            VulnerabilityMatch(
                vulnerability_type="Jailbreak",
                severity="CRITICAL",
                confidence=0.9,
                evidence="Test",
                payload_used="Test",
                response_excerpt="Test"
            )
        ]

        category_scores = self.scorer.calculate_category_scores(vulnerabilities)

        assert "System Prompt Leak" in category_scores
        assert "Jailbreak" in category_scores
        
        # All scores should be in valid range
        for score in category_scores.values():
            assert 0.0 <= score <= 10.0

    def test_severity_weights_exist(self):
        """Test that all severity weights are defined."""
        required_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        
        for severity in required_severities:
            assert severity in self.scorer.SEVERITY_WEIGHTS
            assert 0.0 <= self.scorer.SEVERITY_WEIGHTS[severity] <= 1.0

    def test_category_weights_exist(self):
        """Test that category weights are defined."""
        assert len(self.scorer.CATEGORY_WEIGHTS) > 0
        
        for weight in self.scorer.CATEGORY_WEIGHTS.values():
            assert 0.0 <= weight <= 1.0

    def test_high_success_rate_increases_score(self):
        """Test that high success rate increases risk score."""
        vulnerability = VulnerabilityMatch(
            vulnerability_type="Test",
            severity="MEDIUM",
            confidence=0.5,
            evidence="Test",
            payload_used="Test",
            response_excerpt="Test"
        )

        # Low success rate
        score_low = self.scorer.calculate_risk_score([vulnerability], 100)
        
        # High success rate (same vulnerability, fewer total payloads)
        score_high = self.scorer.calculate_risk_score([vulnerability], 2)

        assert score_high > score_low

    def test_multiple_same_category_vulnerabilities(self):
        """Test handling of multiple vulnerabilities in same category."""
        vulnerabilities = [
            VulnerabilityMatch(
                vulnerability_type="System Prompt Leak",
                severity="HIGH",
                confidence=0.8,
                evidence="Test 1",
                payload_used="Test",
                response_excerpt="Test"
            ),
            VulnerabilityMatch(
                vulnerability_type="System Prompt Leak",
                severity="MEDIUM",
                confidence=0.6,
                evidence="Test 2",
                payload_used="Test",
                response_excerpt="Test"
            ),
            VulnerabilityMatch(
                vulnerability_type="System Prompt Leak",
                severity="LOW",
                confidence=0.4,
                evidence="Test 3",
                payload_used="Test",
                response_excerpt="Test"
            )
        ]

        category_scores = self.scorer.calculate_category_scores(vulnerabilities)
        
        # Should only have one entry for System Prompt Leak
        assert len(category_scores) == 1
        assert "System Prompt Leak" in category_scores
        
        # Score should reflect highest severity
        assert category_scores["System Prompt Leak"] > 5.0
