from engine.judge import PrivacyJudge


class FakeLawyer:
    def __init__(self, score):
        self.score = score

    def review(self, policy_text, hypothesis):
        return self.score


def test_violation_high_risk():
    judge = PrivacyJudge(lawyer=FakeLawyer(0.1))

    result = judge.adjudicate(
        "Some policy text",
        ["socket"]
    )

    assert result[0]["status"] == "VIOLATION"


def test_compliant_high_risk():
    judge = PrivacyJudge(lawyer=FakeLawyer(0.8))

    result = judge.adjudicate(
        "Some policy text",
        ["socket"]
    )

    assert result[0]["status"] == "COMPLIANT"


def test_low_risk_not_violation():
    judge = PrivacyJudge(lawyer=FakeLawyer(0.3))

    result = judge.adjudicate(
        "Some policy text",
        ["send"]
    )

    assert result[0]["status"] == "COMPLIANT"


def test_extreme_suspicion_low_risk():
    judge = PrivacyJudge(lawyer=FakeLawyer(0.1))

    result = judge.adjudicate(
        "Some policy text",
        ["send"]
    )

    assert result[0]["status"] == "VIOLATION"