from engine.verifier import PrivacyVerifier

def test_entropy_low_for_text():
    verifier = PrivacyVerifier("dummy")
    entropy = verifier.calculate_entropy(b"hello world")

    assert entropy < 5