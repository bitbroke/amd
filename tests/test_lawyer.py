import pytest
from unittest.mock import MagicMock, patch
from engine.lawyer import PrivacyLawyer

@pytest.fixture
def lawyer():
    # Initialize without loading the real model to keep tests fast
    return PrivacyLawyer(load_model=False)

def test_lawyer_initializes_without_model(lawyer):
    assert lawyer.model is None

def test_review_raises_without_model(lawyer):
    with pytest.raises(RuntimeError, match="Model not loaded"):
        lawyer.review("text", "hypothesis")

def test_review_logic_calculation():
    """
    This test mocks the AI components to verify the 'Review' math:
    Score = Entailment - Contradiction
    """
    lawyer = PrivacyLawyer(load_model=False)
    
    # 1. Mock the components your review() method expects
    mock_torch = MagicMock()
    mock_tokenizer = MagicMock()
    mock_model = MagicMock()
    
    # 2. Setup the "Fake" Softmax Output
    # We want to simulate: Contradiction=0.1, Neutral=0.0, Entailment=0.9
    # Your code looks for scores[0][0] and scores[0][2]
    mock_score_0 = MagicMock()
    mock_score_0.item.return_value = 0.1  # Contradiction
    
    mock_score_2 = MagicMock()
    mock_score_2.item.return_value = 0.9  # Entailment
    
    mock_torch.nn.functional.softmax.return_value = [[mock_score_0, None, mock_score_2]]
    
    # 3. Inject these mocks into our lawyer instance
    lawyer.torch = mock_torch
    lawyer.tokenizer = mock_tokenizer
    lawyer.model = mock_model
    lawyer.device = "cpu"
    
    # 4. Run the review
    # Expected: 0.9 (Entailment) - 0.1 (Contradiction) = 0.8
    score = lawyer.review("The app collects GPS", "The app tracks location")
    
    assert score == pytest.approx(0.8)