"""
Tests for the ML anomaly model (IsolationForest).
"""

import pytest
import numpy as np
import time
import shutil
import uuid

from src.detection.ml_model import MLAnomalyModel, MLModelConfig


@pytest.fixture
def model(tmp_path):
    """ML model with low training threshold for testing, unique dir."""
    config = MLModelConfig(
        min_train_samples=50,
        model_dir=str(tmp_path / f"test_models_{uuid.uuid4().hex[:8]}"),
        n_estimators=50,
        contamination=0.1,
    )
    return MLAnomalyModel(config)


def _normal_features() -> dict:
    return {
        "header_count": 8,
        "content_length": 0,
        "user_agent": "Mozilla/5.0 Chrome/120.0",
        "path": "/",
        "method": "GET",
        "accept_language": "en-US",
        "_raw_headers": {"cookie": "session=abc", "referer": "/"},
    }


def _attack_features() -> dict:
    return {
        "header_count": 2,
        "content_length": 0,
        "user_agent": "",
        "path": "/",
        "method": "GET",
        "accept_language": "",
        "_raw_headers": {},
    }


def test_model_not_ready_initially(model: MLAnomalyModel):
    """Model should not be ready before training."""
    assert model.is_ready is False
    assert model.score(_normal_features()) == 0.0


def test_record_samples(model: MLAnomalyModel):
    """Recording samples should increase buffer size."""
    for i in range(10):
        model.record_sample(_normal_features())
    assert model.sample_count == 10


@pytest.mark.asyncio
async def test_training_with_enough_samples(model: MLAnomalyModel):
    """Model should train when enough samples are available."""
    # Add normal traffic
    for i in range(55):
        model.record_sample(_normal_features(), rate_ratio=0.1, behavior_score=0.1)

    trained = await model.maybe_train()
    assert trained is True
    assert model.is_ready is True
    assert model.info()["train_count"] == 1


@pytest.mark.asyncio
async def test_training_insufficient_samples(model: MLAnomalyModel):
    """Model should not train with too few samples."""
    for i in range(10):
        model.record_sample(_normal_features())

    trained = await model.maybe_train()
    assert trained is False
    assert model.is_ready is False


@pytest.mark.asyncio
async def test_normal_request_scores_low(model: MLAnomalyModel):
    """After training on normal data, normal requests should score low."""
    for i in range(60):
        model.record_sample(_normal_features(), rate_ratio=0.1, behavior_score=0.1)

    await model.maybe_train()
    score = model.score(_normal_features(), rate_ratio=0.1, behavior_score=0.1)
    assert score < 0.6, f"Normal request scored {score}"


@pytest.mark.asyncio
async def test_attack_request_scores_higher(model: MLAnomalyModel):
    """After training on normal data, attack requests should score higher."""
    import random
    random.seed(42)
    # Add varied normal traffic
    for i in range(80):
        features = {
            "header_count": random.randint(6, 12),
            "content_length": random.randint(0, 500),
            "user_agent": "Mozilla/5.0 Chrome/120.0",
            "path": random.choice(["/", "/about", "/contact", "/blog"]),
            "method": "GET",
            "accept_language": "en-US",
            "_raw_headers": {"cookie": "session=abc", "referer": "/"},
        }
        model.record_sample(features, rate_ratio=random.uniform(0.01, 0.2), behavior_score=random.uniform(0.0, 0.15))

    await model.maybe_train()

    normal_score = model.score(_normal_features(), rate_ratio=0.1, behavior_score=0.1)
    attack_score = model.score(_attack_features(), rate_ratio=0.95, behavior_score=0.9)

    # Attack features (empty UA, high rate, high behavior) should differ from normal
    assert attack_score >= normal_score, (
        f"Attack score {attack_score} should be >= normal score {normal_score}"
    )


def test_extract_vector_shape(model: MLAnomalyModel):
    """Feature vector should have correct shape."""
    vec = model.extract_vector(_normal_features(), 0.5, 0.3)
    assert vec.shape == (11,)
    assert vec.dtype == np.float64


def test_info_dict(model: MLAnomalyModel):
    """Info should return complete status dict."""
    info = model.info()
    assert "is_ready" in info
    assert "train_count" in info
    assert "buffer_size" in info
    assert "min_train_samples" in info


@pytest.mark.asyncio
async def test_predict_label(model: MLAnomalyModel):
    """Predict label should return 1 for normal, -1 for anomaly."""
    # Before training, always returns 1
    assert model.predict_label(_normal_features()) == 1

    for i in range(60):
        model.record_sample(_normal_features(), rate_ratio=0.1, behavior_score=0.1)
    await model.maybe_train()

    # After training, normal should be 1
    label = model.predict_label(_normal_features(), rate_ratio=0.1, behavior_score=0.1)
    assert label == 1
