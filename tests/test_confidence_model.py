import logging
import os
import tempfile
import unittest

import main
from custom.confidence_features import (
    FEATURE_NAMES,
    candidate_to_vector,
    extract_features,
    shannon_entropy_bits,
)
from custom.confidence_model import ConfidenceModel, LogisticRegression
from custom.credential_extractor import extract_credentials_from_line
import train_confidence_model as trainer


def _silent_logger():
    log = logging.getLogger('test_conf')
    log.handlers = [logging.NullHandler()]
    log.setLevel(logging.CRITICAL)
    return log


def _candidate(line):
    cands = extract_credentials_from_line(line, mode='aggressive')
    assert cands, f'expected a candidate from: {line}'
    return cands[0], line


class FeatureExtractionTests(unittest.TestCase):
    def test_vector_length_matches_feature_names(self):
        cand, line = _candidate('https://portal.acme.com/login:jsmith:Str0ng!Pass9')
        vec = candidate_to_vector(cand, line)
        self.assertEqual(len(vec), len(FEATURE_NAMES))

    def test_entropy_monotonic(self):
        self.assertGreater(shannon_entropy_bits('Str0ng!Pass9'), shannon_entropy_bits('aaaaaa'))
        self.assertEqual(shannon_entropy_bits(''), 0.0)

    def test_trivial_signals(self):
        feats = extract_features({'identity': 'admin', 'password': 'admin', 'url': '', 'pattern': 'host_delimited'})
        self.assertEqual(feats['identity_equals_password'], 1.0)
        common = extract_features({'identity': 'bob', 'password': 'password', 'url': '', 'pattern': 'host_delimited'})
        self.assertEqual(common['password_is_common'], 1.0)

    def test_email_and_charset_signals(self):
        feats = extract_features(
            {'identity': 'k.nguyen@gmail.com', 'password': 'Wint3r#2023', 'url': '', 'pattern': 'email_delimited'}
        )
        self.assertEqual(feats['identity_is_email'], 1.0)
        self.assertEqual(feats['password_charset_classes'], 4.0)  # lower+upper+digit+symbol


class LogisticRegressionTests(unittest.TestCase):
    def _toy_data(self):
        # Single informative feature: positives have feature[0]=1, negatives 0.
        X = [[1.0] + [0.0] * (len(FEATURE_NAMES) - 1) for _ in range(20)]
        X += [[0.0] * len(FEATURE_NAMES) for _ in range(20)]
        y = [1] * 20 + [0] * 20
        return X, y

    def test_fits_separable_data(self):
        X, y = self._toy_data()
        model = LogisticRegression(epochs=300).fit(X, y)
        self.assertGreater(model.predict_proba_vector(X[0]), 0.5)
        self.assertLess(model.predict_proba_vector(X[-1]), 0.5)

    def test_save_load_round_trip(self):
        X, y = self._toy_data()
        model = LogisticRegression(epochs=100).fit(X, y)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'm.json')
            model.save(path)
            loaded = LogisticRegression.from_dict(__import__('json').load(open(path)))
        self.assertAlmostEqual(
            model.predict_proba_vector(X[0]), loaded.predict_proba_vector(X[0]), places=6
        )

    def test_fit_empty_raises(self):
        with self.assertRaises(ValueError):
            LogisticRegression().fit([], [])


class ConfidenceModelTests(unittest.TestCase):
    def test_load_missing_returns_none(self):
        self.assertIsNone(ConfidenceModel.load('/nonexistent/model.json'))

    def test_load_schema_mismatch_returns_none(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'm.json')
            with open(path, 'w') as f:
                json.dump({'feature_names': ['wrong'], 'weights': [0.0], 'bias': 0.0,
                           'mean': [0.0], 'std': [1.0]}, f)
            self.assertIsNone(ConfidenceModel.load(path))

    def test_score_in_unit_interval(self):
        examples = trainer.build_synthetic_dataset(120, seed=3)
        model, _ = trainer.train_and_evaluate(examples, seed=3)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'm.json')
            model.save(path)
            scorer = ConfidenceModel.load(path)
        cand, line = _candidate('mail.test.io:carla.bianchi:V3ry$ecret77')
        score = scorer.score(cand, line)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


class TrainerTests(unittest.TestCase):
    def test_is_trivial_candidate(self):
        self.assertTrue(trainer.is_trivial_candidate({'identity': 'admin', 'password': 'admin'}))
        self.assertTrue(trainer.is_trivial_candidate({'identity': 'bob', 'password': 'password'}))
        self.assertTrue(trainer.is_trivial_candidate({'identity': 'bob', 'password': 'x'}))
        self.assertFalse(trainer.is_trivial_candidate({'identity': 'bob', 'password': 'Str0ng!Pass9'}))

    def test_synthetic_dataset_is_balanced_and_labeled(self):
        examples = trainer.build_synthetic_dataset(200, seed=1)
        self.assertGreaterEqual(len(examples), 150)
        positives = sum(1 for _, label in examples if label == 1)
        # Roughly balanced (generator alternates positive/negative).
        self.assertGreater(positives, len(examples) * 0.3)
        self.assertLess(positives, len(examples) * 0.7)

    def test_train_and_evaluate_learns_signal(self):
        examples = trainer.build_synthetic_dataset(400, seed=5)
        _, metrics = trainer.train_and_evaluate(examples, seed=5)
        # Synthetic templates are cleanly separable; expect strong held-out scores.
        self.assertGreater(metrics['accuracy'], 0.9)
        self.assertGreater(metrics['f1'], 0.9)

    def test_label_line_weak_labels_strong_and_trivial(self):
        strong = trainer.label_line_weak('https://portal.acme.com/login:jsmith:Str0ng!Pass9')
        self.assertTrue(any(label == 1 for _, label in strong))
        trivial = trainer.label_line_weak('portal.acme.com:admin:admin')
        self.assertTrue(all(label == 0 for _, label in trivial))

    def test_trainer_main_writes_model(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'model.json')
            rc = trainer.main(['--synthetic', '200', '--out', out, '--seed', '2'])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))


class _StubScorer:
    """Duck-typed scorer that returns a fixed probability."""

    def __init__(self, value):
        self.value = value

    def score(self, candidate, raw_line=None):
        return self.value


class ScorerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()
        self.target = 'example.com'
        self.ctx = main.build_target_context(self.target)

    def _process(self, scorer):
        contents = 'example.com:admin:StrongPass1'
        seen = set()
        new_creds = []
        stats = main._new_stats()
        main._process_contents(
            contents,
            {'name': 'leakA'},
            mode='balanced',
            target_context=self.ctx,
            person_context=None,
            seen=seen,
            new_creds=new_creds,
            stats=stats,
            log=self.log,
            scorer=scorer,
        )
        return new_creds

    def test_scorer_rejection_overrides_heuristic(self):
        # Heuristic would accept this strong line; a low-scoring model rejects it.
        creds = self._process(_StubScorer(0.01))
        self.assertEqual(creds, [])

    def test_scorer_acceptance_sets_confidence(self):
        creds = self._process(_StubScorer(0.95))
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]['confidence'], 0.95)


if __name__ == '__main__':
    unittest.main()
