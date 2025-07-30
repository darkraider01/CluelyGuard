import unittest
import os
import json
from unittest.mock import patch, MagicMock
from io import StringIO
import sys
import tempfile
import shutil
from datetime import datetime

# Adjust the path to import bam.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import bam

class TestBam(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for logs and models
        self.test_dir = tempfile.mkdtemp()
        self.original_logs_dir = os.path.abspath("logs")
        self.original_model_path = os.path.abspath("bam_model.joblib")

        # Create a temporary directory for logs and models
        self.test_dir = tempfile.mkdtemp()
        self.original_logs_dir = os.path.abspath("logs")
        self.original_model_path = os.path.abspath("bam_model.joblib")
        
        # Change working directory for tests to a temporary directory
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

        # Mock the `os` module that `bam.py` imports
        self.mock_os_patch = patch('bam.os')
        self.mock_os = self.mock_os_patch.start()

        # Configure mocked os.path functions
        self.mock_os.path.abspath.side_effect = lambda x: {
            "logs": os.path.join(self.test_dir, "logs"),
            "bam_model.joblib": os.path.join(self.test_dir, "bam_model.joblib")
        }.get(x, os.path.join(self.test_dir, x))
        self.mock_os.path.exists.return_value = True # Default for exists

        # Configure mocked os.makedirs
        self.mock_os.makedirs.return_value = None # No-op for makedirs

        # Explicitly patch joblib and numpy to control ML_AVAILABLE
        self.patch_joblib = patch('bam.joblib', MagicMock())
        self.patch_numpy = patch('bam.np', MagicMock())
        self.mock_joblib = self.patch_joblib.start()
        self.mock_numpy = self.patch_numpy.start()

        # Set ML_AVAILABLE based on test needs
        bam.ML_AVAILABLE = True # Assume ML is available for most tests, override in specific tests

        # Explicitly patch joblib and numpy to control ML_AVAILABLE
        self.patch_joblib = patch('bam.joblib', MagicMock())
        self.patch_numpy = patch('bam.np', MagicMock())
        self.mock_joblib = self.patch_joblib.start()
        self.mock_numpy = self.patch_numpy.start()

        # Set ML_AVAILABLE based on test needs
        bam.ML_AVAILABLE = True # Assume ML is available for most tests, override in specific tests

    def tearDown(self):
        # Clean up the temporary directory
        shutil.rmtree(self.test_dir)
        # Restore original working directory
        os.chdir(self.original_cwd)
        # Stop all patches
        self.mock_os_patch.stop() # Stop the patch for bam.os
        self.patch_joblib.stop()
        self.patch_numpy.stop()

    @patch('builtins.input', side_effect=["word1", "word2", ""])
    @patch('bam.time.time', side_effect=[0, 1, 1, 1.8, 1.8, 3])
    def test_collect_typing_latencies(self, mock_time, mock_input):
        latencies = bam.collect_typing_latencies()
        self.assertEqual(latencies, [1.0, 0.8])

    def test_dummy_typing_data(self):
        data = bam.dummy_typing_data()
        self.assertEqual(len(data), 10)
        self.assertIsInstance(data[0], float)

    @patch('bam.joblib.load')
    @patch('bam.os.path.exists', return_value=True)
    def test_load_model_success(self, mock_exists, mock_load):
        mock_load.return_value = "mock_model"
        model = bam.load_model()
        self.assertEqual(model, "mock_model")
        mock_exists.assert_called_with("bam_model.joblib")
        mock_load.assert_called_with("bam_model.joblib")

    @patch('bam.os.path.exists', return_value=False)
    def test_load_model_not_found(self, mock_exists):
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            model = bam.load_model()
            self.assertIsNone(model)
            self.assertIn("Model file bam_model.joblib not found", fake_stdout.getvalue())

    @patch('bam.joblib.load', side_effect=Exception("Load error"))
    @patch('bam.os.path.exists', return_value=True)
    def test_load_model_error(self, mock_exists, mock_load):
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            model = bam.load_model()
            self.assertIsNone(model)
            self.assertIn("Error loading model: Load error", fake_stdout.getvalue())

    def test_detect_ai_typing_ml_available(self):
        # Configure mock_numpy for reshape and mock_joblib for predict/decision_function
        self.mock_numpy.array.return_value.reshape.return_value = "reshaped_data"
        self.mock_joblib.load.return_value = MagicMock(
            predict=MagicMock(return_value=[-1]),
            decision_function=MagicMock(return_value=[-0.8])
        )

        latencies = [0.1, 0.1, 0.1]
        result = bam.detect_ai_typing(latencies, self.mock_joblib.load.return_value)
        
        self.assertTrue(result["ai_detected"])
        self.assertAlmostEqual(result["confidence"], 0.8)
        self.assertAlmostEqual(result["anomaly_score"], -0.8)
        self.assertEqual(result["status"], "detection_complete")

    def test_detect_ai_typing_human_like(self):
        self.mock_numpy.array.return_value.reshape.return_value = "reshaped_data"
        self.mock_joblib.load.return_value = MagicMock(
            predict=MagicMock(return_value=[1]),
            decision_function=MagicMock(return_value=[0.5])
        )

        latencies = [1.0, 1.1, 1.2]
        result = bam.detect_ai_typing(latencies, self.mock_joblib.load.return_value)
        
        self.assertFalse(result["ai_detected"])
        self.assertAlmostEqual(result["confidence"], 0.5)
        self.assertAlmostEqual(result["anomaly_score"], 0.5)
        self.assertEqual(result["status"], "detection_complete")

    def test_detect_ai_typing_ml_unavailable(self):
        bam.ML_AVAILABLE = False # Temporarily set to False for this test
        latencies = [0.1, 0.1, 0.1]
        result = bam.detect_ai_typing(latencies, None)
        self.assertFalse(result["ai_detected"])
        self.assertEqual(result["status"], "detection_unavailable")

    def test_detect_ai_typing_no_latencies(self):
        result = bam.detect_ai_typing([], MagicMock())
        self.assertFalse(result["ai_detected"])
        self.assertEqual(result["status"], "detection_unavailable")

    @patch('bam.json.dump')
    @patch('bam.os.makedirs')
    @patch('bam.open', unittest.mock.mock_open(), create=True)
    @patch('bam.datetime')
    def test_save_log_with_detection(self, mock_datetime, mock_makedirs, mock_json_dump):
        mock_datetime.now.return_value = datetime(2023, 1, 1, 12, 0, 0)
        latencies = [0.5, 0.6]
        detection_result = {"ai_detected": True, "confidence": 0.9, "anomaly_score": -0.7, "status": "complete"}
        
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            log_path = bam.save_log(latencies, detection_result)
            self.assertTrue(log_path.startswith(os.path.join(self.test_dir, "logs", "bam_20230101_120000.json")))
            self.mock_makedirs.assert_called_with("logs")
            mock_json_dump.assert_called_once()
            self.assertIn("AI DETECTED", fake_stdout.getvalue())

    @patch('bam.json.dump')
    @patch('bam.os.makedirs')
    @patch('bam.open', unittest.mock.mock_open(), create=True)
    @patch('bam.datetime')
    def test_save_log_no_detection(self, mock_datetime, mock_makedirs, mock_json_dump):
        mock_datetime.now.return_value = datetime(2023, 1, 1, 12, 0, 0)
        latencies = [1.5, 1.6]
        
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            log_path = bam.save_log(latencies, None)
            self.assertTrue(log_path.startswith(os.path.join(self.test_dir, "logs", "bam_20230101_120000.json")))
            self.mock_makedirs.assert_called_with("logs")
            mock_json_dump.assert_called_once()
            self.assertIn("No detection", fake_stdout.getvalue()) # Check for the default status message

    @patch('bam.load_model', return_value=None)
    @patch('bam.dummy_typing_data', return_value=[])
    @patch('bam.save_log')
    def test_main_no_data(self, mock_save_log, mock_dummy_data, mock_load_model):
        with patch('sys.stdin.isatty', return_value=False): # Non-interactive mode
            bam.ML_AVAILABLE = False # Ensure ML is off for this path
            bam.main()
            mock_save_log.assert_called_with([], None)

    @patch('bam.load_model')
    @patch('bam.dummy_typing_data', return_value=[1.0, 0.5])
    @patch('bam.detect_ai_typing')
    @patch('bam.save_log')
    def test_main_with_data(self, mock_save_log, mock_detect_ai_typing, mock_dummy_data, mock_load_model):
        mock_load_model.return_value = "mock_model"
        mock_detect_ai_typing.return_value = {"ai_detected": True}
        
        with patch('sys.stdin.isatty', return_value=False): # Non-interactive mode
            bam.main()
            mock_detect_ai_typing.assert_called_with([1.0, 0.5], {"ai_detected": True})
            mock_save_log.assert_called_with([1.0, 0.5], {"ai_detected": True})

if __name__ == '__main__':
    unittest.main()