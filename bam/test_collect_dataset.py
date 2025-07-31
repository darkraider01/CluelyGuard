import unittest
import os
import json
import sys
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from io import StringIO
from datetime import datetime

# Add the parent directory to the sys.path to allow importing collect_dataset
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import collect_dataset

class TestCollectDataset(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        os.makedirs("bam/dataset", exist_ok=True) # Ensure dataset directory exists for saving

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    @patch('builtins.input', side_effect=["word1", "word2", ""])
    @patch('collect_dataset.time.time', side_effect=[0, 1, 1, 1.8, 1.8, 3])
    def test_collect_human_mode(self, mock_time, mock_input):
        """Test collect() function in human mode."""
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            latencies = collect_dataset.collect(mode="human")
            self.assertEqual(latencies, [1.0, 0.8])
            self.assertIn("Collecting typing latency for mode: human", fake_stdout.getvalue())
            self.assertIn("Latency: 1.000 sec", fake_stdout.getvalue())
            self.assertIn("Latency: 0.800 sec", fake_stdout.getvalue())

    @patch('builtins.input', side_effect=["30"])
    @patch('collect_dataset.time.sleep', return_value=None)
    @patch('collect_dataset.random.uniform', side_effect=[0.1, 0.02] * 60) # Extended side_effect
    def test_collect_ai_mode_fixed_input(self, mock_random_uniform, mock_sleep, mock_input):
        """Test collect() function in AI mode with fixed input and mocked random."""
        class MockTime:
            def __init__(self):
                self._time = 0.0
                self._call_count = 0

            def __call__(self):
                self._call_count += 1
                # For every 'end' call (even call count), advance time by expected latency
                if self._call_count % 2 == 0:
                    self._time += round(0.1 + 5 * 0.02, 3) # Expected latency for a 5-char word
                return self._time

        with patch('collect_dataset.time.time', side_effect=MockTime()), \
             patch('sys.stdin', new_callable=StringIO) as mock_stdin:
            mock_stdin.write("hello world\n")
            mock_stdin.seek(0)
            
            with patch('sys.stdout', new=StringIO()) as fake_stdout:
                latencies = collect_dataset.collect(mode="ai")
                expected_latency = round(0.1 + 5 * 0.02, 3)
                self.assertEqual(len(latencies), 60)
                self.assertTrue(all(abs(l - expected_latency) < 0.001 for l in latencies)) # Use approximate comparison
                self.assertIn("Collecting typing latency for mode: ai", fake_stdout.getvalue())
                self.assertIn("Simulating AI typing for 60 words...", fake_stdout.getvalue())
                self.assertIn(f"Typed 'hello': {expected_latency:.3f} sec", fake_stdout.getvalue())
                self.assertIn(f"Typed 'world': {expected_latency:.3f} sec", fake_stdout.getvalue())

    @patch('builtins.input', side_effect=[""])
    @patch('collect_dataset.time.time', side_effect=lambda: 0.0)
    @patch('collect_dataset.time.sleep', return_value=None)
    @patch('collect_dataset.random.uniform', side_effect=[0.1, 0.02])
    def test_collect_ai_mode_no_input(self, mock_random_uniform, mock_sleep, mock_time, mock_input):
        """Test collect() in AI mode with no text input."""
        with patch('sys.stdin', new_callable=StringIO) as mock_stdin:
            mock_stdin.write("")
            mock_stdin.seek(0)

            with patch('sys.stdout', new=StringIO()) as fake_stdout:
                latencies = collect_dataset.collect(mode="ai")
                self.assertEqual(latencies, [])
                self.assertIn("No input received. No data collected for AI mode.", fake_stdout.getvalue())

    @patch('collect_dataset.time.sleep', return_value=None)
    @patch('collect_dataset.random.uniform', side_effect=[0.1, 0.02])
    def test_collect_ai_mode_invalid_repetitions(self, mock_random_uniform, mock_sleep):
        """Test collect() in AI mode with invalid repetitions input."""
        class MockTime:
            def __init__(self):
                self._time = 0.0
                self._call_count = 0

            def __call__(self):
                self._call_count += 1
                if self._call_count % 2 == 0:
                    self._time += round(0.1 + 4 * 0.02, 3) # Expected latency for a 4-char word
                return self._time

        with patch('builtins.input', side_effect=["abc"]), \
             patch('collect_dataset.time.time', side_effect=MockTime()), \
             patch('sys.stdin', new_callable=StringIO) as mock_stdin:
            mock_stdin.write("test\n")
            mock_stdin.seek(0)
            
            with patch('sys.stdout', new=StringIO()) as fake_stdout:
                latencies = collect_dataset.collect(mode="ai")
                self.assertIn("Invalid number, defaulting to 1 repetition.", fake_stdout.getvalue())
                expected_latency = round(0.1 + 4 * 0.02, 3)
                self.assertEqual(len(latencies), 1)
                self.assertEqual(latencies[0], expected_latency)


    @patch('collect_dataset.os.makedirs')
    @patch('builtins.open', new_callable=MagicMock)
    @patch('json.dump')
    @patch('collect_dataset.datetime')
    def test_save_function_success(self, mock_datetime, mock_json_dump, mock_open, mock_makedirs):
        """Test save() function with valid latencies."""
        mock_datetime.now.return_value = datetime(2025, 7, 31, 10, 0, 0)
        latencies = [0.1, 0.2, 0.3]
        mode = "test_mode"
        
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            collect_dataset.save(latencies, mode)
            mock_makedirs.assert_called_once_with("bam/dataset", exist_ok=True)
            expected_filename = f"bam/dataset/{mode}_{mock_datetime.now.return_value.strftime('%Y%m%d_%H%M%S')}.json"
            mock_open.assert_called_once_with(expected_filename, "w")
            
            expected_summary = {
                "mode": mode,
                "timestamp": "20250731_100000",
                "count": 3,
                "mean_latency": 0.2,
                "latencies": latencies,
            }
            mock_json_dump.assert_called_once_with(expected_summary, mock_open.return_value.__enter__(), indent=2)
            self.assertIn(f"Saved 3 latencies to {expected_filename}", fake_stdout.getvalue())

    @patch('collect_dataset.os.makedirs')
    @patch('builtins.open', new_callable=MagicMock)
    @patch('json.dump')
    @patch('collect_dataset.datetime')
    def test_save_function_no_latencies(self, mock_datetime, mock_json_dump, mock_open, mock_makedirs):
        """Test save() function with no latencies."""
        latencies = []
        mode = "test_mode"
        
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            collect_dataset.save(latencies, mode)
            mock_makedirs.assert_not_called()
            mock_open.assert_not_called()
            mock_json_dump.assert_not_called()
            self.assertIn("No latencies were recorded. Nothing to save.", fake_stdout.getvalue())

if __name__ == '__main__':
    unittest.main()