import unittest
import os
import json
import numpy as np
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from io import StringIO

import sys
import importlib

class TestTrain(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

        # Ensure our test directory is at the beginning of sys.path
        # and remove the current directory from sys.path if it's there
        # to prevent conflicts when importing 'train'.
        if self.original_cwd in sys.path:
            sys.path.remove(self.original_cwd)
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

        # Force reload 'train' module in case it was already loaded
        if 'train' in sys.modules:
            del sys.modules['train']
        global train # Declare train as global
        import train # Import train inside setUp

        # Create a dummy dataset directory within the temporary directory
        self.dataset_dir = os.path.join(self.test_dir, "bam/bam/dataset")
        os.makedirs(self.dataset_dir, exist_ok=True)

        # Patch DATASET_DIR and MODEL_PATH in train.py to point to our test directory
        self.original_dataset_dir = train.DATASET_DIR
        self.original_model_path = train.MODEL_PATH
        train.DATASET_DIR = self.dataset_dir
        train.MODEL_PATH = os.path.join(self.test_dir, "bam/bam_model.joblib")

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)
        # Restore original paths
        train.DATASET_DIR = self.original_dataset_dir
        train.MODEL_PATH = self.original_model_path
        # Clean up sys.path
        if os.path.abspath(os.path.join(os.path.dirname(__file__), '..')) in sys.path:
            sys.path.remove(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        if self.original_cwd not in sys.path:
            sys.path.insert(0, self.original_cwd)
        # Remove the train module from sys.modules to ensure a clean import next time
        if 'train' in sys.modules:
            del sys.modules['train']

    def create_dummy_data_file(self, mode, latencies, filename=""):
        if not filename:
            filename = f"{mode}_test.json"
        filepath = os.path.join(self.dataset_dir, filename)
        summary = {
            "mode": mode,
            "latencies": latencies,
        }
        with open(filepath, "w") as f:
            json.dump(summary, f)
        return filepath

    def test_load_data_human(self):
        """Test load_data() for human samples."""
        self.create_dummy_data_file("human", [0.1, 0.2, 0.3], "human_1.json")
        self.create_dummy_data_file("human", [0.4, 0.5], "human_2.json")
        self.create_dummy_data_file("ai", [0.01, 0.02], "ai_1.json") # Should be ignored

        latencies = train.load_data("human")
        self.assertEqual(sorted(latencies), sorted([0.1, 0.2, 0.3, 0.4, 0.5]))

    def test_load_data_ai(self):
        """Test load_data() for AI samples."""
        self.create_dummy_data_file("ai", [0.01, 0.02, 0.03], "ai_1.json")
        self.create_dummy_data_file("human", [0.1, 0.2], "human_1.json") # Should be ignored

        latencies = train.load_data("ai")
        self.assertEqual(sorted(latencies), sorted([0.01, 0.02, 0.03]))

    def test_load_data_empty_dir(self):
        """Test load_data() with an empty dataset directory."""
        latencies = train.load_data("human")
        self.assertEqual(latencies, [])

    def test_load_data_non_existent_dir(self):
        """Test load_data() with a non-existent dataset directory."""
        shutil.rmtree(self.dataset_dir) # Remove the created directory
        latencies = train.load_data("human")
        self.assertEqual(latencies, [])

    def test_load_data_malformed_json(self):
        """Test load_data() with a malformed JSON file."""
        filepath = os.path.join(self.dataset_dir, "human_malformed.json")
        with open(filepath, "w") as f:
            f.write("this is not json {")
        
        with patch('sys.stdout', new=StringIO()) as fake_stdout:
            latencies = train.load_data("human")
            self.assertEqual(latencies, [])
            self.assertIn(f"Failed to read human_malformed.json", fake_stdout.getvalue())

    @patch('train.IsolationForest')
    @patch('train.np.array')
    def test_train_model(self, mock_np_array, mock_isolation_forest):
        """Test train_model() function."""
        mock_model_instance = MagicMock()
        mock_isolation_forest.return_value = mock_model_instance
        
        # Mock the return value of reshape to be a MagicMock object
        mock_reshaped_array = MagicMock()
        mock_np_array.return_value.reshape.return_value = mock_reshaped_array

        data = [0.1, 0.2, 0.3]
        model = train.train_model(data)

        mock_np_array.assert_called_once_with(data)
        mock_np_array.return_value.reshape.assert_called_once_with(-1, 1)
        mock_isolation_forest.assert_called_once_with(contamination='auto', random_state=42)
        mock_model_instance.fit.assert_called_once_with(mock_reshaped_array)
        self.assertEqual(model, mock_model_instance)

    def test_main_no_human_data(self):
        """Test main() when no human data is available."""
        with patch('train.load_data', side_effect=[[], []]) as mock_load_data, \
             patch('sys.stdout', new=StringIO()) as mock_stdout:
            train.main()
            self.assertIn("Not enough human data to train the model. Please collect human samples first.", mock_stdout.getvalue())

    def test_main_with_data(self):
        """Test main() with sufficient human data."""
        with patch('train.load_data', side_effect=[[0.1, 0.2, 0.3], [0.01, 0.02]]) as mock_load_data, \
             patch('train.train_model') as mock_train_model, \
             patch('train.os.makedirs') as mock_makedirs, \
             patch('train.dump') as mock_dump, \
             patch('sys.stdout', new=StringIO()) as mock_stdout:
            
            mock_model = MagicMock()
            mock_train_model.return_value = mock_model
            
            train.main()
            
            mock_load_data.assert_any_call("human")
            mock_load_data.assert_any_call("ai")
            mock_train_model.assert_called_once_with([0.1, 0.2, 0.3])
            mock_makedirs.assert_called_once_with(os.path.dirname(train.MODEL_PATH), exist_ok=True)
            mock_dump.assert_called_once_with(mock_model, train.MODEL_PATH)
            self.assertIn("Model trained and saved to", mock_stdout.getvalue())

if __name__ == '__main__':
    unittest.main()