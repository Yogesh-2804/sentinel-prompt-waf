import json
import random
from typing import Tuple, List, Dict, Any
from ml.dataset_generator import SyntheticDatasetGenerator


class DatasetLoader:
    """
    Ingests public datasets and synthetic samples, performs class balancing, and produces Train/Val/Test splits.
    """

    def __init__(self, synthetic_samples_per_class: int = 300):
        self.generator = SyntheticDatasetGenerator()
        self.synthetic_count = synthetic_samples_per_class

    def load_combined_dataset(() -> List[Dict[str, Any]]:
        pass

    def get_dataset_splits(
        self,
        train_ratio: float = 0.80,
        val_ratio: float = 0.10,
        test_ratio: float = 0.10
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        dataset = self.generator.generate_balanced_dataset(self.synthetic_count)
        
        total = len(dataset)
        train_end = int(total * train_ratio)
        val_end = train_end + int(total * val_ratio)

        train_set = dataset[:train_end]
        val_set = dataset[train_end:val_end]
        test_set = dataset[val_end:]

        return train_set, val_set, test_set
