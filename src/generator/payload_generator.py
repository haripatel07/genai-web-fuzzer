import random

DEFAULT_CORPUS_PATH = 'data/payload_corpus.txt'

class PayloadGenerator:
    """
    Generates fuzzing payloads based on a corpus file.
    Starts with simple random selection and basic mutations.
    """
    def __init__(self, corpus_path=DEFAULT_CORPUS_PATH):
        self.corpus = self._load_corpus(corpus_path)
        if not self.corpus:
            print("Warning: Payload corpus is empty or failed to load.")

    def _load_corpus(self, path):
        """Loads non-empty, non-comment lines from the corpus file."""
        lines = []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(line)
            print(f"Loaded {len(lines)} payloads from corpus: {path}")
            return lines
        except FileNotFoundError:
            print(f"Error: Corpus file not found at {path}")
            return []
        except Exception as e:
            print(f"Error reading corpus file {path}: {e}")
            return []

    def generate_payload(self):
        """Generates a single payload string."""
        if not self.corpus:
            return "default_fuzz_string" # Fallback payload
        
        # 1. Select a random base payload from the corpus
        base_payload = random.choice(self.corpus)

        # 2. Apply a random mutation (with a chance of no mutation)
        mutation_type = random.choice(['none', 'repeat', 'char_swap'])

        if mutation_type == 'repeat' and len(base_payload) > 0:
            repeat_part = random.randint(1, len(base_payload) // 2 + 1)
            times = random.randint(2, 5)
            mutated_payload = base_payload[:repeat_part] * times + base_payload[repeat_part:]
        elif mutation_type == 'char_swap' and len(base_payload) > 1:
            idx = random.randrange(len(base_payload))
            new_char = random.choice("';<>\"`()[]{}\n\t\\") # Common problematic chars
            mutated_payload = list(base_payload)
            mutated_payload[idx] = new_char
            mutated_payload = "".join(mutated_payload)
        else: # 'none' or edge cases
            mutated_payload = base_payload

        # Limit payload length to avoid overly long requests
        return mutated_payload[:256]

if __name__ == "__main__":
    generator = PayloadGenerator()
    print("\n--- Generating 10 sample payloads ---")
    for i in range(10):
        print(f"{i+1}: {generator.generate_payload()}")