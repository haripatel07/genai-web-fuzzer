import random
import re
try:
    import markovify
    MARKOVIFY_AVAILABLE = True
except ImportError:
    MARKOVIFY_AVAILABLE = False
    print("Warning: markovify not installed. Using basic generation only.")

DEFAULT_CORPUS_PATH = 'data/payload_corpus.txt'

class PayloadGenerator:
    """
    Generates fuzzing payloads based on a corpus file.
    Supports both simple random selection/basic mutations and advanced Markov chain generation.
    """
    def __init__(self, corpus_path=DEFAULT_CORPUS_PATH, use_markov=True):
        self.corpus = self._load_corpus(corpus_path)
        self.use_markov = use_markov and MARKOVIFY_AVAILABLE
        self.markov_model = None
        
        if not self.corpus:
            print("Warning: Payload corpus is empty or failed to load.")
            return
            
        if self.use_markov:
            self._build_markov_model()
        else:
            print("Using basic payload generation (Markovify not available or disabled)")

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

    def _build_markov_model(self):
        """Builds a Markov chain model from the corpus for advanced payload generation."""
        if not self.corpus:
            return
            
        # Join corpus into a single text for Markov chain training
        corpus_text = '\n'.join(self.corpus)
        
        # Create Markov model with reasonable state size
        self.markov_model = markovify.Text(corpus_text, state_size=2)
        print("Markov chain model built for advanced payload generation")

    def generate_payload(self):
        """Generates a single payload string using available methods."""
        if not self.corpus:
            return "default_fuzz_string" # Fallback payload
        
        # Use Markov generation if available and enabled (70% chance)
        if self.use_markov and self.markov_model and random.random() < 0.7:
            return self._generate_markov_payload()
        else:
            return self._generate_basic_payload()

    def _generate_markov_payload(self):
        """Generates a payload using Markov chain model."""
        try:
            # Generate payload with length constraints
            payload = self.markov_model.make_sentence(max_overlap_ratio=0.7, max_overlap_total=10)
            if payload:
                # Clean up and limit length
                payload = payload.strip()
                if len(payload) > 256:
                    payload = payload[:253] + "..."
                return payload
        except:
            pass
        
        # Fallback to basic generation if Markov fails
        return self._generate_basic_payload()

    def _generate_basic_payload(self):
        """Generates a payload using basic random selection and mutation."""
        # 1. Select a random base payload from the corpus
        base_payload = random.choice(self.corpus)

        # 2. Apply a random mutation (with a chance of no mutation)
        mutation_type = random.choice(['none', 'repeat', 'char_swap', 'concat', 'wrap'])

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
        elif mutation_type == 'concat' and len(self.corpus) > 1:
            # Concatenate two random payloads
            other_payload = random.choice([p for p in self.corpus if p != base_payload])
            mutated_payload = base_payload + random.choice(['', ' ', ';', '&', '|']) + other_payload
        elif mutation_type == 'wrap' and len(base_payload) > 0:
            # Wrap payload in common injection patterns
            wrappers = [
                f"'{base_payload}'",
                f'"{base_payload}"',
                f"<script>{base_payload}</script>",
                f"{{{base_payload}}}",
                f"(${base_payload})"
            ]
            mutated_payload = random.choice(wrappers)
        else: # 'none' or edge cases
            mutated_payload = base_payload

        # Limit payload length to avoid overly long requests
        return mutated_payload[:256]

if __name__ == "__main__":
    generator = PayloadGenerator()
    print("\n--- Generating 10 sample payloads ---")
    for i in range(10):
        print(f"{i+1}: {generator.generate_payload()}")