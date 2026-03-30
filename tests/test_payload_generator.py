import os
from src.generator.payload_generator import PayloadGenerator

def test_payload_generator_load_from_corpus():
    generator = PayloadGenerator()
    assert isinstance(generator.corpus, list)
    assert len(generator.corpus) > 0 or generator.corpus == []


def test_generate_payload_non_empty():
    generator = PayloadGenerator()
    payload = generator.generate_payload()
    assert isinstance(payload, str)
    assert len(payload) > 0
