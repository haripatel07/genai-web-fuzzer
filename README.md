# AI-Smart-Fuzzer

An intelligent web application security fuzzer that uses AI-powered payload generation to discover vulnerabilities in web applications. The fuzzer combines Markov chain-based payload generation with advanced vulnerability detection patterns.

## Features

### Advanced AI Payload Generation
- **Markov Chain Model**: Generates realistic payloads based on patterns learned from a comprehensive corpus
- **Hybrid Approach**: Combines AI-generated payloads with traditional mutation techniques
- **Extensible Corpus**: Easy to add new payload types and patterns

### Comprehensive Vulnerability Detection
- **SQL Injection**: Detects various SQL injection patterns and error messages
- **Cross-Site Scripting (XSS)**: Identifies reflected, stored, and DOM-based XSS
- **Command Injection**: Recognizes shell command injection attempts
- **Path Traversal**: Detects directory traversal vulnerabilities
- **LDAP Injection**: Identifies LDAP query injection
- **XML External Entity (XXE)**: Detects XXE vulnerabilities
- **Information Disclosure**: Finds sensitive information leaks
- **Open Redirects**: Identifies redirection vulnerabilities

### High-Performance Multi-Threading
- **Concurrent Requests**: Send multiple payloads simultaneously
- **Configurable Threading**: Adjust thread count based on target capacity
- **Thread-Safe Operations**: Safe result collection and reporting

### Flexible HTTP Methods
- **GET Requests**: Traditional query parameter fuzzing
- **POST Requests**: Form data and body parameter testing
- **Extensible**: Easy to add support for other HTTP methods

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/AI-Smart-Fuzzer.git
cd AI-Smart-Fuzzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# GET request fuzzing (default)
python main.py http://example.com -param search -n 100

# POST request fuzzing
python main.py http://example.com/login -param username -m POST -n 50

# Multi-threaded fuzzing
python main.py http://example.com/api -param query -t 10 -n 200
```

### Command Line Options

- `base_url`: Target URL (required, or use `FUZZER_BASE_URL` env var)
- `-p, --path`: Path to fuzz (default: "/")
- `-param, --parameter`: Parameter name to fuzz (required, or use `FUZZER_PARAM` env var)
- `-n, --num_payloads`: Number of payloads to send (default: 100)
- `-m, --method`: HTTP method (GET or POST, default: GET)
- `-t, --threads`: Number of concurrent threads (default: 5)
- `-r, --rate-limit`: Max requests per second (default: 0, no limit)
- `-o, --output-file`: Output JSON file for vulnerabilities (default: output/results.json)
- `-c, --config`: Optional path to JSON config file

### Examples

```bash
# Fuzz a search endpoint
python main.py http://testapp.com -p /search -param q -n 100

# Fuzz a login form with POST
python main.py http://testapp.com -p /login -param password -m POST -t 3 -n 50

# High-throughput fuzzing
python main.py http://api.example.com -p /v1/search -param query -t 20 -n 1000 -r 25 -o output/results.json
```

## Project Structure

```
AI-Smart-Fuzzer/
├── main.py                 # Entry point with CLI interface
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── data/
│   └── payload_corpus.txt # Payload corpus for training
├── models/                # Directory for trained models
└── src/
    ├── fuzzer/
    │   └── web_fuzzer.py  # Main fuzzing engine
    └── generator/
        └── payload_generator.py # AI payload generation
```

## Payload Corpus

The `data/payload_corpus.txt` file contains various attack payloads categorized by vulnerability type:

- SQL Injection payloads
- XSS payloads
- Path Traversal payloads
- Command Injection payloads
- Basic fuzzing strings

Add your own payloads to improve the AI model's effectiveness.

## Advanced Features

### Custom Payload Generation

The `PayloadGenerator` class supports both Markov chain generation and traditional mutations:

```python
from src.generator.payload_generator import PayloadGenerator

generator = PayloadGenerator()
payload = generator.generate_payload()  # AI-generated payload
```

### Vulnerability Detection

The fuzzer uses regex patterns and content analysis to detect vulnerabilities:

- Status code analysis
- Response time monitoring
- Pattern matching for error messages
- Header analysis for information disclosure
- Content analysis for injection success

### Multi-Threading Architecture

- ThreadPoolExecutor for concurrent request handling
- Thread-safe result collection
- Configurable worker thread count
- Individual session per thread for isolation

## Security Considerations

**Important**: This tool is for authorized security testing only. Always obtain explicit permission before testing any web application.

- Use only against applications you own or have permission to test
- Respect rate limits and avoid overwhelming target servers
- Be aware of legal implications of unauthorized security testing

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Running tests

```bash
pip install -r requirements.txt
pip install pytest
pytest
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software.

## 🚀 Running with Docker

1. Build image:

```bash
docker build -t ai-smart-fuzzer .
```

2. Run (local target/input and output/results bind mounts):

```bash
docker run --rm -v $(pwd)/target:/app/input -v $(pwd)/results:/app/output ai-smart-fuzzer http://target.example.com -param q -n 50
```

3. Or start with Docker Compose:

```bash
docker-compose up --build
```

## ⚙️ CLI Usage

Run without Docker from the repository root:

```bash
pip install -r requirements.txt
python main.py <base_url> -param <parameter_name> [-p <path>] [-n <num_payloads>] [-m <GET|POST>] [-t <threads>]
```

Example:

```bash
python main.py http://example.com -p /search -param query -n 100 -m GET -t 10
```

### Is the project complete?

The core fuzzer is implemented and runnable as a CLI tool. It has basic payload generation, vulnerability pattern matching, and multi-threaded execution. Remaining improvements for production readiness include:

- Automatic output file writing (currently prints to stdout)
- Structured logging + result persistence
- Test coverage / integration tests
- Safe execution mode, rate limiting, and target validation
- Optionally, explicit config file support
