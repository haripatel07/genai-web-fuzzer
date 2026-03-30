import argparse
import json
import os
from pathlib import Path
from src.fuzzer.web_fuzzer import WebFuzzer


def load_json_config(path):
    """Load optional JSON config, returning an empty dict on failures."""
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config file not found at {path}. Using CLI/default values.")
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config file {path}: {e}. Using CLI/default values.")
    except Exception as e:
        print(f"Error loading config file {path}: {e}. Using CLI/default values.")
    return {}


def write_results(output_file, results):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="AI-Powered Smart Web Fuzzer")

    parser.add_argument("base_url", nargs='?', default=os.getenv('FUZZER_BASE_URL'), help="The base URL of the target (e.g., http://localhost:8080)")
    parser.add_argument("-p", "--path", default=os.getenv('FUZZER_PATH', '/'), help="The specific path to fuzz (e.g., /search)")
    parser.add_argument("-param", "--parameter", required=False, default=os.getenv('FUZZER_PARAM'), help="The name of the parameter to fuzz (e.g., query)")
    parser.add_argument("-n", "--num_payloads", type=int, default=int(os.getenv('FUZZER_NUM_PAYLOADS', '100')), help="Number of fuzzing payloads to send")
    parser.add_argument("-m", "--method", default=os.getenv('FUZZER_METHOD', 'GET'), choices=["GET", "POST"], help="HTTP method to use for fuzzing (default: GET)")
    parser.add_argument("-t", "--threads", type=int, default=int(os.getenv('FUZZER_THREADS', '5')), help="Number of concurrent threads for fuzzing (default: 5)")
    parser.add_argument("-r", "--rate-limit", type=float, default=float(os.getenv('FUZZER_RATE_LIMIT', '0')), help="Rate limit in requests per second (0 = no limit)")
    parser.add_argument("-o", "--output-file", default=os.getenv('FUZZER_OUTPUT_FILE', 'output/results.json'), help="File path to save detected vulnerabilities")
    parser.add_argument("-c", "--config", help="Optional JSON config file path")

    args = parser.parse_args()

    config = load_json_config(args.config)

    base_url = args.base_url or config.get('base_url')
    parameter = args.parameter or config.get('parameter')
    path = args.path or config.get('path', '/')
    num_payloads = args.num_payloads or config.get('num_payloads', 100)
    method = args.method or config.get('method', 'GET')
    threads = args.threads or config.get('threads', 5)
    rate_limit = args.rate_limit or config.get('rate_limit', 0)
    output_file = args.output_file or config.get('output_file', 'output/results.json')

    if not base_url or not parameter:
        parser.print_help()
        print("\nError: base_url and parameter are required either by args, env vars, or config file.")
        return

    print("*" * 60)
    print(f"Starting AI Smart Fuzzer")
    print(f"Target: {base_url}")
    print(f"Path: {path}")
    print(f"Parameter: {parameter}")
    print(f"Method: {method}")
    print(f"Threads: {threads}")
    print(f"Number of Payloads: {num_payloads}")
    print(f"Rate Limit: {rate_limit} req/s")
    print(f"Output File: {output_file}")
    print("*" * 60)

    fuzzer = WebFuzzer(base_url, max_workers=threads, rate_limit=rate_limit)
    results = fuzzer.fuzz_parameter(path, parameter, num_payloads, method)

    print("\n" + "=" * 60)
    if results:
        print(f"Fuzzing Complete. Found {len(results)} potential vulnerabilities:")
        for res in results:
            print(f"  - Indicator: {res['indicator']}, Payload: '{res['payload']}', URL: {res['url']}")
        write_results(output_file, results)
        print(f"Results written to {output_file}")
    else:
        print("Fuzzing Complete. No obvious vulnerabilities found with current checks.")

    print("=" * 60)


if __name__ == "__main__":
    main() 
