import argparse
from src.fuzzer.web_fuzzer import WebFuzzer

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Smart Web Fuzzer")
    
    parser.add_argument("base_url", help="The base URL of the target (e.g., http://localhost:8080)")
    parser.add_argument("-p", "--path", default="/", help="The specific path to fuzz (e.g., /search)")
    parser.add_argument("-param", "--parameter", required=True, help="The name of the parameter to fuzz (e.g., query)")
    parser.add_argument("-n", "--num_payloads", type=int, default=100, help="Number of fuzzing payloads to send")
    
    args = parser.parse_args()
    
    print("*" * 60)
    print(f"Starting AI Smart Fuzzer")
    print(f"Target: {args.base_url}")
    print(f"Path: {args.path}")
    print(f"Parameter: {args.parameter}")
    print(f"Number of Payloads: {args.num_payloads}")
    print("*" * 60)
    
    fuzzer = WebFuzzer(args.base_url)
    results = fuzzer.fuzz_parameter(args.path, args.parameter, args.num_payloads)
    
    print("\n" + "=" * 60)
    if results:
        print(f"Fuzzing Complete. Found {len(results)} potential vulnerabilities:")
        for res in results:
            print(f"  - Indicator: {res['indicator']}, Payload: '{res['payload']}', URL: {res['url']}")
    else:
        print("Fuzzing Complete. No obvious vulnerabilities found with current checks.")
    print("=" * 60)

if __name__ == "__main__":
    main() 
