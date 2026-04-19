import argparse
import uvicorn

def main():
    # Set up argument parsing for the port
    parser = argparse.ArgumentParser(description="Start the Vulnalyzer API")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    args = parser.parse_args()

    port = args.port

    # Print the ASCII banner
    print("\n  ╔══════════════════════════════════════╗")
    print("  ║          Vulnalyzer API              ║")
    print("  ╠══════════════════════════════════════╣")
    print(f"  ║  API  →  http://localhost:{port}/api  ║")
    print(f"  ║  UI   →  http://localhost:{port}/     ║")
    print("  ╚══════════════════════════════════════╝\n")

    # Run Uvicorn programmatically
    # Note: Pass the import string "vulnalyzer.api.app:app" to allow --reload to work correctly
    uvicorn.run("vulnalyzer.api.app:app", host="127.0.0.1", port=port, reload=True)

if __name__ == "__main__":
    main()