import argparse
import json
import sys
from json import JSONDecodeError

from pydantic import ValidationError

from app.analyzer import analyze
from app.models import AnalyzeRequest
from app.registry import get_registry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["analyze"])
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        with open(args.input) as f:
            data = json.load(f)

        request = AnalyzeRequest.model_validate(data)

        registry = get_registry()

        result = analyze(request, registry)

        with open(args.output, "w") as f:
            json.dump(result.model_dump(), f, indent=2)

        print(f"Wrote {args.output}")

    except FileNotFoundError as e:
        print(f"Input file not found: {e.filename}", file=sys.stderr)
        sys.exit(1)

    except PermissionError as e:
        print(f"Permission denied: {e.filename}", file=sys.stderr)
        sys.exit(1)

    except JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    except ValidationError as e:
        print("Input does not match AnalyzeRequest schema:", file=sys.stderr)
        print(e, file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()