import argparse
import json

from app.analyzer import analyze
from app.models import AnalyzeRequest
from app.registry import get_registry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["analyze"])
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    # AnalyzeRequest is a pydantic model, so model_validate handles nested
    # context_docs and metadata conversion automatically.
    request = AnalyzeRequest.model_validate(data)

    # get_registry() reuses the singleton DetectorRegistry, which loads the
    # real policy.yaml via load_policy() (same as main.py's FastAPI dep).
    registry = get_registry()

    result = analyze(request, registry)

    # AnalyzeResponse is also a pydantic model.
    with open(args.output, "w") as f:
        json.dump(result.model_dump(), f, indent=2)

    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()