#!/usr/bin/env python3
"""DataProbe CAPTCHA solver using ddddocr.
Usage: python ddddocr_solver.py <image_path>
Outputs: recognized text to stdout, errors to stderr.
"""

import sys
import os

def main():
    if len(sys.argv) < 2:
        print("", end="")
        return

    image_path = sys.argv[1]
    if not os.path.exists(image_path):
        print("", end="")
        return

    try:
        import ddddocr
        ocr = ddddocr.DdddOcr(show_ad=False)
        with open(image_path, "rb") as f:
            image_bytes = f.read()
        result = ocr.classification(image_bytes)
        print(result.strip(), end="")
    except ImportError:
        print("", end="")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr, end="")
        print("", end="")

if __name__ == "__main__":
    main()
