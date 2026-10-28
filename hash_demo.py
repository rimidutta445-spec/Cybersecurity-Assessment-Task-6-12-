
import hashlib
from pathlib import Path

BASE_DIR = Path(__file__).parent
FILE_PATH = BASE_DIR / "sample.txt"
BASELINE_PATH = BASE_DIR / "baseline.sha256"


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def main():
    if not FILE_PATH.exists():
        print("ERROR: sample.txt not found.")
        return

    current_hash = calculate_sha256(FILE_PATH)

    print("=" * 45)
    print("TASK 12: FILE INTEGRITY VERIFICATION")
    print("=" * 45)
    print("File:", FILE_PATH.name)
    print("Current SHA-256:", current_hash)

    if not BASELINE_PATH.exists():
        BASELINE_PATH.write_text(current_hash, encoding="utf-8")
        print("\nBaseline hash saved.")
        print("Run the program again after changing the file.")
    else:
        saved_hash = BASELINE_PATH.read_text(
            encoding="utf-8"
        ).strip()

        print("Saved SHA-256:", saved_hash)

        if current_hash == saved_hash:
            print("\nRESULT: FILE UNCHANGED")
            print("The file matches the saved baseline.")
        else:
            print("\nRESULT: FILE MODIFIED")
            print("The file differs from the saved baseline.")

    print("=" * 45)


if __name__ == "__main__":
    main()
