
# Task 12: Explore a Cryptography Concept

## Project Title
SHA-256 Hashing and File Integrity Verification

## 1. Objective
The objective of this project is to understand SHA-256 hashing
and demonstrate how it can help identify changes in a file.

## 2. Concept Explanation
SHA-256 is a cryptographic hash function that produces a
256-bit hash value, usually displayed as 64 hexadecimal characters.

The same input produces the same hash when the same algorithm
is used. A small change in the input will normally produce a
very different hash.

Hashing is different from encryption because hashing is not
designed to be reversed to recover the original content.

## 3. Tools Used
- Python 3
- Visual Studio Code
- Python hashlib library
- PowerShell terminal

## 4. Project Files
- hash_demo.py: Calculates the SHA-256 hash and checks file integrity.
- sample.txt: Sample file used for testing.
- baseline.sha256: Stores the original hash for comparison.
- screenshots/: Stores evidence of the test results.

## 5. Methodology
1. Create a sample text file.
2. Calculate its SHA-256 hash.
3. Save the first hash as the baseline.
4. Run the program again without changing the file.
5. Modify the file and run the program again.
6. Compare the current hash with the saved baseline.

## 6. Test Results

### Test 1: Baseline Creation
The program calculated the original hash and saved it
in baseline.sha256.

Result: PASS

### Test 2: Unchanged File
The file was restored to its original content.
The current hash matched the saved baseline.

Result: PASS - FILE UNCHANGED

### Test 3: Modified File
The sample file content was changed.
The current hash did not match the saved baseline.

Result: PASS - FILE MODIFIED

## 7. What SHA-256 Can Protect
- It can help detect accidental or unauthorized changes
  when compared with a trusted reference hash.
- It can help verify file integrity.
- It is useful in software downloads, digital forensics,
  and security monitoring workflows.

## 8. Limitations
- Hashing does not encrypt or hide file contents.
- A hash alone does not prove who created or sent a file.
- A matching hash does not prove authenticity if the reference
  hash itself is untrusted.
- If an attacker can change both the file and its saved baseline,
  this simple program may not detect the change.
- SHA-256 alone is not a password-storage solution.

## 9. Conclusion
This project demonstrated SHA-256 hashing and file integrity
verification using Python. The tests showed that an unchanged
file matched its saved baseline, while a modified file produced
a different hash.

The experiment helped explain the usefulness and limitations
of cryptographic hashing.

## 10. References
- Python hashlib documentation:
  https://docs.python.org/3/library/hashlib.html
- NIST Secure Hash Standard (FIPS 180-4):
  https://csrc.nist.gov/pubs/fips/180-4/upd1/final
