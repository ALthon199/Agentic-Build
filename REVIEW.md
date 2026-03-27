1. [PASS] Uses Python and SQLite with minimal external dependencies.
   Evidence: SPEC.md:1-3 requires Python + SQLite; app.py:1-8 imports only Python standard library modules; SQLite is used throughout app.py:36-63, app.py:118-167, app.py:258-267, app.py:579-587.

2. [WARN] Coding style is generally clean, but type aliases or dataclasses would improve readability for repeated question payload structures.
   Evidence: SPEC.md:4-6 asks for clean code/concise helpers; app.py:362-389, app.py:414-433, app.py:536-603 repeatedly construct and pass raw Dict objects with overlapping keys.

3. [FAIL] App does not ask how many questions the user wants at startup; it asks for login/register first.
   Evidence: SPEC.md:10 requires this at app start; app.py:613-615 runs setup/login first, and app.py:621 asks question count only after login.

4. [PASS] Questions are selected from the question database and written to a generated JSON file.
   Evidence: SPEC.md:13-14; app.py:118-167 stores questions in quiz.db; app.py:414-437 loads from DB and writes generated_quiz.json.

5. [PASS] quiz.db exists conceptually and is populated from question_bank.json.
   Evidence: SPEC.md:57-59; app.py:10 defines quiz.db path, app.py:118-167 creates/populates questions table.

6. [PASS] user.db stores login data and quiz performance history in quiz_attempts.
   Evidence: SPEC.md:60; app.py:36-63 defines users and quiz_attempts tables, app.py:579-587 inserts attempts.

7. [PASS] Invalid question count input is reprompted until it is a whole number > 0 (and <= available questions).
   Evidence: SPEC.md:66; app.py:342-359 validates int conversion and positive range with reprompts.

8. [PASS] Missing/invalid generated quiz JSON triggers one refetch attempt and then an explicit restart/retry message.
   Evidence: SPEC.md:68; app.py:439-456 retries once and prints a recovery failure message.

9. [PASS] Invalid login allows only 3 attempts before exiting.
   Evidence: SPEC.md:70; app.py:326-339 decrements attempts and raises QuizError after 3 failures.

10. [PASS] Invalid answer formats are reprompted with explicit format guidance.
    Evidence: SPEC.md:72; app.py:469-487 (MC), app.py:489-497 (true/false), app.py:499-504 (short answer).

11. [PASS] Local login system supports both existing login and registration.
    Evidence: SPEC.md:75; app.py:304-325 offers login/register and account creation.

12. [PASS] Passwords are not stored in plaintext; salted PBKDF2 hashes are used.
    Evidence: SPEC.md:77; app.py:32-33 performs PBKDF2-HMAC, app.py:42-45 stores salt + password_hash.

13. [FAIL] Score history security is weaker than the spec expectation of being relatively secure.
    Evidence: SPEC.md:79; app.py:169-171 uses a hardcoded default secret when QUIZ_HISTORY_KEY is unset, and app.py:174-181 uses unauthenticated XOR-stream encryption (no integrity check), allowing tampering/forgery risk.

14. [PASS] Feedback (like/dislike/skip) is collected and used to influence future question selection weights.
    Evidence: SPEC.md:81; app.py:522-533 records feedback, app.py:396-405 adjusts sampling weights by liked/disliked values.

15. [PASS] Question bank is in a separate human-readable JSON file.
    Evidence: SPEC.md:83; question_bank.json:1-127 stores editable human-readable questions.

16. [PASS] Hint system exists and deducts points while still allowing answers.
    Evidence: SPEC.md:86; app.py:546-549 provides hint, app.py:566-567 applies reduced score (0.75 instead of 1.0).

17. [FAIL] Missing error handling for malformed question_bank.json can crash the app with an uncaught JSONDecodeError.
    Evidence: app.py:70-71 calls json.load without try/except; main only catches QuizError and KeyboardInterrupt at app.py:632-635.

18. [WARN] Missing IO/database exception handling can terminate the app unexpectedly on file permission, disk, or SQLite operational errors.
    Evidence: app.py:36-63, app.py:118-167, app.py:435-436, app.py:579-587 perform DB/file operations without handling OSError/sqlite3.OperationalError.

19. [WARN] Login hash comparison is not constant-time, which is a minor but avoidable security weakness.
    Evidence: app.py:284 uses direct bytes comparison instead of hmac.compare_digest.

20. [WARN] Usability issue: multiple-choice exact text matching is case-sensitive and whitespace-sensitive, which may reject semantically correct answers.
    Evidence: app.py:483-486 accepts only exact raw option text when not using numeric input; no normalization is applied.

21. [WARN] Usability/trust issue: generated_quiz.json includes answers in plaintext, so users can inspect the file and bypass quiz intent.
    Evidence: app.py:427 writes answer into generated_quiz.json for each question.

22. [WARN] Data model quality issue: question_feedback table lacks foreign key constraints, so orphaned feedback rows are possible.
    Evidence: app.py:133-143 defines question_feedback without FOREIGN KEY references to users/questions.
