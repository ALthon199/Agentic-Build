import hashlib
import json
import os
import random
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

QUIZ_DB = Path("quiz.db")
USER_DB = Path("user.db")
QUESTION_BANK_FILE = Path("question_bank.json")
GENERATED_QUIZ_FILE = Path("generated_quiz.json")
SCORE_HISTORY_FILE = Path("score_history.bin")

PBKDF2_ROUNDS = 200_000
HISTORY_MAGIC = b"QH1"


class QuizError(Exception):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


def create_user_db() -> None:
    with sqlite3.connect(USER_DB) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                score REAL NOT NULL,
                total_questions INTEGER NOT NULL,
                hints_used INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
        conn.commit()


def load_question_bank() -> List[Dict]:
    if not QUESTION_BANK_FILE.exists():
        raise QuizError("Question bank file is missing.")

    with QUESTION_BANK_FILE.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    questions = payload.get("questions")
    if not isinstance(questions, list) or not questions:
        raise QuizError("Question bank JSON is invalid or empty.")

    validated: List[Dict] = []
    for index, question in enumerate(questions, start=1):
        if not isinstance(question, dict):
            raise QuizError(f"Question #{index} is not an object.")

        q_text = question.get("question")
        q_type = question.get("type")
        answer = question.get("answer")
        category = question.get("category", "General")
        hint = question.get("hint", "No hint provided.")

        if not all(isinstance(value, str) and value.strip() for value in [q_text, q_type, answer]):
            raise QuizError(f"Question #{index} is missing required text fields.")

        q_type = q_type.strip().lower()
        if q_type not in {"multiple_choice", "true_false", "short_answer"}:
            raise QuizError(f"Question #{index} has unsupported type: {q_type}")

        options = question.get("options", [])
        if q_type == "multiple_choice":
            if not isinstance(options, list) or len(options) < 2:
                raise QuizError(f"Question #{index} must have at least 2 options.")
            if answer not in options:
                raise QuizError(f"Question #{index} answer must match one of its options.")
        else:
            options = []

        validated.append(
            {
                "question": q_text.strip(),
                "type": q_type,
                "options": options,
                "answer": answer.strip(),
                "category": category.strip() if isinstance(category, str) and category.strip() else "General",
                "hint": hint.strip() if isinstance(hint, str) and hint.strip() else "No hint provided.",
            }
        )

    return validated


def create_quiz_db(question_bank: List[Dict]) -> None:
    with sqlite3.connect(QUIZ_DB) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL,
                options_json TEXT,
                answer TEXT NOT NULL,
                category TEXT NOT NULL,
                hint TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS question_feedback (
                user_id INTEGER NOT NULL,
                question_id INTEGER NOT NULL,
                liked INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (user_id, question_id)
            )
            """
        )

        for q in question_bank:
            conn.execute(
                """
                INSERT INTO questions (question, type, options_json, answer, category, hint)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(question) DO UPDATE SET
                    type = excluded.type,
                    options_json = excluded.options_json,
                    answer = excluded.answer,
                    category = excluded.category,
                    hint = excluded.hint
                """,
                (
                    q["question"],
                    q["type"],
                    json.dumps(q["options"]),
                    q["answer"],
                    q["category"],
                    q["hint"],
                ),
            )
        conn.commit()


def _history_key() -> bytes:
    secret = os.getenv("QUIZ_HISTORY_KEY", "quiz-history-default-key")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _xor_stream(data: bytes, nonce: bytes, key: bytes) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, stream[: len(data)]))


def append_score_history(username: str, score_payload: Dict) -> None:
    key = _history_key()
    nonce = os.urandom(16)
    raw = json.dumps(score_payload, separators=(",", ":")).encode("utf-8")
    encrypted = _xor_stream(raw, nonce, key)

    username_bytes = username.encode("utf-8")
    record = (
        HISTORY_MAGIC
        + len(username_bytes).to_bytes(2, "big")
        + username_bytes
        + nonce
        + len(encrypted).to_bytes(4, "big")
        + encrypted
    )

    with SCORE_HISTORY_FILE.open("ab") as f:
        f.write(record)


def read_user_score_history(username: str) -> List[Dict]:
    if not SCORE_HISTORY_FILE.exists():
        return []

    key = _history_key()
    records: List[Dict] = []
    data = SCORE_HISTORY_FILE.read_bytes()
    cursor = 0

    while cursor + 3 <= len(data):
        if data[cursor : cursor + 3] != HISTORY_MAGIC:
            break
        cursor += 3

        if cursor + 2 > len(data):
            break
        ulen = int.from_bytes(data[cursor : cursor + 2], "big")
        cursor += 2

        if cursor + ulen + 16 + 4 > len(data):
            break

        user = data[cursor : cursor + ulen].decode("utf-8", errors="ignore")
        cursor += ulen

        nonce = data[cursor : cursor + 16]
        cursor += 16

        payload_len = int.from_bytes(data[cursor : cursor + 4], "big")
        cursor += 4

        if cursor + payload_len > len(data):
            break

        encrypted = data[cursor : cursor + payload_len]
        cursor += payload_len

        if user != username:
            continue

        try:
            decrypted = _xor_stream(encrypted, nonce, key)
            payload = json.loads(decrypted.decode("utf-8"))
            records.append(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue

    return records


def create_user(username: str, password: str) -> Tuple[int, str]:
    salt = os.urandom(16)
    pwhash = hash_password(password, salt)

    with sqlite3.connect(USER_DB) as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, salt, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, salt, pwhash, now_iso()),
        )
        user_id = cursor.lastrowid
        conn.commit()

    return int(user_id), username


def verify_login(username: str, password: str) -> Optional[int]:
    with sqlite3.connect(USER_DB) as conn:
        row = conn.execute(
            "SELECT id, salt, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if row is None:
            return None

        user_id, salt, stored_hash = row
        computed_hash = hash_password(password, salt)
        if computed_hash != stored_hash:
            return None

        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (now_iso(), user_id),
        )
        conn.commit()

    return int(user_id)


def prompt_nonempty(prompt_text: str) -> str:
    while True:
        value = input(prompt_text).strip()
        if value:
            return value
        print("Input cannot be empty. Please try again.")


def login_flow() -> Tuple[int, str]:
    print("Welcome to the Quiz App")
    print("1. Login")
    print("2. Register")

    while True:
        choice = input("Choose an option (1/2): ").strip()
        if choice in {"1", "2"}:
            break
        print("Invalid option. Please enter 1 or 2.")

    if choice == "2":
        while True:
            username = prompt_nonempty("Choose a username: ")
            password = prompt_nonempty("Choose a password: ")
            try:
                user_id, uname = create_user(username, password)
                print("Registration successful. You are now logged in.")
                return user_id, uname
            except sqlite3.IntegrityError:
                print("That username already exists. Try another one.")

    attempts_left = 3
    while attempts_left > 0:
        username = prompt_nonempty("Username: ")
        password = prompt_nonempty("Password: ")
        user_id = verify_login(username, password)
        if user_id is not None:
            print("Login successful.")
            return user_id, username

        attempts_left -= 1
        if attempts_left > 0:
            print(f"Invalid login. You have {attempts_left} attempt(s) remaining.")

    raise QuizError("Too many invalid login attempts. Exiting for security.")


def parse_question_count(total_available: int) -> int:
    while True:
        raw = input("How many questions would you like? ").strip()
        try:
            value = int(raw)
        except ValueError:
            print("Please enter a whole number greater than 0.")
            continue

        if value <= 0:
            print("Please enter a whole number greater than 0.")
            continue

        if value > total_available:
            print(f"Only {total_available} questions are available. Please enter a smaller number.")
            continue

        return value


def get_all_questions_with_feedback(user_id: int) -> List[Dict]:
    query = """
        SELECT q.id, q.question, q.type, q.options_json, q.answer, q.category, q.hint,
               COALESCE(f.liked, 0) AS liked
        FROM questions q
        LEFT JOIN question_feedback f
          ON q.id = f.question_id AND f.user_id = ?
    """
    with sqlite3.connect(QUIZ_DB) as conn:
        rows = conn.execute(query, (user_id,)).fetchall()

    questions = []
    for row in rows:
        qid, text, qtype, options_json, answer, category, hint, liked = row
        options = json.loads(options_json) if options_json else []
        questions.append(
            {
                "id": qid,
                "question": text,
                "type": qtype,
                "options": options,
                "answer": answer,
                "category": category,
                "hint": hint,
                "liked": liked,
            }
        )
    return questions


def weighted_random_sample(questions: List[Dict], count: int) -> List[Dict]:
    pool = questions[:]
    selected: List[Dict] = []

    for _ in range(min(count, len(pool))):
        weights = []
        for q in pool:
            liked = q.get("liked", 0)
            if liked > 0:
                weights.append(2.0)
            elif liked < 0:
                weights.append(0.6)
            else:
                weights.append(1.0)

        chosen = random.choices(pool, weights=weights, k=1)[0]
        selected.append(chosen)
        pool = [q for q in pool if q["id"] != chosen["id"]]

    return selected


def generate_quiz_json(user_id: int, count: int) -> None:
    questions = get_all_questions_with_feedback(user_id)
    selected = weighted_random_sample(questions, count)

    payload = {
        "generated_at": now_iso(),
        "count": len(selected),
        "questions": [
            {
                "id": q["id"],
                "question": q["question"],
                "type": q["type"],
                "options": q["options"],
                "answer": q["answer"],
                "category": q["category"],
                "hint": q["hint"],
            }
            for q in selected
        ],
    }

    with GENERATED_QUIZ_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_generated_quiz_with_refetch(user_id: int, count: int) -> Optional[List[Dict]]:
    for attempt in range(2):
        if GENERATED_QUIZ_FILE.exists():
            try:
                with GENERATED_QUIZ_FILE.open("r", encoding="utf-8") as f:
                    payload = json.load(f)
                questions = payload.get("questions", [])
                if isinstance(questions, list) and questions:
                    return questions
            except json.JSONDecodeError:
                pass

        generate_quiz_json(user_id, count)
        if attempt == 0:
            print("Quiz JSON missing or invalid. Refetching quiz questions...")

    print("Quiz JSON could not be recovered. Please try again or restart the application.")
    return None


def prompt_yes_no(prompt_text: str) -> bool:
    while True:
        response = input(prompt_text).strip().lower()
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False
        print("Please answer with yes or no.")


def prompt_multiple_choice(question: Dict) -> str:
    options = question.get("options", [])
    for index, option in enumerate(options, start=1):
        print(f"  {index}. {option}")

    while True:
        raw = input("Answer using option number or exact text: ").strip()
        if raw.isdigit():
            selected_idx = int(raw)
            if 1 <= selected_idx <= len(options):
                return options[selected_idx - 1]
            print("Invalid option number. Please enter a listed number.")
            continue

        if raw in options:
            return raw

        print("Invalid format. Enter a valid option number or exact option text.")


def prompt_true_false() -> str:
    while True:
        raw = input("Answer (true/false): ").strip().lower()
        if raw in {"true", "t"}:
            return "true"
        if raw in {"false", "f"}:
            return "false"
        print("Invalid format. Please answer using true or false.")


def prompt_short_answer() -> str:
    while True:
        raw = input("Answer (short text): ").strip()
        if raw:
            return raw
        print("Invalid format. Please provide a non-empty short answer.")


def save_feedback(user_id: int, question_id: int, liked_value: int) -> None:
    with sqlite3.connect(QUIZ_DB) as conn:
        conn.execute(
            """
            INSERT INTO question_feedback (user_id, question_id, liked, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, question_id) DO UPDATE SET
                liked = excluded.liked,
                updated_at = excluded.updated_at
            """,
            (user_id, question_id, liked_value, now_iso()),
        )
        conn.commit()


def prompt_feedback(user_id: int, question_id: int) -> None:
    while True:
        raw = input("Did you like this question? (like/dislike/skip): ").strip().lower()
        if raw == "like":
            save_feedback(user_id, question_id, 1)
            return
        if raw == "dislike":
            save_feedback(user_id, question_id, -1)
            return
        if raw == "skip":
            return
        print("Invalid feedback. Please type like, dislike, or skip.")


def run_quiz(user_id: int, username: str, questions: List[Dict]) -> None:
    score = 0.0
    hints_used = 0

    print("\nStarting quiz...\n")
    for index, question in enumerate(questions, start=1):
        print(f"Q{index}. {question['question']}")
        print(f"Category: {question.get('category', 'General')}")

        used_hint = False
        if prompt_yes_no("Need a hint? (yes/no): "):
            print(f"Hint: {question.get('hint', 'No hint available.')}")
            used_hint = True
            hints_used += 1

        qtype = question["type"]
        if qtype == "multiple_choice":
            user_answer = prompt_multiple_choice(question)
            correct_answer = question["answer"]
            is_correct = user_answer == correct_answer
        elif qtype == "true_false":
            user_answer = prompt_true_false()
            correct_answer = normalize_text(question["answer"])
            is_correct = normalize_text(user_answer) == correct_answer
        else:
            user_answer = prompt_short_answer()
            correct_answer = normalize_text(question["answer"])
            is_correct = normalize_text(user_answer) == correct_answer

        if is_correct:
            points = 0.75 if used_hint else 1.0
            score += points
            print(f"Correct. +{points:.2f} points")
        else:
            print(f"Incorrect. Correct answer: {question['answer']}")

        prompt_feedback(user_id, int(question["id"]))
        print()

    total = float(len(questions))
    percent = (score / total * 100.0) if total else 0.0
    print(f"Final score: {score:.2f}/{total:.0f} ({percent:.1f}%)")

    with sqlite3.connect(USER_DB) as conn:
        conn.execute(
            """
            INSERT INTO quiz_attempts (user_id, score, total_questions, hints_used, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, score, int(total), hints_used, now_iso()),
        )
        conn.commit()

    history_payload = {
        "timestamp": now_iso(),
        "score": score,
        "total_questions": int(total),
        "percent": round(percent, 2),
        "hints_used": hints_used,
    }
    append_score_history(username, history_payload)

    records = read_user_score_history(username)
    if records:
        avg_percent = sum(float(r.get("percent", 0.0)) for r in records) / len(records)
        best_percent = max(float(r.get("percent", 0.0)) for r in records)
        print(f"History: attempts={len(records)}, avg={avg_percent:.2f}%, best={best_percent:.2f}%")


def setup() -> None:
    question_bank = load_question_bank()
    create_quiz_db(question_bank)
    create_user_db()


def main() -> None:
    try:
        setup()
        user_id, username = login_flow()

        total_available = len(get_all_questions_with_feedback(user_id))
        if total_available == 0:
            raise QuizError("No questions available in quiz database.")

        while True:
            count = parse_question_count(total_available)
            generate_quiz_json(user_id, count)
            questions = load_generated_quiz_with_refetch(user_id, count)
            if not questions:
                continue

            run_quiz(user_id, username, questions)
            if not prompt_yes_no("Would you like to take another quiz? (yes/no): "):
                print("Goodbye.")
                break

    except QuizError as exc:
        print(str(exc))
    except KeyboardInterrupt:
        print("\nApplication interrupted.")


if __name__ == "__main__":
    main()
