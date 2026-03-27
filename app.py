import hashlib
import hmac
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
SCORE_HISTORY_KEY_FILE = Path("score_history.key")

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

    try:
        with QUESTION_BANK_FILE.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except json.JSONDecodeError as exc:
        raise QuizError("Question bank JSON is malformed.") from exc
    except OSError as exc:
        raise QuizError("Question bank file could not be read.") from exc

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
        conn.execute("PRAGMA foreign_keys = ON")
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
                PRIMARY KEY (user_id, question_id),
                FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
                CHECK (liked IN (-1, 1))
            )
            """
        )

        schema_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'question_feedback'"
        ).fetchone()
        schema_sql = schema_row[0] if schema_row else ""
        if "FOREIGN KEY (question_id)" not in schema_sql or "CHECK (liked IN (-1, 1))" not in schema_sql:
            conn.execute("ALTER TABLE question_feedback RENAME TO question_feedback_old")
            conn.execute(
                """
                CREATE TABLE question_feedback (
                    user_id INTEGER NOT NULL,
                    question_id INTEGER NOT NULL,
                    liked INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, question_id),
                    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
                    CHECK (liked IN (-1, 1))
                )
                """
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO question_feedback (user_id, question_id, liked, updated_at)
                SELECT qf.user_id, qf.question_id,
                       CASE WHEN qf.liked > 0 THEN 1 ELSE -1 END,
                       qf.updated_at
                FROM question_feedback_old qf
                JOIN questions q ON q.id = qf.question_id
                WHERE qf.liked <> 0
                """
            )
            conn.execute("DROP TABLE question_feedback_old")

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
    secret = os.getenv("QUIZ_HISTORY_KEY")
    if secret:
        return hashlib.sha256(secret.encode("utf-8")).digest()

    if SCORE_HISTORY_KEY_FILE.exists():
        key = SCORE_HISTORY_KEY_FILE.read_bytes()
        if len(key) == 32:
            return key

    key = os.urandom(32)
    with SCORE_HISTORY_KEY_FILE.open("wb") as f:
        f.write(key)

    try:
        os.chmod(SCORE_HISTORY_KEY_FILE, 0o600)
    except OSError:
        pass

    return key


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
    tag = hmac.new(key, nonce + encrypted, hashlib.sha256).digest()

    username_bytes = username.encode("utf-8")
    record = (
        HISTORY_MAGIC
        + len(username_bytes).to_bytes(2, "big")
        + username_bytes
        + nonce
        + len(encrypted).to_bytes(4, "big")
        + encrypted
        + tag
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

        # Backward compatibility: support both legacy records (no HMAC tag)
        # and newer authenticated records (32-byte HMAC tag).
        has_tag = False
        tag = b""
        if cursor + 32 <= len(data):
            candidate_tag = data[cursor : cursor + 32]
            expected_tag = hmac.new(key, nonce + encrypted, hashlib.sha256).digest()
            if hmac.compare_digest(candidate_tag, expected_tag):
                has_tag = True
                tag = candidate_tag
                cursor += 32
            elif cursor + 32 == len(data) or data[cursor + 32 : cursor + 35] == HISTORY_MAGIC:
                # Looks like a tagged record but tag/key mismatch; consume tag
                # so parsing can continue with later records.
                has_tag = True
                tag = candidate_tag
                cursor += 32

        if user != username:
            continue

        try:
            if has_tag:
                expected_tag = hmac.new(key, nonce + encrypted, hashlib.sha256).digest()
                if not hmac.compare_digest(tag, expected_tag):
                    continue

            decrypted = _xor_stream(encrypted, nonce, key)
            payload = json.loads(decrypted.decode("utf-8"))
            if not isinstance(payload, dict):
                continue
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
        if not hmac.compare_digest(computed_hash, stored_hash):
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


def get_total_question_count() -> int:
    with sqlite3.connect(QUIZ_DB) as conn:
        row = conn.execute("SELECT COUNT(*) FROM questions").fetchone()
    return int(row[0]) if row else 0


def get_answer_map(question_ids: List[int]) -> Dict[int, str]:
    if not question_ids:
        return {}

    placeholders = ",".join("?" for _ in question_ids)
    query = f"SELECT id, answer FROM questions WHERE id IN ({placeholders})"
    with sqlite3.connect(QUIZ_DB) as conn:
        rows = conn.execute(query, tuple(question_ids)).fetchall()
    return {int(row[0]): str(row[1]) for row in rows}


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


def prompt_logged_in_action() -> str:
    print("\nWhat would you like to do?")
    print("1. Take a quiz")
    print("2. View score history")
    print("3. View liked/disliked questions")
    print("4. Logout")

    while True:
        choice = input("Choose an option (1/2/3/4): ").strip()
        if choice in {"1", "2", "3", "4"}:
            return choice
        print("Invalid option. Please enter 1, 2, 3, or 4.")


def show_user_history(username: str) -> None:
    records = read_user_score_history(username)
    if not records:
        print("No score history found yet.")
        return

    print("\nScore history:")
    for idx, record in enumerate(records, start=1):
        timestamp = str(record.get("timestamp", "unknown"))
        try:
            score = float(record.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        try:
            total = int(record.get("total_questions", 0))
        except (TypeError, ValueError):
            total = 0
        try:
            percent = float(record.get("percent", 0.0))
        except (TypeError, ValueError):
            percent = 0.0
        try:
            hints_used = int(record.get("hints_used", 0))
        except (TypeError, ValueError):
            hints_used = 0
        print(
            f"{idx}. {timestamp} | score={score:.2f}/{total} | "
            f"percent={percent:.2f}% | hints_used={hints_used}"
        )

    avg_percent = sum(float(r.get("percent", 0.0)) for r in records) / len(records)
    best_percent = max(float(r.get("percent", 0.0)) for r in records)
    print(f"Summary: attempts={len(records)}, avg={avg_percent:.2f}%, best={best_percent:.2f}%")


def show_liked_questions(user_id: int) -> None:
    query = """
        SELECT q.question, q.category, f.liked
        FROM question_feedback f
        JOIN questions q ON q.id = f.question_id
        WHERE f.user_id = ? AND f.liked IN (-1, 1)
        ORDER BY f.updated_at DESC
    """
    with sqlite3.connect(QUIZ_DB) as conn:
        rows = conn.execute(query, (user_id,)).fetchall()

    if not rows:
        print("No liked/disliked questions found yet.")
        return

    print("\nLiked/disliked questions:")
    for idx, (question, category, liked) in enumerate(rows, start=1):
        sentiment = "LIKE" if int(liked) > 0 else "DISLIKE"
        print(f"{idx}. [{sentiment}] [{category}] {question}")


def show_disliked_questions(user_id: int) -> None:
    query = """
        SELECT q.question, q.category
        FROM question_feedback f
        JOIN questions q ON q.id = f.question_id
        WHERE f.user_id = ? AND f.liked = -1
        ORDER BY f.updated_at DESC
    """
    with sqlite3.connect(QUIZ_DB) as conn:
        rows = conn.execute(query, (user_id,)).fetchall()

    if not rows:
        print("\nNo disliked questions found yet.")
        return

    print("\nDisliked questions:")
    for idx, (question, category) in enumerate(rows, start=1):
        print(f"{idx}. [{category}] {question}")


def prompt_return_to_interface() -> None:
    input("\nPress Enter to return to the interface...")


def prompt_multiple_choice(question: Dict) -> str:
    options = question.get("options", [])
    for index, option in enumerate(options, start=1):
        print(f"  {index}. {option}")

    normalized_options = {normalize_text(opt): opt for opt in options if isinstance(opt, str)}

    while True:
        raw = input("Answer using option number or exact text (type hint for hint): ").strip()
        if normalize_text(raw) == "hint":
            return "__HINT__"
        if raw.isdigit():
            selected_idx = int(raw)
            if 1 <= selected_idx <= len(options):
                return options[selected_idx - 1]
            print("Invalid option number. Please enter a listed number.")
            continue

        if raw in options:
            return raw

        normalized = normalize_text(raw)
        if normalized in normalized_options:
            return normalized_options[normalized]

        print("Invalid format. Enter a valid option number or exact option text.")


def prompt_true_false() -> str:
    while True:
        raw = input("Answer (true/false, or type hint for hint): ").strip().lower()
        if normalize_text(raw) == "hint":
            return "__HINT__"
        if raw in {"true", "t"}:
            return "true"
        if raw in {"false", "f"}:
            return "false"
        print("Invalid format. Please answer using true or false.")


def prompt_short_answer() -> str:
    while True:
        raw = input("Answer (short text, or type hint for hint): ").strip()
        if normalize_text(raw) == "hint":
            return "__HINT__"
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
    answer_map = get_answer_map([int(question["id"]) for question in questions])

    print("\nStarting quiz...\n")
    for index, question in enumerate(questions, start=1):
        print(f"Q{index}. {question['question']}")
        print(f"Category: {question.get('category', 'General')}")

        used_hint = False

        qtype = question["type"]
        question_id = int(question["id"])
        correct_answer = answer_map.get(question_id, "")

        while True:
            if qtype == "multiple_choice":
                user_answer = prompt_multiple_choice(question)
            elif qtype == "true_false":
                print("Choices: true, false")
                user_answer = prompt_true_false()
            else:
                user_answer = prompt_short_answer()

            if user_answer == "__HINT__":
                if used_hint:
                    print("Hint already shown for this question. Please submit your answer.")
                else:
                    print(f"Hint: {question.get('hint', 'No hint available.')}")
                    used_hint = True
                    hints_used += 1
                continue
            break

        if qtype == "multiple_choice":
            is_correct = normalize_text(user_answer) == normalize_text(correct_answer)
        elif qtype == "true_false":
            is_correct = normalize_text(user_answer) == normalize_text(correct_answer)
        else:
            is_correct = normalize_text(user_answer) == normalize_text(correct_answer)

        if is_correct:
            points = 0.75 if used_hint else 1.0
            score += points
            print(f"Correct. +{points:.2f} points")
        else:
            print(f"Incorrect. Correct answer: {correct_answer}")

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
        total_available = get_total_question_count()
        if total_available == 0:
            raise QuizError("No questions available in quiz database.")

        user_id, username = login_flow()

        while True:
            action = prompt_logged_in_action()
            if action == "2":
                show_user_history(username)
                prompt_return_to_interface()
                continue
            if action == "3":
                show_liked_questions(user_id)
                prompt_return_to_interface()
                continue
            if action == "4":
                print("Goodbye.")
                break

            count = parse_question_count(total_available)
            generate_quiz_json(user_id, count)
            questions = load_generated_quiz_with_refetch(user_id, count)
            if not questions:
                continue

            run_quiz(user_id, username, questions)

    except QuizError as exc:
        print(str(exc))
    except (sqlite3.Error, OSError) as exc:
        print(f"A system error occurred: {exc}")
    except KeyboardInterrupt:
        print("\nApplication interrupted.")


if __name__ == "__main__":
    main()
