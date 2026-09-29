"""Login Form with Validation (Python + SQL)

A simple console program where a user can register and log in.
- Input is validated (empty, wrong length, wrong characters).
- User data is stored in an SQLite database (users.db).
- SQL queries use placeholders (?) to block malicious input (SQL injection).
- Passwords are stored as hashes, not as plain text.
"""

import hashlib
import re
import sqlite3

DB_NAME = "users.db"


def connect_db():
    """Open the database and create the users table if it does not exist."""
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY, "
        "password_hash TEXT NOT NULL)"
    )
    return conn


def hash_password(password):
    """Convert the password into a hash so the real password is never saved."""
    return hashlib.sha256(password.encode()).hexdigest()


def validate_username(username):
    """Username: 4 to 15 characters, only letters, numbers and underscore."""
    if not username:
        return "Username cannot be empty."
    if not re.fullmatch(r"[A-Za-z0-9_]{4,15}", username):
        return "Username must be 4-15 characters (letters, numbers, underscore only)."
    return None


def validate_password(password):
    """Password: at least 6 characters, with at least one letter and one number."""
    if not password:
        return "Password cannot be empty."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        return "Password must contain at least one letter and one number."
    return None


def register(conn):
    username = input("Choose a username: ").strip()
    error = validate_username(username)
    if error:
        print(error)
        return

    password = input("Choose a password: ")
    error = validate_password(password)
    if error:
        print(error)
        return

    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        conn.commit()
        print("Registration successful. You can now log in.")
    except sqlite3.IntegrityError:
        print("This username is already taken.")


def login(conn):
    username = input("Username: ").strip()
    password = input("Password: ")

    if not username or not password:
        print("Username and password cannot be empty.")
        return

    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    if row and row[0] == hash_password(password):
        print(f"Login successful. Welcome, {username}!")
    else:
        print("Invalid username or password.")


def main():
    conn = connect_db()
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Enter your choice (1-3): ").strip()
        if choice == "1":
            register(conn)
        elif choice == "2":
            login(conn)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Please enter 1, 2 or 3.")
    conn.close()


if __name__ == "__main__":
    main()
