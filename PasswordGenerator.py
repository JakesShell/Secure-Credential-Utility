import secrets
import string


def build_character_pool(use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    pool = ""

    if use_uppercase:
        pool += string.ascii_uppercase
    if use_lowercase:
        pool += string.ascii_lowercase
    if use_digits:
        pool += string.digits
    if use_special:
        pool += "!@#$%^&*()-_=+[]{};:,.?/"

    return pool


def generate_password(length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    pool = build_character_pool(use_uppercase, use_lowercase, use_digits, use_special)

    if not pool:
        raise ValueError("At least one character group must be enabled.")

    if length < 8:
        raise ValueError("Password length must be at least 8.")

    required_chars = []

    if use_uppercase:
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if use_lowercase:
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        required_chars.append(secrets.choice(string.digits))
    if use_special:
        required_chars.append(secrets.choice("!@#$%^&*()-_=+[]{};:,.?/"))

    if length < len(required_chars):
        raise ValueError("Password length is too short for the selected policy requirements.")

    remaining_length = length - len(required_chars)
    password_chars = required_chars + [secrets.choice(pool) for _ in range(remaining_length)]

    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def evaluate_password(password):
    checks = {
        "Length >= 12": len(password) >= 12,
        "Has Uppercase": any(char.isupper() for char in password),
        "Has Lowercase": any(char.islower() for char in password),
        "Has Digit": any(char.isdigit() for char in password),
        "Has Special Character": any(char in "!@#$%^&*()-_=+[]{};:,.?/" for char in password)
    }

    score = sum(checks.values())

    if score == 5:
        rating = "Strong"
    elif score >= 3:
        rating = "Moderate"
    else:
        rating = "Weak"

    return rating, checks


def prompt_yes_no(message, default=True):
    suffix = "[Y/n]" if default else "[y/N]"

    while True:
        value = input(f"{message} {suffix}: ").strip().lower()

        if value == "":
            return default
        if value in ["y", "yes"]:
            return True
        if value in ["n", "no"]:
            return False

        print("Please enter yes or no.")


def generate_workflow():
    try:
        length = int(input("Enter desired password length (minimum 8): ").strip())
    except ValueError:
        print("Invalid length. Please enter a number.")
        return

    use_uppercase = prompt_yes_no("Include uppercase letters?", True)
    use_lowercase = prompt_yes_no("Include lowercase letters?", True)
    use_digits = prompt_yes_no("Include digits?", True)
    use_special = prompt_yes_no("Include special characters?", True)

    try:
        password = generate_password(length, use_uppercase, use_lowercase, use_digits, use_special)
    except ValueError as error:
        print(f"Error: {error}")
        return

    rating, checks = evaluate_password(password)

    print()
    print("Generated Credential")
    print("--------------------")
    print(password)
    print()
    print("Policy Review")
    print("-------------")
    print(f"Strength Rating: {rating}")

    for check, passed in checks.items():
        print(f"{check}: {'Pass' if passed else 'Fail'}")


def validate_workflow():
    password = input("Enter a password to evaluate: ").strip()

    if not password:
        print("No password entered.")
        return

    rating, checks = evaluate_password(password)

    print()
    print("Validation Result")
    print("-----------------")
    print(f"Strength Rating: {rating}")

    for check, passed in checks.items():
        print(f"{check}: {'Pass' if passed else 'Fail'}")


def show_policy_guidance():
    print()
    print("Recommended Internal Credential Guidance")
    print("---------------------------------------")
    print("1. Use at least 12 characters for standard user passwords.")
    print("2. Use at least 16 characters for admin or privileged credentials.")
    print("3. Include uppercase, lowercase, digits, and special characters.")
    print("4. Do not reuse credentials across systems.")
    print("5. Use a password manager for secure storage and rotation.")


def main():
    while True:
        print()
        print("Secure Credential Utility")
        print("-------------------------")
        print("1. Generate Credential")
        print("2. Validate Existing Password")
        print("3. View Policy Guidance")
        print("4. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            generate_workflow()
        elif choice == "2":
            validate_workflow()
        elif choice == "3":
            show_policy_guidance()
        elif choice == "4":
            print("Exiting Secure Credential Utility.")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
