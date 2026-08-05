"""
Guardion AI — Synthetic Dataset Generator
==========================================
Generates ~500 labeled prompt examples across five security categories:
  - safe            : Benign coding / general questions
  - pii_leak        : Personal identifiable information (emails, phones, SSNs)
  - credential_leak : API keys, passwords, tokens, connection strings
  - financial_data  : Credit cards, bank accounts, routing numbers
  - secret_code     : Private keys, PEM files, SSH keys, encryption secrets

Each category has hand-written templates with randomized placeholders so the
model sees diverse phrasing.  Output: data/training_data.csv
"""

import csv
import os
import random
import string

# ──────────────────── Reproducibility ────────────────────
random.seed(42)

# ──────────────────── Helper Generators ────────────────────

def _rand_str(length: int, chars: str = string.ascii_letters + string.digits) -> str:
    """Generate a random alphanumeric string."""
    return "".join(random.choices(chars, k=length))


def _rand_email() -> str:
    names = ["john", "jane", "alice", "bob", "mike", "sarah", "kumar", "priya",
             "alex", "chris", "daniel", "emma", "frank", "grace", "henry", "ivy"]
    domains = ["gmail.com", "yahoo.com", "outlook.com", "company.com",
               "proton.me", "hotmail.com", "example.org", "work.io"]
    return f"{random.choice(names)}{random.randint(1, 999)}@{random.choice(domains)}"


def _rand_phone() -> str:
    return f"+1-{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}"


def _rand_ssn() -> str:
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"


def _rand_cc() -> str:
    """Generate a fake credit card number (Visa-like)."""
    return f"4{random.randint(100,999)} {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"


def _rand_aws_key() -> str:
    return f"AKIA{_rand_str(16, string.ascii_uppercase + string.digits)}"


def _rand_api_key() -> str:
    return f"sk-{_rand_str(32)}"


def _rand_password() -> str:
    passwords = ["admin123", "P@ssw0rd!", "hunter2", "letmein", "qwerty123",
                 "Welcome1!", "Sup3rS3cr3t", "pass1234", "MyP@ss99", "root1234"]
    return random.choice(passwords)


def _rand_bearer() -> str:
    return f"Bearer {_rand_str(40)}"


def _rand_jwt() -> str:
    header = _rand_str(20, string.ascii_letters + string.digits + "-_")
    payload = _rand_str(40, string.ascii_letters + string.digits + "-_")
    sig = _rand_str(30, string.ascii_letters + string.digits + "-_")
    return f"eyJ{header}.eyJ{payload}.{sig}"


def _rand_github_token() -> str:
    return f"ghp_{_rand_str(36)}"


def _rand_bank_account() -> str:
    return f"{random.randint(10000000, 99999999)}"


def _rand_routing() -> str:
    return f"{random.randint(100000000, 999999999)}"


def _rand_db_url() -> str:
    engines = ["postgres", "mysql", "mongodb+srv"]
    users = ["admin", "root", "dbuser", "app"]
    return f"{random.choice(engines)}://{random.choice(users)}:{_rand_str(12)}@db.example.com:5432/mydb"


# ──────────────────── Template Pools ────────────────────

SAFE_TEMPLATES = [
    "Explain {concept} in {language}",
    "Write a {algo} algorithm in {language}",
    "What is the difference between {concept} and {concept2}?",
    "How do I implement {pattern} pattern in {language}?",
    "Can you help me debug this {language} code?",
    "Show me an example of {concept} in {language}",
    "What are best practices for {topic}?",
    "How does {concept} work internally?",
    "Write unit tests for a {algo} function",
    "Explain the time complexity of {algo}",
    "Create a REST API endpoint for {topic}",
    "How to set up CI/CD for a {language} project?",
    "What is the purpose of {concept} in {language}?",
    "Translate this pseudocode to {language}",
    "Optimize this {language} function for performance",
    "How to use Docker with {language}?",
    "Explain {concept} to a beginner",
    "What are the SOLID principles?",
    "How to handle errors in {language}?",
    "Write a {language} function to validate input",
    "Summarize the key features of {language}",
    "What is dependency injection?",
    "Write a {language} script to read a CSV file",
    "How does garbage collection work in {language}?",
    "Explain microservices architecture",
    "What is the observer pattern?",
    "How to implement pagination in a REST API?",
    "Explain async/await in {language}",
    "What is the factory design pattern?",
    "How to write clean code?",
]

SAFE_CONCEPTS = ["recursion", "polymorphism", "inheritance", "closures", "decorators",
                 "generators", "async programming", "multithreading", "hashing", "caching",
                 "memoization", "linked lists", "binary trees", "graphs", "dynamic programming"]
SAFE_CONCEPTS2 = ["stacks and queues", "arrays and lists", "TCP and UDP", "SQL and NoSQL",
                  "threads and processes", "REST and GraphQL", "monolith and microservices",
                  "OOP and functional", "compile time and runtime", "deep copy and shallow copy"]
SAFE_LANGUAGES = ["Python", "JavaScript", "Java", "C++", "Go", "Rust", "TypeScript", "C#", "Ruby", "Kotlin"]
SAFE_ALGOS = ["bubble sort", "merge sort", "quick sort", "binary search", "BFS", "DFS",
              "Dijkstra's", "A*", "KMP", "Kruskal's"]
SAFE_PATTERNS = ["singleton", "observer", "factory", "strategy", "adapter", "decorator", "builder"]
SAFE_TOPICS = ["logging", "testing", "authentication", "authorization", "rate limiting",
               "database indexing", "caching", "monitoring", "deployment", "security"]


PII_TEMPLATES = [
    "My email address is {email}",
    "Contact me at {email}",
    "Send the report to {email}",
    "My phone number is {phone}",
    "You can reach me at {phone}",
    "Call me on {phone}",
    "My SSN is {ssn}",
    "Social security number: {ssn}",
    "My date of birth is {dob} and my name is {name}",
    "I live at {address}",
    "My home address is {address}",
    "Here is my personal info: name {name}, email {email}, phone {phone}",
    "Please use this email for login: {email}",
    "My full name is {name} and my phone is {phone}",
    "Ship to: {name}, {address}",
    "My passport number is {passport}",
    "National ID: {ssn}",
    "Contact info: {email}, {phone}",
    "Personal details: {name}, DOB {dob}, SSN {ssn}",
    "Reach me via email at {email} or call {phone}",
]

PII_NAMES = ["John Smith", "Jane Doe", "Alice Johnson", "Bob Williams", "Priya Kumar",
             "Carlos Rodriguez", "Emma Wilson", "Michael Brown", "Sarah Davis", "David Lee"]
PII_ADDRESSES = ["123 Main St, Springfield IL 62701", "456 Oak Ave, Portland OR 97201",
                 "789 Pine Rd, Austin TX 78701", "321 Elm Blvd, Denver CO 80201",
                 "654 Maple Dr, Seattle WA 98101"]
PII_DOBS = ["01/15/1990", "03/22/1985", "07/08/1992", "11/30/1988", "05/14/1995"]
PII_PASSPORTS = [f"{_rand_str(1, string.ascii_uppercase)}{random.randint(10000000, 99999999)}" for _ in range(10)]


CREDENTIAL_TEMPLATES = [
    "My API key is {api_key}",
    "Use this API key: {api_key}",
    "api_key = \"{api_key}\"",
    "API_KEY={api_key}",
    "My AWS access key is {aws_key}",
    "aws_access_key_id = {aws_key}",
    "AWS_ACCESS_KEY={aws_key}",
    "Here are my AWS credentials: {aws_key}",
    "My password is {password}",
    "password = \"{password}\"",
    "PASSWORD={password}",
    "Login with password: {password}",
    "Set the password to {password}",
    "The token is {bearer}",
    "Authorization: {bearer}",
    "auth_token = \"{bearer}\"",
    "Use this JWT: {jwt}",
    "jwt_token = \"{jwt}\"",
    "My GitHub token is {github_token}",
    "GITHUB_TOKEN={github_token}",
    "ghp token: {github_token}",
    "Connect using {db_url}",
    "DATABASE_URL={db_url}",
    "database_url = \"{db_url}\"",
    "The connection string is {db_url}",
    "client_secret = \"{api_key}\"",
    "OPENAI_API_KEY={api_key}",
    "Here is my secret key: {api_key}",
    "encryption_key = \"{api_key}\"",
    "ACCESS_TOKEN={bearer}",
]


FINANCIAL_TEMPLATES = [
    "My credit card number is {cc}",
    "Card: {cc}",
    "Pay with card {cc}",
    "Credit card: {cc}, expiry 12/25",
    "My bank account number is {bank_account}",
    "Account: {bank_account}, routing: {routing}",
    "Wire transfer to account {bank_account}",
    "Bank details: account {bank_account}, routing {routing}",
    "My Visa card is {cc}",
    "Debit card number: {cc}",
    "Send money to account {bank_account}",
    "Billing info: card {cc}, CVV 123",
    "Payment method: {cc}, exp 06/27",
    "ACH routing number is {routing}",
    "My bank routing number: {routing}",
    "IBAN: GB29 NWBK {bank_account}",
    "Transfer ${amount} to account {bank_account}",
    "Please charge {cc} for the subscription",
    "My PayPal is linked to {cc}",
    "Financial details: card {cc}, bank {bank_account}",
]


SECRET_CODE_TEMPLATES = [
    "Here is my private_key.pem file content",
    "-----BEGIN RSA PRIVATE KEY-----\n{key_block}\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----\n{key_block}\n-----END EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----\n{key_block}\n-----END OPENSSH PRIVATE KEY-----",
    "My SSH private key is:\n-----BEGIN RSA PRIVATE KEY-----\n{key_block}",
    "Here is the PEM file:\n-----BEGIN PRIVATE KEY-----\n{key_block}",
    "Encryption secret: {secret}",
    "ENCRYPTION_KEY={secret}",
    "private_key = \"{secret}\"",
    "signing_secret = \"{secret}\"",
    "Here is the .env file:\nSECRET_KEY={secret}\nAPI_KEY={api_key}",
    "My GPG private key starts with -----BEGIN PGP PRIVATE KEY BLOCK-----",
    "ssh-rsa {key_block} user@host",
    "The server's private key:\n{key_block}",
    "Upload this key file: id_rsa containing {key_block}",
    "HMAC secret: {secret}",
    "Signing key: {secret}",
    "Here's the SSL cert private key:\n-----BEGIN RSA PRIVATE KEY-----",
    "TLS private key content: {key_block}",
    "Code signing key = {secret}",
]


# ──────────────────── Dataset Generator ────────────────────

def generate_safe_examples(count: int = 120) -> list[dict]:
    """Generate safe / benign coding prompts."""
    examples = []
    for _ in range(count):
        template = random.choice(SAFE_TEMPLATES)
        prompt = template.format(
            concept=random.choice(SAFE_CONCEPTS),
            concept2=random.choice(SAFE_CONCEPTS2),
            language=random.choice(SAFE_LANGUAGES),
            algo=random.choice(SAFE_ALGOS),
            pattern=random.choice(SAFE_PATTERNS),
            topic=random.choice(SAFE_TOPICS),
        )
        examples.append({"prompt": prompt, "label": "safe"})
    return examples


def generate_pii_examples(count: int = 100) -> list[dict]:
    """Generate prompts leaking personal identifiable information."""
    examples = []
    for _ in range(count):
        template = random.choice(PII_TEMPLATES)
        prompt = template.format(
            email=_rand_email(),
            phone=_rand_phone(),
            ssn=_rand_ssn(),
            name=random.choice(PII_NAMES),
            address=random.choice(PII_ADDRESSES),
            dob=random.choice(PII_DOBS),
            passport=random.choice(PII_PASSPORTS),
        )
        examples.append({"prompt": prompt, "label": "pii_leak"})
    return examples


def generate_credential_examples(count: int = 100) -> list[dict]:
    """Generate prompts containing credential leaks."""
    examples = []
    for _ in range(count):
        template = random.choice(CREDENTIAL_TEMPLATES)
        prompt = template.format(
            api_key=_rand_api_key(),
            aws_key=_rand_aws_key(),
            password=_rand_password(),
            bearer=_rand_bearer(),
            jwt=_rand_jwt(),
            github_token=_rand_github_token(),
            db_url=_rand_db_url(),
        )
        examples.append({"prompt": prompt, "label": "credential_leak"})
    return examples


def generate_financial_examples(count: int = 90) -> list[dict]:
    """Generate prompts containing financial information."""
    examples = []
    for _ in range(count):
        template = random.choice(FINANCIAL_TEMPLATES)
        prompt = template.format(
            cc=_rand_cc(),
            bank_account=_rand_bank_account(),
            routing=_rand_routing(),
            amount=random.randint(10, 50000),
        )
        examples.append({"prompt": prompt, "label": "financial_data"})
    return examples


def generate_secret_code_examples(count: int = 90) -> list[dict]:
    """Generate prompts containing secret keys / code."""
    examples = []
    for _ in range(count):
        template = random.choice(SECRET_CODE_TEMPLATES)
        prompt = template.format(
            key_block=_rand_str(64),
            secret=_rand_str(32),
            api_key=_rand_api_key(),
        )
        examples.append({"prompt": prompt, "label": "secret_code"})
    return examples


def generate_dataset(output_path: str = None) -> str:
    """
    Generate the full synthetic training dataset and save to CSV.
    
    Returns:
        Path to the generated CSV file.
    """
    # Default output path
    if output_path is None:
        output_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "training_data.csv")

    # Generate examples for each category
    all_examples = []
    all_examples.extend(generate_safe_examples(120))
    all_examples.extend(generate_pii_examples(100))
    all_examples.extend(generate_credential_examples(100))
    all_examples.extend(generate_financial_examples(90))
    all_examples.extend(generate_secret_code_examples(90))

    # Shuffle for good measure
    random.shuffle(all_examples)

    # Write CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["prompt", "label"])
        writer.writeheader()
        writer.writerows(all_examples)

    # Print summary
    from collections import Counter
    label_counts = Counter(ex["label"] for ex in all_examples)
    print(f"\n✅ Dataset generated: {output_path}")
    print(f"   Total examples: {len(all_examples)}")
    for label, count in sorted(label_counts.items()):
        print(f"   {label}: {count}")

    return output_path


# ──────────────────── CLI Entry Point ────────────────────

if __name__ == "__main__":
    generate_dataset()