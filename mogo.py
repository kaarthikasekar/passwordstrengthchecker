from flask import Flask, request, render_template_string
import pymongo
import re
import math
from datetime import datetime, timedelta

app = Flask(__name__)

# MongoDB connection
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client["passwordDB"]
users_collection = db["users"]

# Common passwords and words for the check
common_passwords = [
    "123456", "password", "12345678", "qwerty", "12345", "123456789", "letmein",
    "1234567", "football", "admin", "welcome", "monkey", "abcd", "xyz", "abc123"
]

common_words = [
    "password", "welcome", "admin", "letmein", "football", "monkey"
]

custom_prohibited_words = [
    "companyname", "projectname"
]

def calculate_entropy(password):
    pool = 0
    if re.search("[a-z]", password):
        pool += 26
    if re.search("[A-Z]", password):
        pool += 26
    if re.search("[0-9]", password):
        pool += 10
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        pool += 32

    if pool == 0:
        return 0
    entropy = len(password) * math.log2(pool)
    return entropy

def estimate_time_to_crack(password):
    entropy = calculate_entropy(password)
    attempts_per_second = 10**10
    time_to_crack_seconds = 2**entropy / attempts_per_second
    return time_to_crack_seconds

def check_password_strength(password, username=None, old_passwords=None, last_changed=None):
    suggestions = []
    strength = 0
    
    # Check length
    if len(password) >= 8:
        strength += 1
    else:
        suggestions.append("Password should be at least 8 characters long.\n")
    
    # Check for uppercase and lowercase
    if re.search("[a-z]", password) and re.search("[A-Z]", password):
        strength += 1
    else:
        suggestions.append("Password should contain both uppercase and lowercase characters.\n")
    
    # Check for digits
    if re.search("[0-9]", password):
        strength += 1
    else:
        suggestions.append("Password should contain at least one digit.\n")
    
    # Check for special characters
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    else:
        suggestions.append("Password should contain at least one special character.\n")
    
    # Check for common patterns
    if password in common_passwords:
        suggestions.append("Password is too common.\n")
    if re.search(r"(.)\1\1", password):
        suggestions.append("Password should not have repeated characters or sequences.\n")
    if re.search(r"123456|abcdef|password|qwerty", password):
        suggestions.append("Password contains common patterns.\n")
    
    # Check against dictionary words
    if any(word in password.lower() for word in common_words):
        suggestions.append("Password contains common dictionary words.\n")
    
    # Check for username inclusion
    if username and username.lower() in password.lower():
        suggestions.append("Password should not contain the username.\n")
    
    # Check against old passwords
    if old_passwords and password in old_passwords:
        suggestions.append("Password should not be similar to previous passwords.\n")
    
    # Check against custom prohibited words
    if any(word in password.lower() for word in custom_prohibited_words):
        suggestions.append("Password contains prohibited words.\n")
    
    # Entropy check
    entropy = calculate_entropy(password)
    if entropy < 50:
        suggestions.append(f"Password entropy is too low ({entropy:.2f} bits). Consider making it more complex.\n")
    
    # Time-to-crack estimate
    time_to_crack = estimate_time_to_crack(password)
    if time_to_crack < 60:
        suggestions.append(f"Password can be cracked in {time_to_crack:.2f} seconds.\n")
    elif time_to_crack < 3600:
        suggestions.append(f"Password can be cracked in {time_to_crack/60:.2f} minutes.\n")
    elif time_to_crack < 86400:
        suggestions.append(f"Password can be cracked in {time_to_crack/3600:.2f} hours.\n")
    else:
        suggestions.append(f"Password can be cracked in {time_to_crack/86400:.2f} days.\n")
    
    # Password aging
    if last_changed:
        days_since_changed = (datetime.now() - last_changed).days
        if days_since_changed > 90:
            suggestions.append("Password should be changed every 90 days. Consider changing it now.\n")
    
    if strength == 4 and not suggestions:
        return "Password is strong."
    else:
        return "Password is weak.\nSuggestions:\n" + "".join(suggestions)

@app.route('/')
def index():
    return render_template_string(open('index.html').read())

@app.route('/check_password', methods=['POST'])
def check_password():
    username = request.form['username']
    password = request.form['password']
    
    # Retrieve old passwords and last changed date from MongoDB
    user = users_collection.find_one({"username": username})
    
    if user:
        old_passwords = user.get("old_passwords", [])
        last_changed = user.get("last_changed", datetime.now() - timedelta(days=100))
    else:
        old_passwords = []
        last_changed = datetime.now() - timedelta(days=100)

    result = check_password_strength(password, username, old_passwords, last_changed)
    
    # Update MongoDB with the new password if it is strong
    if "Password is strong" in result:
        users_collection.update_one(
            {"username": username},
            {"$set": {"password": password, "last_changed": datetime.now()},
             "$push": {"old_passwords": password}},
            upsert=True
        )
    
    return result

if __name__ == "__main__":
    app.run(debug=True)
