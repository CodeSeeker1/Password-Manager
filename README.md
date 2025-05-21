# Password-Manager
A simple command-line password manager written in C. 

## 🧰 Features

- ✅ Add new account credentials (website, username, password)
- 📄 View all saved accounts
- 🔍 Search for an account by website name
- ❌ Delete an account entry
- 💾 Store data persistently in a file
- 🔒 Optional: Encrypt/decrypt passwords using a simple Caesar cipher
- 🛠 Menu-driven interface

## 📁 File Structure
password_manager/
│
├── main.c # Source code
├── makefile # Compile the program
├── passwords.txt # Data file for saved credentials
└── README.md # Project documentation

## 🔧 Getting Started

### Prerequisites
- A C compiler (e.g., `gcc`)
- Terminal or command prompt

## ✏️ Usage
1. Add New Account
2. View All Accounts
3. Search Account
4. Delete Account
5. Exit

## Example: Adding a New Account
You’ll be asked to enter: Website name, Username or Email, Password
```
Website: github.com
Username: john_doe
Password: myS3cretP@ss
```
The data will be saved in passwords.txt.

## 🌱 Stretch Goals
- Add a master password to access the manager
- Obscure password input using asterisks (*)
- Accept command-line arguments for automation
