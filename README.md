# Password-Manager
A secure CLI password manager written in C. 

## 🧰 Features

- ✅ Add new account credentials (website, username, password)
- 📄 View all saved accounts
- 🔍 Search for an account by website name
- ❌ Delete an account entry
- 💾 Store data persistently in a file
- 🔒 Using Libsodium to hash the passwords and encrypt the file
- 🛠 Menu-driven interface

## 📁 Folder Structure
```
password_manager/
│
├── pmanager.c         # Source code
├── pmanager.h       # header file
├── makefile       # Compile the program
└── README.md      # Project documentation
```


## 🔧 Getting Started

### Prerequisites
- A C compiler (e.g., `gcc`)
- Terminal or command prompt

## 🔐 Cryptography with Libsodium

This project uses [**libsodium**](https://libsodium.gitbook.io/doc/) for secure password hashing and encryption.  
Libsodium is a modern cryptographic library based on NaCl.

### Why Libsodium?
- Easy-to-use and secure-by-default
- Strong password hashing with `crypto_pwhash()`
- Optional encryption with `crypto_secretbox_easy()`

### How to Install

#### On Ubuntu (including WSL):
```bash
sudo apt update
sudo apt install libsodium-dev
```
#### On MacOS (With Homebrew):
```bash
brew install libsodium
```
## Notes
- Initialize libsodium in ``main()``:
  ```
  if (sodium_init() < 0) {
    // panic: libsodium couldn't initialize
  }
  ```

## ✏️ Usage
1. ➕ **Add New Account** – Enter a website, username, and password to store securely.
2. 🗑️ **Delete an Account** – Remove an existing account entry from the password file.
3. ✏️ **Update Account Credentials** – Modify the username or password for a saved account.
4. 📋 **View All Accounts** – Display all saved account entries.
5. 🔍 **Search for an Account** – Find an account by website name.
6. 🚪 **Quit Program** – Closes the application and encrypts the password file.

*The program will decrypt the password file once the correct master password is provided* 

## Example: Adding a New Account
You’ll be asked to enter:
```
Website: github.com
Username: john_doe
Password: myS3cretP@ss
```
The data will be saved in passwords.txt.

## 🌱 Stretch Goals
- Add a master password to access the manager --> Completed
