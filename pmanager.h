#ifndef PMANAGER_H
#define PMANAGER_H

typedef struct{
/**
 * @brief Represents a user account with login credentials.
 * 
 * This structure holds the username, password, and website name
 * for an account entry stored in the password manager.
 */
    char uname[25];    // Username
    char pword[128];  // Password
    char site[64];   // Website name
}Account;


int encrypt_file(const char *in_file,const char *out_file, unsigned char key[crypto_secretbox_KEYBYTES]);
/**
 * @brief Encrypts the contents of a file using libsodium's crypto_secretbox_easy.
 * 
 * Reads the entire plaintext file, encrypts it with the provided symmetric key 
 * and a randomly generated nonce, then writes the nonce followed by the ciphertext 
 * into the output file.
 * 
 * @param in_file Path to the plaintext input file to be encrypted.
 * @param out_file Path where the encrypted output file will be saved.
 * @param key 32-byte symmetric key used for encryption (must be securely generated/stored).
 * 
 * @return int Returns 0 on success, or -1 on failure (e.g., file I/O errors).
 */

int decrypt_file(const char *out_file,const char *in_file, unsigned char key[crypto_secretbox_KEYBYTES]);
/**
 * @brief Decrypts an encrypted file created by encrypt_file().
 * 
 * Reads the encrypted file containing the nonce and ciphertext, verifies and decrypts 
 * the ciphertext using the provided symmetric key and nonce, then writes the 
 * decrypted plaintext to the specified output file.
 * 
 * @param in_file Path to the encrypted input file (nonce + ciphertext).
 * @param out_file Path where the decrypted plaintext file will be saved.
 * @param key 32-byte symmetric key used for decryption (must be the same key used for encryption).
 * 
 * @return int Returns 0 on successful decryption and write, or -1 on failure 
 */

int add_account(const char *file);
/**
 * @brief Adds a new account to the specified password file.
 *
 * Opens the given file in append mode, creating it if it doesn't exist,
 * and writes the account data (username, password, and site) to it.
 *
 * @param a The Account struct containing the user’s credentials.
 * @param file The path to the password file.
 * @return  int Returns 0 on success, or -1 on file I/O failure
 */


int delete_account(const char *target_user,const char *target_site, const char * file);
/**
 * @brief Deletes an account entry from the password file.
 *
 * Searches the file for an account matching the given username and site,
 * and removes it by rewriting the file without that entry.
 *
 * @param target_user The username of the account to delete.
 * @param target_site The website associated with the account.
 * @param file The file to modify.
 * @return int Returns 0 if the account was found and deleted, -1 otherwise.
 */

int update_account(const char *search_user,const char *search_site,const char *file);
/**
 * @brief Updates an existing account in the password file.
 *
 * Finds the matching account based on username and site, and updates its password
 * or other fields as needed.
 * @param search_user The username of the account to update.
 * @param search_site The website associated with the account.
 * @param file The file containing all accounts.
 * @return int Returns 0 if update is successful, -1 if the account is not found.
 */

int view_all_accounts(const char *file);
/**
 * @brief Displays all stored accounts.
 *
 * Reads all entries from the password file and prints them to the console.
 *
 * @param file The name of the password file to read from.
 * @return returns 0 for success, -1 for failure
 */

int search_account(const char *target_user,const char *target_site, const char *file);
/**
 * @brief Searches for a specific account in the password file.
 *
 * Compares entries in the file against the given username and site,
 * and displays the match if found.
 *
 * @param target_user The username to search for.
 * @param target_site The website to match with the username.
 * @param file The file to search in.
 * @return int Returns 0 if a match is found, -1 otherwise.
 */

void menu_display();
  /**
 * @brief Displays the main menu options to the user.
 *
 * Prints a numbered list of available actions (e.g., add, delete, update).
 *
 * @return void
 */

int create_pmaster();
/**
 * @brief Creates the master key for the user if doesn't exist yet
 * 
 * @return int returns 0 if successful, -1 otherwise
 * 
 */

int verify_pmaster(unsigned char key[crypto_secretbox_KEYBYTES]);
/**
 * @brief Verifies the user provided the correct key
 * 
 * @param key the master key the user previously created
 * @return int return 0 if user is sucessful, otherwise -1 with an error message
 */


#endif
