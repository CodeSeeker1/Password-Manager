/**
 * @file pmanager.c
 * @author Ayub Haji 
 * @version 0.1
 * @date 2025-05-21
 * @copyright Copyright (c) 2025
 * @brief Password Manager that allows users to add,delete,view and search accounts. 
 *        The information is stored securing through layers of security:
 *          - Hashing the password field of the account with a salt 
 *          - Encrypting the credential file    
 */

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "pmanager.h"


#define MASTER_PASS "master.hash"
#define ENC_FILE "password.enc"
#define PLAINTEXT_FILE "password.txt"
#define SALT_FILE "salt.bin"

/*Get user input*/
void get_input(const char *prompt, char *buffer, size_t size) {
    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buffer, size, stdin)) {
        buffer[strcspn(buffer, "\n")] = '\0';  // Strip newline
    } else {
        buffer[0] = '\0';
    }
}

/*Add a new account*/
int add_account(const char *file){ 
    //Creates file if it doesn't exist
    FILE *f = fopen(file, "a+");
    if (f == NULL) {
        fprintf(stderr, "[!] Error creating or opening %s\n", file);
        return -1;
    }

    // Check if file is empty and write CSV header if so
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size == 0) {
        fprintf(f, "site,username,password\n");
    }

    //Allocate memory to add new account
    Account *a = malloc(sizeof(Account));
    if(!a){
        fprintf(stderr,"[!] ERROR: Memory allocation failed.");
    }
    
    //Extract credentials from user
    get_input("Enter site name: ",a->site, sizeof(a->site));
    get_input("Enter username: ", a->uname, sizeof(a->uname));
    get_input("Enter password: ", a->pword, sizeof(a->pword));    
    

    char line[256];

    snprintf(line,sizeof(line),"%s,%s,%s\n",a->site,a->uname,a->pword);

    fputs(line,f);
    // Clean up
    free(a);
    fclose(f);
    return 0;
}

int parse_account(const char *line,Account *ac){
    return sscanf(line,"%63[^,],%24[^,],%127[^\n]",ac->site,ac->uname,ac->pword) == 3;
}

int write_to_account(FILE *f,Account *ac){
    return fprintf(f,"%s %s %s\n",ac->site,ac->uname,ac->pword);
}

/*Delete an account*/
int delete_account(const char *target_user,const char *target_site, const char *file) {
  
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        fprintf(stderr, "[!] Failed to open %s for reading.\n", file);
        return -1;
    }

    FILE *temp = fopen("temp.txt", "w");
    if (temp == NULL){
        fclose(f);
        fprintf(stderr,"[!] Failed to open temporary file.\n");
    }

    char line[256];
    int found = 0;
    Account ac;

    //Copy header
    if(fgets(line,sizeof(line),f)){
        fputs(line,temp);
    }

    while(fgets(line,sizeof(line),f)){
        if(parse_account(line,&ac)){
            if(strcmp(ac.site,target_site) == 0 && strcmp(ac.uname,target_user) == 0){
                found = 1;
                continue; //skip writing this entry
            }
            write_to_account(temp,&ac);
        }
    }
    fclose(f);
    fclose(temp);

    if(!found){
        fprintf(stderr,"[!] Failed to find a matching account.\n");
        remove("temp.txt");
        return -1;
    }

    if(remove(file) != 0 || rename("temp.txt",file) != 0){
        fprintf(stderr,"[!] Failed to update file.\n");
        return -1;
    }

    printf("[+] Account has been successfully deleted.\n");
    return 0;
}

/*Update an account credentials*/
int update_account(const char *search_user,const char *search_site,const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "[!] Error opening file: %s\n", file);
        return -1;
    }

    FILE *temp = fopen("temp.txt", "w");
    if (!temp) {
        fclose(f);
        fprintf(stderr, "[!] Error opening temporary file.\n");
        return -1;
    }

    char line[256];
    Account ac;
    int found = 0;

    // Copy header from the first line
    if (fgets(line, sizeof(line), f)) {
        fputs(line, temp);
    }

    //extract the file content and look for a match
    while (fgets(line, sizeof(line), f)) {
        if (parse_account(line,&ac)) {
            if (strcmp(ac.site, search_site) == 0 && strcmp(ac.uname, search_user) == 0) {
                printf("Account found. Enter new credentials:\n");
                get_input("New username: ", ac.uname, sizeof(ac.uname));
                get_input("New password: ", ac.pword, sizeof(ac.pword));
                found = 1;
            }
            write_to_account(temp,&ac);
        }
    }

    fclose(f);
    fclose(temp);

    if (!found) {
        fprintf(stderr, "[!] No matching account found for update.\n");
        remove("temp.txt");
        return -1;
    }

    if(remove(file) != 0 || rename("temp.txt",file) != 0){
        fprintf(stderr,"[!] Failed to update file.\n");
        return -1;
    }

    printf("[+] Account has been successfully updated.\n");
    return 0;
}

int view_all_accounts(const char *file){

    FILE *f = fopen(file,"r");
     if (!f) {
        fprintf(stderr, "[!] Error opening file: %s\n", file);
        return -1;
    }
    
    //the file opened, so read the entries from the file and display them 
    char line[256];
    Account ac;
    int header = 1;
    while(fgets(line,sizeof(line),f)){
        //skip the header
        if(header && strncmp(line,"site,",5) == 0){
            header = 0;
            continue;
        }

        if (parse_account(line,&ac)){
            printf("\n---------------------------\n");
            printf("Website: %s\n",ac.site);
            printf("Username: %s\n",ac.uname);
            printf("Password: %s\n",ac.pword);
            printf("=============================\n");
        }
    }
    fclose(f);
    return 0;
}

int search_account(const char *target_user,const char *target_site, const char *file){

    FILE *f = fopen(file, "r");
    if (f == NULL) {
        fprintf(stderr, "[!] Failed to open %s for reading.\n", file);
        return -1;
    }

    char line[256];
    int found = 0;
    int header = 1;
    Account ac;

    //Skip the header line if present
    if(fgets(line,sizeof(line),f) && strncmp(line,"site,",5) == 0){
        header = 0;
    }  

    //extract the file content and look for a match
    while(fgets(line,sizeof(line),f)){
        if (parse_account(line,&ac)) {
            if (strcmp(ac.site, target_site) == 0 && strcmp(ac.uname, target_user) == 0) {
                printf("\n---------------------------\n");
                printf("Website: %s\n",ac.site);
                printf("Username: %s\n",ac.uname);
                printf("Password: %s\n",ac.pword);
                printf("---------------------------\n");
                found = 1;
                break; //Stop after match is found
            }
        }
    }

    //close file
    fclose(f);

    //Incase account is not found, inform the user
    if (!found){
        printf("No account was found for site '%s' and username '%s'",target_site,target_user);
    }

    return 0;
}
/*Display User Menu*/
void menu_display(){
    printf("=====================================\n");
    printf("Select one of the available options below:\n");
    printf("  1. Add new account\n");
    printf("  2. Delete an account\n");
    printf("  3. Update an account\n");
    printf("  4. View all accounts\n");
    printf("  5. Search for an account\n");
    printf("  6. Quit\n");
    printf("=====================================\n");
}

int create_pmaster(){
    unsigned char salt[crypto_pwhash_SALTBYTES];
    char hash_pass[crypto_pwhash_STRBYTES];
    char pass[128];
    size_t hashn = sizeof(hash_pass) / sizeof(hash_pass[0]);
    size_t saltn = sizeof(salt)/ sizeof(salt[0]);

    //Prompt user for a master password 
    get_input("Enter a new master password: ",pass,sizeof(pass));


    //hash the password
    if(crypto_pwhash_str(hash_pass,pass,strlen(pass),crypto_pwhash_OPSLIMIT_INTERACTIVE,crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0){
        fprintf(stderr,"[!] Out of memory while hashing.\n");
        return -1;
    }

    //Save hash into file
    FILE *f = fopen(MASTER_PASS,"wx");
    if (!f){
         fprintf(stderr, "[!] Failed to open %s in write mode.\n", MASTER_PASS);
        return -1;
    }
    fwrite(hash_pass,sizeof(char),hashn,f);
    fclose(f);

    //Generate and save salt for key derivation
    randombytes_buf(salt,sizeof(salt));
    FILE *s = fopen(SALT_FILE,"wx");
    if (!s){
        fprintf(stderr, "[!] Failed to open %s in write mode.\n", SALT_FILE);
        return -1;
    }
    fwrite(salt,sizeof(char),saltn,s);
    fclose(s);

    printf("[+] Master password has been set.\n");
    return 0;
}

int verify_pmaster(unsigned char key[crypto_secretbox_KEYBYTES]){
    char pass[128];
    char hash_pass[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    int failed_cnt = 0;

    FILE *f = fopen(MASTER_PASS,"r");
    if(!f){
        fprintf(stderr,"[!] Failed to open %s in read mode.\n",MASTER_PASS);
        return -1;
    }
    fread(hash_pass, sizeof(char), crypto_pwhash_STRBYTES, f);
    fclose(f);

    f = fopen(SALT_FILE,"rb");
    if(!f){
        fprintf(stderr,"[!] Failed to read %s in byte mode.\n",MASTER_PASS);
        return -1;
    }
    fread(salt, sizeof(unsigned char), crypto_pwhash_SALTBYTES, f);
    fclose(f);

    //Gives the user 3 tries to enter in the correct password
    while(failed_cnt < 3){
    //Prompt user for password
    get_input("\nEnter master password: ",pass,sizeof(pass));

    printf("\n");
    //verify that it's the correct one
    if (crypto_pwhash_str_verify(hash_pass, pass, strlen(pass)) == 0){
        //password has been verified, now derive a key
        if (crypto_pwhash(key,crypto_secretbox_KEYBYTES,pass,strlen(pass), salt,
                              crypto_pwhash_OPSLIMIT_MODERATE,
                              crypto_pwhash_MEMLIMIT_MODERATE,
                              crypto_pwhash_ALG_DEFAULT) != 0) {
                fprintf(stderr, "[!] Failed to derive key.\n");
                return -1;
        }
        return 0;
    }

    else{
      fprintf(stderr, "\n[!] Incorrect master password has been given, try again.\n");
            failed_cnt++;
            if (failed_cnt == 3) {
                fprintf(stderr, "\n*** INTRUDER ALERT ***\n");
                return -1;
            }
        }
    }
    return -1;
}


int encrypt_file(const char *in_file,const char *out_file, unsigned char key[crypto_secretbox_KEYBYTES]){
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    FILE *f_s = fopen(in_file,"rb");
    if(!f_s){
        fprintf(stderr,"[!] Failed to open input file for encryption.\n");
        return -1;
    }

    //Get the file size
    fseek(f_s,0,SEEK_END);
    long f_size = ftell(f_s);
    rewind(f_s);

    //allocate memory for plaintext and write the data into it
    unsigned char *plaintext = malloc(f_size);
    fread(plaintext,1,f_size,f_s);
    fclose(f_s);

    //Generate a random nonce
    randombytes_buf(nonce,sizeof(nonce));
    //allocate memory for ciphertext
    unsigned char *ciphertext = malloc(f_size + crypto_secretbox_MACBYTES);

    //encrypt
    crypto_secretbox_easy(ciphertext,plaintext,f_size,nonce,key);

    //store the ciphertext
    FILE *f_t = fopen(out_file,"wb");
    if (!f_t){
        fprintf(stderr,"[!] Failed to open output file for encryption.\n");
        free(plaintext);
        free(ciphertext);
        return -1;
    }
    fwrite(nonce,1,sizeof(nonce),f_t);
    fwrite(ciphertext,1,f_size + crypto_secretbox_MACBYTES,f_t);
    fclose(f_t);

    //free everything
    free(plaintext);
    free(ciphertext);

    return 0;
}


int decrypt_file(const char *out_file,const char *in_file, unsigned char key[crypto_secretbox_KEYBYTES]){
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    FILE *f_s = fopen(in_file,"rb");
    if(!f_s){
        fprintf(stderr,"[!] Failed to open output file for decryption.\n");
        return -1;
    }

    //Get the file size
    fseek(f_s,0,SEEK_END);
    long f_size = ftell(f_s);
    rewind(f_s);

    if (f_size < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES){
        fclose(f_s);
        fprintf(stderr,"[!] Encrypted file is too small or corrupted.\n");
        return -1;
    }

    //read nonce and ciphertext into memory
    fread(nonce,1,sizeof(nonce),f_s);
    long ciphertext_len = f_size - crypto_secretbox_NONCEBYTES;
    unsigned char *ciphertext = malloc(ciphertext_len);
    fread(ciphertext,1,ciphertext_len,f_s);
    fclose(f_s);

    //initiate plaintext file
    unsigned char *decrypted_text = malloc(ciphertext_len - crypto_secretbox_MACBYTES);

    //decrypt the ciphertext file
    if(crypto_secretbox_open_easy(decrypted_text,ciphertext,ciphertext_len,nonce,key) != 0){
        fprintf(stderr,"[!] Decryption Failed. Possibly provided the wrong password.\n");
        free(decrypted_text);
        free(ciphertext);
        return -1;
    }

    FILE *f_t = fopen(out_file,"wb");
    if (!f_t){
        fprintf(stderr, "[!] Failed to open output file for decryption.\n");
        free(ciphertext);
        free(decrypted_text);
        return -1;
    }

    fwrite(decrypted_text,1,(ciphertext_len - crypto_secretbox_MACBYTES),f_t);
    fclose(f_t);

    //free everything
    free(ciphertext);
    free(decrypted_text);

    printf("[+] File has been decrypted.\n");
    return 0;
}

//main driver
int main() {
    char uname[25], site[64];
    unsigned char key[crypto_secretbox_KEYBYTES];
    // Initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "[!] Failed to initialize libsodium.\n");
        return -1;
    }

  

    //Check if master password has been set, if not prompt user to create one
    if(access(MASTER_PASS,F_OK) != 0){
        // Prompt for master password and hash it
        create_pmaster();
    }
    
    printf("=====================================\n");
    printf("  Welcome to VaultSecure!\nYour credentials are protected with strong cryptography and never stored in plain text.\nPlease enter your master password to unlock access.");
    printf("\n**Security Tip** Never share your master password. If you forget it, recovery is not possible.");
    //User already created a master password, verify the correct master password is provide
    if (verify_pmaster(key) != 0){
        fprintf(stderr,"[!] Authentication failed, Exiting.\n");
        return -1;
    }

    // Decrypt file if exists
    if (access(ENC_FILE, F_OK) == 0) {
        if (decrypt_file(PLAINTEXT_FILE, ENC_FILE, key) != 0) {
            fprintf(stderr, "[!] Failed to decrypt credentials. Exiting.\n");
            return -1;
        }
    }

    int choice;
    char choice_buf[8];  // Enough for digits + null terminator
    do {
        menu_display();
       
        get_input("Enter your choice: ", choice_buf, sizeof(choice_buf));
        choice = atoi(choice_buf);  // Converts string to int
        switch (choice) {
            case 1:
                add_account(PLAINTEXT_FILE);
                break;
            case 2: {
                get_input("Enter username: ", uname, sizeof(uname));
                //fflush(stdout);
                get_input("Enter site: ", site, sizeof(site));
                delete_account(uname, site, PLAINTEXT_FILE);
                break;
            }
            case 3:
                get_input("Enter username: ", uname, sizeof(uname));
                get_input("Enter site: ", site, sizeof(site));
                update_account(uname,site,PLAINTEXT_FILE);
                break;
            case 4:
                view_all_accounts(PLAINTEXT_FILE);
                break;
            case 5:
                get_input("Enter username: ", uname, sizeof(uname));
                get_input("Enter site: ", site, sizeof(site));
                search_account(uname,site,PLAINTEXT_FILE);
                break;
            case 6:
                //With the encryption key, the file could now be encrypted
                printf("[*] Exiting and encrypting data...\n");
                if (encrypt_file(PLAINTEXT_FILE, ENC_FILE, key) != 0) {
                    fprintf(stderr, "[!] Encryption failed.\n");
                } else {
                    remove(PLAINTEXT_FILE); // Clean up decrypted file
                    printf("[+] Data encrypted and saved.\n");
                }
                printf("\nGood bye.\n");
                break;
            default:
                printf("[!] Invalid choice.\n");
                break;
        }
    } while (choice != 6);

    return 0;
}