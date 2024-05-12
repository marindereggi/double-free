/**
 * @file main.c
 * @brief Double Free Demo
 *
 * This program demonstrates a double free vulnerability.
 * The program serves as a simple database manager, enabling users to query and
 * insert entries into a database. It distinguishes between two user roles: user
 * and admin.
 *
 * Can you identify the double free vulnerability and understand how to exploit
 * it?
 *
 * Spoiler: line 0x68
 *
 * @note This program contains intentional vulnerabilities. Avoid using it in
 * production or on untrusted networks.
 * @note The vulnerability is not immediately reported and hence is exploitable
 * only when linked against glibc versions lacking tcache support (prior
 * to 2.26).
 * @bug There is a double free vulnerability in the program.
 * @see https://cwe.mitre.org/data/definitions/415.html
 *
 * @author Marin Gazvoda de Reggi
 * @date 2024-05-11
 */

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIZE 16

#define streq(a, b) (strncmp(a, b, SIZE) == 0)

/**
 * User management
 */
#define ADMIN_UID 0
#define USER_UID 1

static int uid = USER_UID;

#define IS_ADMIN (uid == ADMIN_UID)
#define USERNAME (IS_ADMIN ? "admin" : "user")

/**
 * Database
 */
static int db = -1;

typedef struct {
    unsigned char id;
    char name[SIZE - 1];
} DBEntry;

/**
 * Admin utilities
 */
void insert_into_db(char *line) {
    char name[SIZE];
    if (sscanf(line, "%*s %s", name) != 1) {
        puts("Invalid entry.");
        return;
    }

    DBEntry *entry = malloc(sizeof(DBEntry));
    entry->id = lseek(db, 0, SEEK_END) / sizeof(DBEntry);
    strncpy(entry->name, name, SIZE - 1);

    if (write(db, entry, sizeof(DBEntry)) == sizeof(DBEntry))
        printf("Entry added: %d | %s\n", entry->id, entry->name);
    else
        puts("Error writing to database.");

    free(entry);
}

void drop_db() {
    printf("Are you sure you want to wipe the database? (y/N): ");
    char buf[SIZE];
    fgets(buf, SIZE, stdin);

    if (buf[0] == 'y') {
        puts("Wiping database...");
        ftruncate(db, 0);
        puts("Database wiped!");
    } else
        puts("Aborted.");
}

/**
 * User utilities
 */
void select_from_db(char *line) {
    DBEntry *entry = malloc(sizeof(DBEntry));

    char query[SIZE];
    if (sscanf(line, "%*s %s", query) != 1) {
        puts("Invalid query.");
        free(line);
        free(entry);
        return;
    }

    bool match_all = streq(query, "*");

    int num_entries = lseek(db, 0, SEEK_END) / sizeof(DBEntry);
    lseek(db, 0, SEEK_SET);

    puts(" id | name");
    puts("----+----------------");

    int count = 0;

    for (int i = 0; i < num_entries; i++) {
        read(db, entry, sizeof(DBEntry));
        if (match_all || streq(entry->name, query)) {
            printf("%3d | %s\n", entry->id, entry->name);
            count++;
        }
    }

    printf("Found %d entr%s.\n", count, count == 1 ? "y" : "ies");

    free(entry);
}

void change_user(char *line) {
    char *username = malloc(SIZE * sizeof(char));
    if (sscanf(line, "%*s %s", username) != 1) {
        puts("Invalid username.");
        free(username);
        return;
    }

    if (streq(username, "user")) {
        uid = USER_UID;
        puts("Switched to user.");
        free(username);
        return;
    } else if (!streq(username, "admin")) {
        puts("Invalid username.");
        free(username);
        return;
    }

    char *password = malloc(SIZE * sizeof(char));

    /**
     * NOTE: For demonstration purposes, the password is stored in plaintext.
     * In a real application, never store passwords in plaintext.
     */
    int fd = open("password.txt", O_RDONLY);
    if (fd == -1) {
        puts("Error opening file");
        exit(1);
    }

    read(fd, password, SIZE);
    close(fd);

    printf("Enter password: ");
    fgets(line, SIZE, stdin);
    printf("\033[A\33[2K\r"); // Clear line
    line[strcspn(line, "\r\n")] = 0;

    if (streq(line, password)) {
        uid = ADMIN_UID;
        puts("Switched to admin.");
    } else
        puts("Incorrect password!");

    // Clear buffers
    memset(password, 0, SIZE * sizeof(char));
    memset(line, 0, SIZE * sizeof(char));

    free(password);
    free(username);
}

/**
 * Main loop
 */
void print_info() {
    printf("\nLogged in as: %s\n", USERNAME);

    puts("1) Quit\n"
         "2) Change <user>\n"
         "3) Query <something|*>");

    if (IS_ADMIN)
        puts("4) Insert <entry> into database\n"
             "5) Wipe database");

    printf("Enter your choice: ");
}

void handle_choice() {
    char *line = malloc(SIZE * sizeof(char));

    fgets(line, SIZE, stdin);
    int choice = atoi(line);

    switch (choice) {
    case 1:
        puts("Goodbye!");
        exit(0);
    case 2:
        change_user(line);
        break;
    case 3:
        select_from_db(line);
        break;
    case 4:
        if (IS_ADMIN)
            insert_into_db(line);
        break;
    case 5:
        if (IS_ADMIN)
            drop_db();
        break;
    }

    free(line);
}

int main() {
    // Disable buffering for stdin and stdout
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    assert(sizeof(DBEntry) == SIZE);

    if ((db = open("database.db", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) == -1) {
        puts("Error opening database.");
        exit(1);
    }

    puts("Welcome to database manager!");

    while (true) {
        print_info();
        handle_choice();
    }

    return 0;
}
