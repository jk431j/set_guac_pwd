#include <iostream>
#include "INIReader.h"
#include <uuid/uuid.h>
#include <termios.h>
#include <pwd.h>

#include <unistd.h>

#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>

using namespace std;

bool getDbParms(string& dbName, string& dbUser, string& dbPwd, string& dbSchema) {
    INIReader guacProp("/etc/guacamole/guacamole.properties");

    if (guacProp.ParseError() != 0) {
        cerr << "Can't open guacamole.properties" << endl;
        if (getgid() == getegid()) {
            cerr << "Contact your administrator to set 'setgid' bit on set_guac_pwd" << endl;
        };
        return false;
    };

    dbName = guacProp.Get("", "mysql-database", "");
    dbUser = guacProp.Get("", "mysql-username", "");
    dbPwd = guacProp.Get("", "mysql-password", "");
    dbSchema = "guacamole_db";

    return true;
}

bool readPassword(string& newPwd) {
    string secondPwd;

    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);

    // disable echo
    tty.c_lflag &= ~ECHO;
    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    cout << "Enter password: ";
    cin >> newPwd;
    cout << endl;

    cout << "Once more: ";
    cin >> secondPwd;
    cout << endl;

    // re-enable echo
    tty.c_lflag |= ECHO;
    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    if (newPwd != secondPwd) {
        cerr << "Passwords don't match, exiting" << endl;
        return false;
    } else
        return true;
}

int main(int argc, char *argv[]) {
    try {
        string dbName, dbUser, dbPwd, dbSchema, newPwd;

        if (!getDbParms(dbName, dbUser, dbPwd, dbSchema))
            exit(1);

        sql::Driver *driver;
        sql::Connection *con;
        sql::PreparedStatement *pstmt;
        sql::ResultSet *res;

        struct passwd *userInfo;

        userInfo = getpwuid(getuid());

        if (argc > 1)
            newPwd = argv[1];
        else
            if (!readPassword(newPwd))
                exit(2);

        /* Create a connection */
        driver = get_driver_instance();
        con = driver->connect("tcp://127.0.0.1:3306", dbUser, dbPwd);
        con->setSchema(dbSchema);

        uuid_t UUID;
        char UUIDstr[40];
        int userId;

        uuid_generate(UUID);
        uuid_unparse(UUID, UUIDstr);

        pstmt = con->prepareStatement("SELECT entity_id FROM guacamole_entity WHERE name = ? AND type = 'USER'");
        pstmt->setString(1, userInfo->pw_name);
        res = pstmt->executeQuery();
        if (res->next())
            userId = res->getInt("entity_id");
        else {
            cerr << "Could not find Guacamole account for user " << userInfo->pw_name << endl;
            exit(3);
        };
        delete res;
        delete pstmt;

        string updateSQL = "UPDATE guacamole_user "
                           "SET "
                           "   password_salt = UNHEX(SHA2(?, 256)), "
                           "   password_hash = UNHEX(SHA2(CONCAT(?, HEX(UNHEX(SHA2(?, 256)))), 256)), "
                           "   password_date = CURRENT_TIMESTAMP "
                           "WHERE entity_id = ? ";

        pstmt = con->prepareStatement(updateSQL);
        pstmt->setString(1, UUIDstr);
        pstmt->setString(2, newPwd);
        pstmt->setString(3, UUIDstr);
        pstmt->setInt(4, userId);
        pstmt->executeUpdate();

        delete pstmt;
        delete con;

        cout << "Guacamole password updated for " << userInfo->pw_name <<  endl;
    } catch (sql::SQLException &e) {
        cout << "# ERR: SQLException in " << __FILE__;
        cout << "(" << __FUNCTION__ << ") on line "<< __LINE__ << endl;
        cout << "# ERR: " << e.what();
        cout << " (MySQL error code: " << e.getErrorCode();
        cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    };

    return 0;
}