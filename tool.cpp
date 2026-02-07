#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

class PasswordVault {
private:
    string db_file;
    string key;

    // XOR Encryption (Basic Lock)
    string xor_process(string text, string key_code) {
        string result = text;
        for (int i = 0; i < text.length(); i++) {
            result[i] = text[i] ^ key_code[i % key_code.length()];
        }
        return result;
    }

    // Convert Weird Symbols to Safe HEX (Important!)
    // Ye function encrypted kachre ko "Safe Text" me badalta hai
    string stringToHex(string input) {
        stringstream ss;
        for (size_t i = 0; i < input.length(); i++) {
            ss << hex << setw(2) << setfill('0') << (int)(unsigned char)input[i];
        }
        return ss.str();
    }

    // Convert HEX back to Symbols
    string hexToString(string input) {
        string output;
        for (size_t i = 0; i < input.length(); i += 2) {
            string part = input.substr(i, 2);
            char ch = (char)strtol(part.c_str(), NULL, 16);
            output += ch;
        }
        return output;
    }

public:
    PasswordVault() {
        db_file = "vault.txt";
        key = "";
    }

    void set_master_password(string mp) {
        key = mp;
    }

    void save_password() {
        if (key == "") {
            cout << "[ERROR] Master Password set nahi hai!" << endl;
            return;
        }

        string service, password;
        
        cout << "Service Name (e.g. Gmail): ";
        getline(cin, service);
        
        cout << "Password: ";
        getline(cin, password);

        // Encrypt kiya (Weird Symbols bane)
        string encrypted_raw = xor_process(password, key);
        
        // Hex me convert kiya (Safe text bana)
        string encrypted_hex = stringToHex(encrypted_raw);

        ofstream file(db_file.c_str(), ios::app);
        if (file.is_open()) {
            file << service << ":" << encrypted_hex << endl;
            file.close();
            cout << "[SUCCESS] Password saved!" << endl;
        } else {
            cout << "[ERROR] File khul nahi rahi!" << endl;
        }
    }

    void get_password() {
        if (key == "") {
            cout << "[ERROR] Vault locked." << endl;
            return;
        }

        string search_service;
        cout << "Kaunsi Service ka password chahiye?: ";
        getline(cin, search_service);

        ifstream file(db_file.c_str());
        string line;
        bool found = false;

        if (file.is_open()) {
            while (getline(file, line)) {
                size_t divider_pos = line.find(':');
                
                if (divider_pos != string::npos) {
                    string s_name = line.substr(0, divider_pos);
                    string s_hex_pass = line.substr(divider_pos + 1);

                    if (s_name == search_service) {
                        // Hex se wapas raw text banaya
                        string raw_encrypted = hexToString(s_hex_pass);
                        
                        // Decrypt kiya
                        string decrypted = xor_process(raw_encrypted, key);
                        
                        cout << "---------------------------------" << endl;
                        cout << "Service : " << s_name << endl;
                        cout << "Password: " << decrypted << endl;
                        cout << "---------------------------------" << endl;
                        found = true;
                        break;
                    }
                }
            }
            file.close();
        }

        if (!found) {
            cout << "[ERROR] Service nahi mili." << endl;
        }
    }
};

int main() {
    PasswordVault vault;
    string master_pass;
    int choice;

    cout << "Master Password banayein: ";
    getline(cin, master_pass);
    vault.set_master_password(master_pass);
    
    cout << "[OK] Vault Unlocked.\n" << endl;

    while (true) {
        cout << "\n1. Password Save karein";
        cout << "\n2. Password Dekhein";
        cout << "\n3. Exit";
        cout << "\nChoice: ";
        
        if (!(cin >> choice)) { 
            cout << "Sirf number dalein!" << endl;
            cin.clear();
            cin.ignore(1000, '\n');
            continue;
        }
        cin.ignore(); // Buffer clear (Bahut zaroori)

        if (choice == 1) {
            vault.save_password();
        } 
        else if (choice == 2) {
            vault.get_password();
        } 
        else if (choice == 3) {
            cout << "Bye Bye!" << endl;
            break;
        } 
        else {
            cout << "Ghalat choice!" << endl;
        }
    }
    return 0;
}