#include <iostream>

#include "modes/ecb.hpp"
#include "modes/cbc.hpp"
#include "modes/cfb.hpp"
#include "modes/ofb.hpp"
#include "modes/ctr.hpp"

using namespace std;

int main()
{
    int choice;

    while (true)
    {
        cout << "\n===== AES Modes of Operation =====\n";
        cout << "1. ECB\n";
        cout << "2. CBC\n";
        cout << "3. CFB\n";
        cout << "4. OFB\n";
        cout << "5. CTR\n";
        cout << "0. Exit\n";
        cout << "Select mode: ";

        cin >> choice;

        switch (choice)
        {
            case 1:
                ecb_mode();
                break;

            case 2:
                //cbc_mode();
                break;

            case 3:
                //cfb_mode();
                break;

            case 4:
                //ofb_mode();
                break;

            case 5:
                //ctr_mode();
                break;

            case 0:
                cout << "Exiting...\n";
                return 0;

            default:
                cout << "Invalid option. Try again.\n";
        }
    }
}