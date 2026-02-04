#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

bool suspicious = false;
bool infected_flag = false;

int suspicious_count = 0;
int infected_count = 0;

std::string project_path;
std::string luckyware_winsdk_file = "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\um\\winnetwk.h";

std::vector<std::string> suspicious_indicators = {
    "Command",
    "PreBuildEvent",
    "PostBuildEvent",
    "cmd",
    "bat",
    "pwsh",
    "powershell"
};

std::vector<std::string> infected = {
    "i-like.boats",
    "devruntime.cy",
    "zetolacs-cloud.top",
    "frozi.cc",
    "exo-api.tf",
    "nuzzyservices.com",
    "darkside.cy",
    "balista.lol",
    "phobos.top",
    "phobosransom.com",
    "pee-files.nl",
    "vcc-library.uk",
    "luckyware.co",
    "luckyware.cc",
    "91.92.243.218",
    "dhszo.darkside.cy",
    "188.114.96.11",
    "risesmp.net",
    "luckystrike.pw",
    "krispykreme.top",
    "vcc-redistrbutable.help",
    "i-slept-with-ur.mom",
    "Berok.exe",
    "Retev.php"
};

std::string read_file_to_string(const fs::path& file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
        return {};

    return std::string(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "[-] no path provided. usage: Anti-Luckyware.exe <path containing project>\n";
        std::cout << "press enter to exit...\n";

        std::cin.get();

        return 1;
    }

    fs::path root_dir = argv[1];
    std::string target_extension = ".vcxproj";

	std::cout << "[+] starting project scan in directory: " << root_dir << "\n\n";

    for (const auto& entry : fs::recursive_directory_iterator(root_dir))
    {
        if (entry.is_directory()) {
            if (entry.path().stem().string().find(".vs") != std::string::npos) {
                std::cout << "[+] found .vs folder, deleting..." << "\n";
                try {
                    fs::remove_all(entry);
                    continue;
                }
                catch (std::exception e) {
                    std::cout << "[-] failed to delete .vs folder. error: " << e.what() << "\n\n";
                }
            }
        }

        if (!entry.is_regular_file())
            continue;

        if (entry.path().extension() == target_extension)
        {
			std::cout << "[+] scanning file: " << entry.path() << "\n";

            std::string contents = read_file_to_string(entry.path());

			for (auto& indicator : suspicious_indicators)
            {
                if (contents.find(indicator) != std::string::npos)
                {
                    std::cout << "[!] project is suspicious, string found: " << indicator << "\n";

                    suspicious = true;
					suspicious_count++;
                }
            }

			for (auto& infected_string : infected)
            {
                if (contents.find(infected_string) != std::string::npos)
                {
                    std::cout << "[X] project is infected, string found: " << infected_string << "\n";

                    infected_flag = true;
					infected_count++;
                }
            }

            break;
        }
    }

    std::cout << "[+] vcxproj scanned.\n";
    std::cout << "\n[+] scanning windows sdk for luckyware...\n";

    if (fs::exists(luckyware_winsdk_file)) {
        std::string winnetwk_contents = read_file_to_string(luckyware_winsdk_file);

        if (winnetwk_contents.find("VCCHelp") != std::string::npos) {
            std::cout << "[X] windows sdk was infected, VCCHelp found.\n";

            infected_flag = true;
            infected_count++;
        }
    }

    std::cout << "[+] windows sdk scanned.\n";

    std::cout << "\nscan finished.\n\n";

	std::cout << "suspicious indicators found: " << suspicious_count << "\n";
	std::cout << "infected indicators found: " << infected_count << "\n\n";

    if (infected_flag)
        std::cout << "[X] the scanned project is infected, do not open it.\n";
    else if (suspicious)
        std::cout << "[!] the scanned project is suspicious, carefully check the vcxproj.\n";
    else
		std::cout << "[+] the scanned project appears clean, however still check the vcxproj for anything else.\n";

	std::cout << "\npress enter to exit...\n";

    std::cin.get();

    return 0;
}