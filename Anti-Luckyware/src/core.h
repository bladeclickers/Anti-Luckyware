#pragma once

#include <fstream>
#include <iostream>
#include <filesystem>

#include "globals.h"

namespace fs = std::filesystem;

inline std::string read_file_to_string(const fs::path& file_path)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
        return {};

    return std::string(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

void scan_vcxproj(std::string root_dir) {
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

            for (auto& link_string : links)
            {
                if (contents.find(link_string) != std::string::npos)
                {
                    std::cout << "[X] project is infected, link found: " << link_string << "\n";

                    infected_flag = true;
                    infected_count++;
                }
            }

            break;
        }
    }
}

void scan_winsdk() {
    if (fs::exists(luckyware_winsdk_file)) {
        std::string winnetwk_contents = read_file_to_string(luckyware_winsdk_file);

        if (winnetwk_contents.find("VCCHelp") != std::string::npos) {
            std::cout << "[X] windows sdk was infected, VCCHelp found. your computer has already been infected by luckyware\n";

            infected_flag = true;
            infected_count++;
        }
        else {
            std::cout << "[+] windows sdk does not appear to be infected, VCCHelp not found.\n";
        }
    }
}

void block_luckyware_links() {
    std::ofstream hosts_file(hosts, std::ios::app);

    if (!hosts_file) {
        std::cout << "[-] failed to open hosts file.\n";
        return;
    }

	std::string hosts_contents = read_file_to_string(hosts);

    if (hosts_contents.find("i-like.boats") != std::string::npos) {
        std::cout << "[+] luckyware links already blocked in hosts file.\n";
        hosts_file.close();
        return;
	}

    for (auto& link : links) {
        hosts_file << "\n0.0.0.0 " << link << " # luckyware server link";
    }

    hosts_file.close();
}