#include "cmd_options.h"

#include <iostream>
#include <ostream>
#include <print>
#include <string>

namespace po = boost::program_options;
namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    desc_.add_options()("help", "produce help message")("command", po::value<std::string>()->required(),
                                                        "command to execute")(
        "input,i", po::value<std::string>()->required(), "path to input file")(
        "output,o", po::value<std::string>(), "path to file with result")("password,p", po::value<std::string>(),
                                                                          "password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc_ << "\n";
            return true;
        }

        inputFile_ = vm["input"].as<std::string>();

        std::string stringCommand = vm["command"].as<std::string>();
        if (auto it = commandMapping_.find(stringCommand); it != commandMapping_.end()) {
            command_ = it->second;
        } else {
            std::print("No such command\n");
            return false;
        }

        if (command_ != COMMAND_TYPE::CHECKSUM) {
            if (vm.count("output")) {
                outputFile_ = vm["output"].as<std::string>();
            } else {
                std::print("Output file was not set.\n");
                return false;
            }

            if (vm.count("password")) {
                password_ = vm["password"].as<std::string>();
            } else {
                std::print("Password was not set.\n");
                return false;
            }
        }

    } catch (std::exception &e) {
        std::print("Error parsing arguments: {}\n", e.what());
        return false;
    }

    return true;
}

}  // namespace CryptoGuard
