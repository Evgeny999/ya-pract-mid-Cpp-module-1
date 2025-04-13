#include "cmd_options.h"

#include <iostream>
#include <ostream>
#include <string>

namespace po = boost::program_options;
namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    desc_.add_options()("help", "produce help message")("command", po::value<std::string>(), "command to execute")(
        "input,i", po::value<std::string>(), "path to input file")(
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

        if (vm.count("command")) {
            std::string stringCommand = vm["command"].as<std::string>();
            try {
                command_ = commandMapping_.at(stringCommand);
            } catch (...) {
                std::cout << "No such command\n";
                return false;
            }
            std::cout << "Command is " << stringCommand << ".\n";
        } else {
            std::cout << "Command was not specified\n";
            return false;
        }

        if (vm.count("input")) {
            inputFile_ = vm["input"].as<std::string>();
            std::cout << "Input file is " << inputFile_ << ".\n";
        } else {
            std::cout << "Input file was not set.\n";
            return false;
        }

        if (command_ != COMMAND_TYPE::CHECKSUM) {
            if (vm.count("output")) {
                outputFile_ = vm["output"].as<std::string>();
                std::cout << "Output file is " << outputFile_ << ".\n";
            } else {
                std::cout << "Output file was not set.\n";
                return false;
            }

            if (vm.count("password")) {
                password_ = vm["password"].as<std::string>();
                std::cout << "Password is " << password_ << ".\n";
            } else {
                std::cout << "Password was not set.\n";
                return false;
            }
        }

    } catch (std::exception &e) {
        std::cout << "Error parsing arguments: " << e.what() << "\n";
        return false;
    }

    return true;
}

}  // namespace CryptoGuard
