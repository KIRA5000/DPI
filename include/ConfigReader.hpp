#pragma once

#include <fstream>
#include <unordered_map>

#include "String.hpp"

#define CONFIG_FILE_PATH "/home/kira5000/study/DPI/Configuration.ini"

class ConfigReader {
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> configData;

    ConfigReader() {
        std::ifstream configFile(CONFIG_FILE_PATH);

        std::string line, sectionName = "";
        while (std::getline(configFile, line)) {
            if (line.empty() || line[0] == '#') {
                continue;
            }

            if ((line[0] == '[') && (line.back() == ']')) {
                sectionName = line.substr(1, line.size() - 2);
            } 
            else {
                auto pair = StringOperations::getInstance().parse(line, '=');

                if ((pair.size() == 2) && (!sectionName.empty())) {
                    configData[sectionName][pair[0]] = pair[1];
                }
            }
        }
    }

    ConfigReader(const ConfigReader&) = delete;
    ConfigReader& operator=(const ConfigReader&) = delete;

public:

    static ConfigReader& getInstance() {
        static ConfigReader instance;
        return instance;
    }

    std::string getValue(const std::string& section, const std::string& key) {
        if ((configData.find(section) != configData.end()) && (configData[section].find(key) != configData[section].end())) {
            return configData[section][key];
        }

        return std::string();
    }
};