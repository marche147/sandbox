#pragma once

#include <iostream>
#include <json/json.h>
#include <string>
#include <fstream>

class ConfigFile
{
private:
	std::ifstream* m_config;
	Json::Value* m_root;

public:
	ConfigFile(std::string config);
	~ConfigFile();

	bool getBool(std::string key, bool defvalue = false);
	std::string getString(std::string key, std::string defvalue = "");
	int getInt(std::string key, int defvalue = 0);
	__int64 getInt64(std::string key, __int64 defvalue = 0);
	Json::Value get(std::string key, Json::Value defvalue = Json::Value());
};

