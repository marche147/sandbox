#include "stdafx.h"
#include "ConfigFile.h"
#include <string>

ConfigFile::ConfigFile(std::string config)
{
	m_config = new std::ifstream(config, std::ifstream::in);
	if (!m_config) {
		throw std::exception("open config failed");
	}
	m_root = new Json::Value();
	if (!m_root) {
		throw std::exception("create json failed");
	}

	*m_config >> *m_root;
}

ConfigFile::~ConfigFile()
{
	delete m_config, m_root;
}

bool ConfigFile::getBool(std::string key, bool defvalue)
{
	return m_root->get(key, defvalue).asBool();
}

std::string ConfigFile::getString(std::string key, std::string defvalue)
{
	return m_root->get(key, defvalue).asString();
}

int ConfigFile::getInt(std::string key, int defvalue)
{
	return m_root->get(key, defvalue).asInt();
}

__int64 ConfigFile::getInt64(std::string key, __int64 defvalue)
{
	return m_root->get(key, defvalue).asInt64();
}

Json::Value ConfigFile::get(std::string key, Json::Value defvalue)
{
	return m_root->get(key, defvalue);
}

