#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <random>
#include <string_view>
#include <string>
#include <unordered_map>
#include <vector>
#include <system_error>
#include <chrono>

using std::cout;
using std::endl;
using std::string;
using std::string_view;
namespace fs = std::filesystem;

using cstr_ref = const string&;
using str_cref = const string&;
using str = string;

using bytes = std::vector<uint8_t>;

#define JSON_USE_IMPLICIT_CONVERSIONS 0
#include <nlohmann/json.hpp>
using nlohmann::literals::operator""_json_pointer;
using njson = nlohmann::json;

#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_ZLIB_SUPPORT
#define CPPHTTPLIB_BROTLI_SUPPORT
#include <httplib.h>

#include <picosha2.h>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_default_url_unpadded.hpp>
