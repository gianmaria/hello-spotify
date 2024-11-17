#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
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

#include "Spotify.h"

string env(string_view name)
{
    auto split_line = [](cstr_ref line)
        -> std::pair<string, string>
    {
        const string delimiter = "=";
        auto pos = line.find(delimiter);

        if (pos == std::string::npos)
            return {};

        std::pair<string, string> res;

        res.first = line.substr(0, pos);
        res.second = line.substr(pos + 1);

        return res;
    };

    std::ifstream ifs(".env");

    string res;

    if (ifs.is_open())
    {
        string line;
        while (std::getline(ifs, line))
        {
            auto [key, value] = split_line(line);

            if (key == name)
            {
                res = value;
                break;
            }
        }
    }

    return res;
}


void general_test(const Spotify::API& api)
{
    auto me = api.user_profile_get_current_user_profile();
    auto id = me.body["id"].get_ref<str_cref>();

    cout << "User: " << me.body["display_name"].get_ref<str_cref>()
        << " mail: " << me.body["email"].get_ref<str_cref>()
        << " id: " << id
        << " product: " << me.body["product"].get_ref<str_cref>()
        << endl;

    //cout << playlists.dump(3) << endl;
    size_t offset = 0;
    size_t limit = 50;

    auto playlists = api.playlists_get_current_user_playlists(limit, offset);

    cout << "Found " << playlists.body["total"].get<size_t>() << " playlists" << endl;

    size_t count = 1;
    while (true)
    {
        for (const auto& item : playlists.body["items"])
        {
            auto playlist_owner = item["owner"]["id"].get_ref<str_cref>();

            if (id != playlist_owner)
            {
                continue;
            }

            cout
                << "[" << count++ << "] "
                << item["name"]
                << " by " << item["owner"]["display_name"]
                << " - " << item["tracks"]["total"].get<uint32_t>() << " songs"
                << endl;


        }

        if (playlists.body["next"].is_null())
            break;

        offset += limit;

        using namespace std::chrono_literals;
        std::this_thread::sleep_for(500ms);

        playlists = api.playlists_get_current_user_playlists(limit, offset);
    }
}

void playback_test(const Spotify::API& api)
{
    auto state = api.player_get_playback_state();
    cout << state.body.dump(3) << endl;

    auto res = api.player_skip_to_next();
    cout << res.body.dump(3) << endl;

    int stop = 0;
}

int main()
{
    try
    {
        njson spotify_auth;
        auto spotify_auth_filename = "spotify_auth.json";

        if (fs::exists(spotify_auth_filename))
        {
            spotify_auth = njson::parse(std::ifstream(spotify_auth_filename));

            if (Spotify::API(spotify_auth["access_token"].get_ref<string&>()).is_token_expired())
            {
                auto new_access_token = Spotify::Auth::refresh_access_token(
                    env("CLIENT_ID"),
                    spotify_auth["refresh_token"].get_ref<cstr_ref>());

                spotify_auth = new_access_token;

                std::ofstream(spotify_auth_filename)
                    << spotify_auth.dump(3) << std::endl;
            }
        }
        else
        {
            Spotify::Auth_Settings settings
            {
                .client_id = env("CLIENT_ID"),
                .client_secret = env("CLIENT_SECRET"),

                .scope = "ugc-image-upload user-read-playback-state user-modify-playback-state user-read-currently-playing app-remote-control streaming playlist-read-private playlist-read-collaborative playlist-modify-private playlist-modify-public user-follow-modify user-follow-read user-read-playback-position user-top-read user-read-recently-played user-library-modify user-library-read user-read-email user-read-private",

                .redirect_uri_host = "localhost",
                .redirect_uri_port = 6969,
                .redirect_uri_path = "/spotify-callback"
            };

            auto auth = Spotify::Auth(settings);

            auto chrome_params = std::format("--new-window --profile-directory=\"Default\" {}",
                                             auth.generate_url_for_user_authorization());

            auto res = ShellExecuteA(NULL, "open",
                                     "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                     chrome_params.c_str(), NULL, 0);

            if (reinterpret_cast<INT_PTR>(res) < 32)
            {
                str error;

                switch (reinterpret_cast<INT_PTR>(res))
                {
                    case 0: error = "The operating system is out of memory or resources"; break;
                    case ERROR_FILE_NOT_FOUND: error = "ERROR_FILE_NOT_FOUND"; break;
                    case ERROR_PATH_NOT_FOUND: error = "ERROR_PATH_NOT_FOUND"; break;
                    case ERROR_BAD_FORMAT: error = "ERROR_BAD_FORMAT"; break;
                    case SE_ERR_ACCESSDENIED: error = "SE_ERR_ACCESSDENIED"; break;
                    case SE_ERR_ASSOCINCOMPLETE: error = "SE_ERR_ASSOCINCOMPLETE"; break;
                    case SE_ERR_DDEBUSY: error = "SE_ERR_DDEBUSY"; break;
                    case SE_ERR_DDEFAIL: error = "SE_ERR_DDEFAIL"; break;
                    case SE_ERR_DDETIMEOUT: error = "SE_ERR_DDETIMEOUT"; break;
                    case SE_ERR_DLLNOTFOUND: error = "SE_ERR_DLLNOTFOUND"; break;
                    case SE_ERR_NOASSOC: error = "SE_ERR_NOASSOC"; break;
                    case SE_ERR_OOM: error = "SE_ERR_OOM"; break;
                    case SE_ERR_SHARE: error = "SE_ERR_SHARE"; break;
                    default: error = "???"; break;
                }

                cout << "[ERROR] Cannot start Chrome: " << error
                    << " (" << std::system_category().message(GetLastError()) << ")"
                    << endl;

                return 1;
            }

            auto auth_code = auth.spawn_server_for_callback();

            if (auth_code == "")
            {
                cout << "[ERROR] Cannot obtain auth_code" << endl;
                return 1;
            }

            spotify_auth = auth.request_access_token(auth_code);

            if (spotify_auth.is_null())
            {
                cout << "[ERROR] Cannot get barer token" << endl;
                return 1;
            }

            std::ofstream(spotify_auth_filename) <<
                spotify_auth.dump(3) << std::endl;
        }

        auto api = Spotify::API(spotify_auth["access_token"].get_ref<string&>());

        //playback_test(api);
        general_test(api);

        return 0;
    }
    catch (const std::exception& e)
    {
        cout << "[EXCEPTION] " << e.what() << endl;
        return 1;
    }
}
