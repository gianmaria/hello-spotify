#include "pch.h"

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

int main()
{
    try
    {
        njson spotify_auth;
        auto spotify_auth_filename = "spotify_auth.json";

        if (fs::exists(spotify_auth_filename))
        {
            spotify_auth = njson::parse(std::ifstream(spotify_auth_filename));

            if (Spotify::Auth::is_token_expired(spotify_auth["access_token"].get_ref<string&>()))
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

        auto spotify = Spotify::API(spotify_auth["access_token"].get_ref<string&>());

        auto me = spotify.get_current_user_profile();

        cout << me["display_name"] << " "
            << me["email"] << " "
            << me["id"] << " "
            << me["product"] << " "
            << endl;

        //cout << playlists.dump(3) << endl;
        size_t offset = 0;
        size_t count = 1;
        while (true)
        {
            auto playlists = spotify.get_current_user_playlists(10, offset);

            for (const auto& item : playlists["items"])
            {
                cout
                    << "[" << count++ << "] "
                    << item["name"]
                    << " by " << item["owner"]["display_name"]
                    << " - " << item["uri"]
                    << endl;
            }

            if (playlists["next"].is_null())
                break;

            offset += 10;
        }

        //auto play = spotify.get_currently_playing_track();

        //cout << play.dump(3) << endl;


        //if (not play.is_null() and
        //    play.find("error") == play.end())
        //{
        //    cout << "Currently playing song: "
        //        << play["item"]["name"] << " by "
        //        << play["item"]["artists"][0]["name"]
        //        << " on " << play["/device/name"_json_pointer]
        //        << endl;
        //}
        //else
        //{
        //    cout << "[ERR] "
        //        << play["/error/status"_json_pointer]
        //        << " " << play["/error/message"_json_pointer]
        //        << endl;
        //}

        //cout << spotify.skip_to_next() << endl;

        return 0;
    }
    catch (const std::exception& e)
    {
        cout << "[EXCEPTION] " << e.what() << endl;
        return 1;
    }
}
