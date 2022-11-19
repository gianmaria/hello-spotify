#pragma once

#include "pch.h"

namespace Spotify
{

class Auth
{
public:
    Auth(string client_id, string client_secret) :
        client_id(client_id), client_secret(client_secret)
    { }

    string generate_url_for_user_authorization()
    {
        state = random_string(16);
        code_verifier = random_string(43);

        auto scope = "ugc-image-upload user-read-playback-state user-modify-playback-state user-read-currently-playing app-remote-control streaming playlist-read-private playlist-read-collaborative playlist-modify-private playlist-modify-public user-follow-modify user-follow-read user-read-playback-position user-top-read user-read-recently-played user-library-modify user-library-read user-read-email user-read-private";

        std::stringstream ss;

        ss << "client_id=" << client_id
            << "&response_type=" << "code"
            << "&redirect_uri=" << url_encode(get_redirect_uri())
            << "&state=" << state
            << "&scope=" << url_encode(scope)
            // PKCE stuff
            << "&code_challenge_method=" << "S256"
            << "&code_challenge=" << base64_url_encode_unpadded(sha256_raw(code_verifier))
            << "&show_dialog=" << "false"
            ;

        auto url = "https://accounts.spotify.com/authorize?" + ss.str();

        return url;
    }

    string spawn_server_for_callback()
    {
        string auth_code;

        auto srv = httplib::Server();

        srv.Get(redirect_uri_path, [&]
        (const httplib::Request& req, httplib::Response& resp)
        {
            string resp_state;

        if (req.has_param("code"))
        {
            auth_code = req.get_param_value("code");
        }

        if (req.has_param("state"))
        {
            resp_state = req.get_param_value("state");
        }

        if (resp_state == state)
        {
            constexpr auto fmt = R"(
                        <html>
                        <title>Spotify</title>
                        <body>
                        <h1><a href="http://{}:{}/stop">Click here to continue</a></h1>
                        </body>
                        </html>
                        )";

            auto html = std::format(fmt,
                                    redirect_uri_host,
                                    redirect_uri_port);

            resp.set_content(html, "text/html");
        }
        else
        {
            constexpr auto fmt = R"(
                        <html>
                        <title>Error</title>
                        <body>
                        <h1><a href="http://{}:{}/stop">Sadge</a></h1>
                        </body>
                        </html>
                        )";
            auto html = std::format(fmt,
                                    redirect_uri_host,
                                    redirect_uri_port);

            resp.set_content(html, "text/html");
        }
        });

        srv.Get("/stop",
                [&srv](const httplib::Request&, httplib::Response&)
        {
            srv.stop();
        });

        if (not srv.listen(redirect_uri_host, redirect_uri_port))
        {
            return {};
        }

        return auth_code;
    }

    njson request_access_token(cstr_ref auth_code)
    {
        httplib::Headers headers
        {
            {"Authorization", "Basic " + base64_encode(client_id + ":" + client_secret)},
        };

        httplib::Params params
        {
            {"grant_type", "authorization_code"},
            {"code", auth_code},
            {"redirect_uri", get_redirect_uri()},

            {"client_id", client_id},
            {"code_verifier", code_verifier},
        };

        auto r = httplib::SSLClient(host);
        auto path = "/api/token";
        auto res = r.Post(path, headers, params);

        if (not res)
        {
            cout
                << "[ERROR]" << endl
                << "  POST request " << host << path << " failed" << endl
                << "  '" << httplib::to_string(res.error()) << "'" << endl
                ;
            return {};
        }

        auto resp = res.value();

        if (resp.status != 200)
        {
            cout
                << "[ERROR]" << endl
                << "  POST request: '" << host << path << "'" << endl
                << "  " << resp.status << " " << resp.reason << endl
                << "  '" << resp.body << "'" << endl
                ;
            return {};
        }

        return njson::parse(resp.body);
    }

    static string get_redirect_uri()
    {
        std::stringstream ss;
        ss << "http://"
            << redirect_uri_host
            << ":"
            << redirect_uri_port
            << redirect_uri_path;

        return ss.str();
    }

    static njson refresh_access_token(cstr_ref client_id,
                                      cstr_ref refresh_token)
    {
        httplib::Headers headers
        {
        };

        httplib::Params params
        {
            {"grant_type", "refresh_token"},
            {"refresh_token", refresh_token},
            // for PKCE
            {"client_id", client_id},
        };

        auto r = httplib::SSLClient(host);
        auto path = "/api/token";
        auto result = r.Post(path, headers, params);

        if (not result)
        {
            cout
                << "[ERROR]" << endl
                << "  POST request " << host << path << endl
                << "  failed with reason: " << httplib::to_string(result.error()) << endl
                ;
            return {};
        }

        auto resp = result.value();

        if (resp.status != 200)
        {
            cout
                << "[ERROR]" << endl
                << "  POST request: '" << host << path << "'" << endl
                << "  " << resp.status << " " << resp.reason << endl
                << "  '" << resp.body << "'" << endl
                ;
            return {};
        }

        return njson::parse(resp.body);
    }

    static bool is_token_expired(cstr_ref access_token)
    {
        auto r = httplib::SSLClient(host);

        httplib::Headers headers
        {
            {"Content-Type", "application/json"},
            {"Authorization", "Bearer " + access_token},
        };

        auto result = r.Get("/v1/me", headers);

        if (not result)
        {
            return true;
        }

        return (result.value().status == 401);
    }

    static int random_int(int min, int max)
    {
        static std::random_device random_device;
        static std::mt19937 random_engine(random_device());
        static std::uniform_int_distribution distrib(min, max);

        return distrib(random_engine);
    }

    static string random_string(uint8_t len)
    {
        auto alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-~";
        auto max = strlen(alphabet);

        string res;
        res.reserve(len);

        for (uint8_t i = 0;
             i < len;
             ++i)
        {
            auto c = alphabet[random_int(0, max - 1)];
            res.append(1, c);
        }

        return res;
    }

    static bytes sha256_raw(cstr_ref input)
    {
        bytes hash(picosha2::k_digest_size);
        picosha2::hash256(input, hash);
        return hash;
    }

    static str sha256_str(cstr_ref input)
    {
        return picosha2::hash256_hex_string(input);
    }

    static string url_encode(cstr_ref url)
    {
        // https://en.wikipedia.org/wiki/Percent-encoding#Reserved_characters
        std::unordered_map<char, string> map
        {
            {' ', "%20"},
            {'!', "%21"},
            {'#', "%23"},
            {'$', "%24"},
            {'%', "%25"},
            {'&', "%26"},
            {'\'', "%27"},
            {'(', "%28"},
            {')', "%29"},
            {'*', "%2A"},
            {'+', "%2B"},
            {',', "%2C"},
            {'/', "%2F"},
            {':', "%3A"},
            {';', "%3B"},
            {'=', "%3D"},
            {'?', "%3F"},
            {'@', "%40"},
            {'[', "%5B"},
            {']', "%5D"}
        };

        string encoded;
        encoded.reserve(url.size() * 2);

        for (auto c : url)
        {
            if (auto it = map.find(c); it != map.end())
            {
                encoded.append((*it).second);
            }
            else
            {
                encoded.append(1, c);
            }
        }

        return encoded;
    }

    static string base64_encode(cstr_ref input)
    {
        return cppcodec::base64_rfc4648::encode<string>(input);
    }

    static string base64_url_encode_unpadded(const bytes& input)
    {
        return cppcodec::base64_url_unpadded::encode<string>(input);
    }

    static string base64_url_encode(const bytes& input)
    {
        return cppcodec::base64_url_unpadded::encode<string>(input);
    }


private:
    string client_id;
    string client_secret;

    string state;
    string code_verifier;

    static constexpr auto host = "accounts.spotify.com";

    static constexpr auto redirect_uri_host = "localhost";
    static constexpr auto redirect_uri_port = 6969;
    static constexpr auto redirect_uri_path = "/spotify-callback";
};


class API
{
public:

    API(cstr_ref access_token) :
        access_token(access_token) {}

    njson get_current_user_profile()
    {
        return get("/v1/me");
    }

    njson get_current_user_playlists(size_t limit, size_t offset)
    {
        auto path = std::format("/v1/me/playlists?limit={}&offset={}",
                                limit, offset);
        return get(path);
    }

    njson get_currently_playing_track()
    {
        return get("/v1/me/player/currently-playing");
    }

    njson skip_to_next()
    {
        return post("/v1/me/player/next");
    }

private:
    string access_token;

    static auto constexpr host = "api.spotify.com";

    njson get(cstr_ref path)
    {
        static auto r = httplib::SSLClient(host);
        static httplib::Headers headers
        {
            {"Accept", "application/json"},
            {"Content-Type", "application/json"},
            {"Authorization", "Bearer " + access_token},
        };

        auto result = r.Get(path, headers);

        if (not result)
        {
            njson json;
            json["error"] = {{"message", httplib::to_string(result.error())}};
            json["error"].push_back({{"status", ""}});
            return json;
        }

        auto resp = result.value();

        switch (resp.status)
        {
            case 204:
            {
                njson json;
                json["error"] = {
                    {"message", resp.reason},
                    {"status", resp.status}
                };
                return json;
            } break;

            default: return njson::parse(resp.body);
        }
    }

    njson post(cstr_ref path)
    {
        static auto r = httplib::SSLClient(host);
        static httplib::Headers headers
        {
            {"Accept", "application/json"},
            {"Content-Type", "application/json"},
            {"Authorization", "Bearer " + access_token},
        };

        static httplib::Params params
        {

        };

        auto result = r.Post(path, headers, params);

        if (not result)
        {
            njson json{
                "error", {
                    {"message", httplib::to_string(result.error())},
                {"status", "" }
            }
            };
            return json;
        }

        auto resp = result.value();

        switch (resp.status)
        {
            case 204:
            {
                njson json;
                json["error"] = {
                    {"message", resp.reason},
                    {"status", resp.status}
                };
                return json;
            } break;

            default: return njson::parse(resp.body);
        }
    }

};

}
