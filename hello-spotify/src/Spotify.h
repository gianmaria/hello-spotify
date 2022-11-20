#pragma once

#include <format>
#include <fstream>
#include <iostream>
#include <random>
#include <string_view>
#include <string>
#include <vector>
#include <stdexcept>

using std::cout;
using std::endl;
using std::string;
using std::string_view;

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

namespace Spotify
{

struct Auth_Settings
{
    str client_id;
    str client_secret;

    str scope;

    str redirect_uri_host;
    uint16_t redirect_uri_port;
    str redirect_uri_path;
};

class Auth
{
public:
    Auth(const Auth_Settings& auth_settings)
        : auth_settings(auth_settings)
    { }

    string generate_url_for_user_authorization()
    {
        state = random_string(16);
        code_verifier = random_string(43);

        std::stringstream query_parameters;

        query_parameters << "client_id=" << auth_settings.client_id
            << "&response_type=" << "code"
            << "&redirect_uri=" << url_encode(get_redirect_uri())
            << "&state=" << state
            << "&scope=" << url_encode(auth_settings.scope)
            << "&show_dialog=" << "false"
            // PKCE stuff
            << "&code_challenge_method=" << "S256"
            << "&code_challenge=" << base64_url_encode_unpadded(sha256_raw(code_verifier))
            ;

        return std::format("https://{}/authorize?{}",
                           host, query_parameters.str());
    }

    string spawn_server_for_callback()
    {
        using httplib::Request;
        using httplib::Response;

        string auth_code;

        auto srv = httplib::Server();

        auto handle_callback =
            [&auth_code, this]
        (const Request& req, Response& resp)
        {
            if (req.has_param("code") and
                req.has_param("state"))
            {
                // the user accepted your request

                string resp_state = req.get_param_value("state");
                auth_code = req.get_param_value("code");

                if (not (resp_state == state))
                {
                    auto html = std::format(html_state_mismatch,
                                            auth_settings.redirect_uri_host,
                                            auth_settings.redirect_uri_port);
                    resp.set_content(html, "text/html");
                }
                else
                {
                    auto html = std::format(html_all_good,
                                            auth_settings.redirect_uri_host,
                                            auth_settings.redirect_uri_port);

                    resp.set_content(html, "text/html");
                }
            }
            else if (req.has_param("error") and
                     req.has_param("state"))
            {
                // the user doesn't accepted your request or an error has occurreded
                auto html = std::format(html_user_approval_denied_or_error,
                                        req.get_param_value("error"),
                                        auth_settings.redirect_uri_host,
                                        auth_settings.redirect_uri_port);

                resp.set_content(html, "text/html");
            }
            else
            {
                // something bad happened
                auto html = std::format(html_unknown_error,
                                        auth_settings.redirect_uri_host,
                                        auth_settings.redirect_uri_port);
                resp.set_content(html, "text/html");
            }
        };

        auto handle_stop = [&srv](const Request&,
                                  Response& resp)
        {
            resp.set_content(html_stop, "text/html");
            srv.stop();
        };

        srv.Get(auth_settings.redirect_uri_path, handle_callback);
        srv.Get("/stop", handle_stop);

        if (not srv.listen(auth_settings.redirect_uri_host, auth_settings.redirect_uri_port))
        {
            throw std::runtime_error(
                std::format("Cannot listen on {}:{}",
                auth_settings.redirect_uri_host, auth_settings.redirect_uri_port)
            );
        }

        return auth_code;
    }

    njson request_access_token(cstr_ref auth_code)
    {
        httplib::Headers headers
        {
            {"Authorization", "Basic " + base64_encode(
                auth_settings.client_id + ":" + auth_settings.client_secret)},
        };

        httplib::Params params
        {
            {"grant_type", "authorization_code"},
            {"code", auth_code},
            {"redirect_uri", get_redirect_uri()},

            {"client_id", auth_settings.client_id},
            {"code_verifier", code_verifier},
        };

        auto r = httplib::SSLClient(host);

        auto path = "/api/token";
        auto result = r.Post(path, headers, params);

        if (not result)
        {
            auto msg = std::format("Cannot POST to {}{} - {}",
                                   host, path, httplib::to_string(result.error()));
            throw std::runtime_error(msg);
        }

        auto resp = result.value();

        if (resp.status != 200)
        {
            auto msg = std::format("POST request '{}{}' failed, status '{}' reson '{}', body: {}",
                                   host, path, resp.status, resp.reason, resp.body);
            throw std::runtime_error(msg);
        }

        return njson::parse(resp.body);
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
            auto msg = std::format("Cannot POST to {}{} - {}",
                                   host, path, httplib::to_string(result.error()));
            throw std::runtime_error(msg);
        }

        auto resp = result.value();

        if (resp.status != 200)
        {
            auto msg = std::format("POST request '{}{}' failed, status '{}' reson '{}', body: {}",
                                   host, path, resp.status, resp.reason, resp.body);
            throw std::runtime_error(msg);
        }

        return njson::parse(resp.body);
    }

private:
    Auth_Settings auth_settings;

    string state;
    string code_verifier;

    static constexpr auto host = "accounts.spotify.com";

    static constexpr auto html_state_mismatch =
        R"(
<html>
    <title>Spotify Auth Error</title>
<body>
    <h1>Error, parameter 'state' sent to the server and parameter 'state' received from callback does not match</h1>
    <a href="http://{}:{}/stop">Click here to continue</a>
</body>
</html>
)";

    static constexpr auto html_user_approval_denied_or_error =
        R"(
<html>
    <title>Spotify Auth Error</title>
<body>
    <h1>Sorry, user did not accept your request: {}</h1>
    <a href="http://{}:{}/stop">Click here to continue</a>
</body>
</html>
)";

    static constexpr auto html_unknown_error =
        R"(
<html>
    <title>Spotify Auth Error</title>
<body>
    <h1>Unknown error</h1>
    <a href="http://{}:{}/stop">Click here to continue</a>
</body>
</html>
)";

    static constexpr auto html_all_good =
        R"(
<html>
    <title>Spotify Auth Success</title>
<body>
    <h1>Everything went good!</h1>
    <a href="http://{}:{}/stop">Click here to continue</a>
</body>
</html>
)";

    static constexpr auto html_stop =
        R"(
<html>
    <title>Spotify Auth</title>
<body>
    <h1>You can close the browser now</h1>
</body>
</html>
)";

    string get_redirect_uri()
    {
        std::stringstream ss;
        ss << "http://"
            << auth_settings.redirect_uri_host
            << ":"
            << auth_settings.redirect_uri_port
            << auth_settings.redirect_uri_path;

        return ss.str();
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

};

class API
{
public:

    struct Result
    {
        int status_code;
        str reason;

        njson body;
    };

    API(cstr_ref access_token) :
        access_token(access_token) {}

    Result get_current_user_profile()
    {
        return GET("/v1/me");
    }

    Result get_current_user_playlists(size_t limit, size_t offset)
    {
        auto path = std::format("/v1/me/playlists?limit={}&offset={}",
                                limit, offset);
        return GET(path);
    }

    Result get_currently_playing_track()
    {
        return GET("/v1/me/player/currently-playing");
    }

    Result skip_to_next(str_cref device_id = "")
    {
        str path = "/v1/me/player/next";

        if (device_id != "")
        {
            path = std::format("/v1/me/player/next?device_id={}",
                               device_id);
        }

        return POST(path);
    }

    static bool is_token_expired(cstr_ref access_token)
    {
        auto r = httplib::SSLClient(host);

        httplib::Headers headers
        {
            {"Content-Type", "application/json"},
            {"Authorization", "Bearer " + access_token},
        };

        auto path = "/v1/me";
        auto result = r.Get(path, headers);

        if (not result)
        {
            auto msg = std::format("Cannot GET to {}{} - {}",
                                   host, path, httplib::to_string(result.error()));
            throw std::runtime_error(msg);
        }

        switch (result.value().status)
        {
            case 200:
            {
                return false;
            } break;

            case 401:
            {
                return true;
            } break;

            default:
            {
                auto msg = std::format("Unknown status code for call to is_token_expired(): {}",
                                       result.value().status);
                throw std::runtime_error(msg);
            } break;
        }

    }

private:
    string access_token;

    static auto constexpr host = "api.spotify.com";

    Result GET(cstr_ref path)
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
            auto msg = std::format("GET {}{} failed: {}",
                                   host, path, httplib::to_string(result.error()));
            throw std::runtime_error(msg);
        }

        auto resp = result.value();

        return Result{
            .status_code = resp.status,
            .reason = resp.reason,
            .body = (resp.body != "") ? njson::parse(resp.body) : njson::parse("{}")
        };
    }

    Result POST(cstr_ref path)
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
            auto msg = std::format("POST {}{} failed: {}",
                                   host, path, httplib::to_string(result.error()));
            throw std::runtime_error(msg);
        }

        auto resp = result.value();

        return Result{
            .status_code = resp.status,
            .reason = resp.reason,
            .body = (resp.body != "") ? njson::parse(resp.body) : njson::parse("{}")
        };
    }

};

}

