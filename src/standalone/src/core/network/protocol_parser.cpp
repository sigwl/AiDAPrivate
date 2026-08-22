#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "protocol_parser.hpp"
#include "helpers/diag_log.hpp"

#include <zlib.h>
#include <brotli/decode.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>
#include <utility>

namespace protocol_parser {

namespace {
constexpr size_t kMaxDecompressedBodyBytes = 64u * 1024u * 1024u;
constexpr size_t kMaxHpackStringBytes = 1u * 1024u * 1024u;
constexpr size_t kMaxHpackFields = 65536;
}


static std::string to_lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

static bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

static size_t find_crlf(const uint8_t* data, size_t len, size_t start = 0) {
    for (size_t i = start; i + 1 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') return i;
    }
    return std::string::npos;
}

static std::string make_string(const uint8_t* data, size_t len) {
    return std::string(reinterpret_cast<const char*>(data), len);
}

static std::string escaped_preview(const std::string& s, size_t cap = 96) {
    std::string out;
    const size_t n = std::min(s.size(), cap);
    out.reserve(n + 16);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\r') out += "\\r";
        else if (c == '\n') out += "\\n";
        else if (c == '\t') out += "\\t";
        else if (c >= 0x20 && c <= 0x7E) out.push_back(static_cast<char>(c));
        else {
            char b[5];
            std::snprintf(b, sizeof(b), "\\x%02X", static_cast<unsigned>(c));
            out += b;
        }
    }
    if (s.size() > n)
        out += "...";
    return out;
}

static std::string hex_preview(const std::string& s, size_t cap = 48) {
    std::string out;
    const size_t n = std::min(s.size(), cap);
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02X", static_cast<unsigned>(static_cast<unsigned char>(s[i])));
        if (!out.empty())
            out.push_back(' ');
        out += b;
    }
    if (s.size() > n)
        out += " ...";
    return out;
}

static bool is_ows(char c) {
    return c == ' ' || c == '\t';
}

static std::string trim_ows(std::string s) {
    size_t first = 0;
    while (first < s.size() && is_ows(s[first])) ++first;
    size_t last = s.size();
    while (last > first && is_ows(s[last - 1])) --last;
    return s.substr(first, last - first);
}

static bool is_tchar(char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (std::isalnum(uc)) return true;
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
        return true;
    default:
        return false;
    }
}

static bool valid_token(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!is_tchar(c)) return false;
    }
    return true;
}

static bool parse_decimal_size(const std::string& raw, size_t& out) {
    std::string s = trim_ows(raw);
    if (s.empty()) return false;
    size_t value = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        size_t digit = static_cast<size_t>(c - '0');
        if (value > (std::numeric_limits<size_t>::max() - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

static bool parse_hex_size(const std::string& raw, size_t& out) {
    std::string s = trim_ows(raw);
    if (s.empty()) return false;
    size_t value = 0;
    for (char c : s) {
        size_t digit;
        if (c >= '0' && c <= '9')
            digit = static_cast<size_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            digit = static_cast<size_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            digit = static_cast<size_t>(c - 'A' + 10);
        else
            return false;
        if (value > (std::numeric_limits<size_t>::max() - digit) / 16)
            return false;
        value = value * 16 + digit;
    }
    out = value;
    return true;
}

struct header_parse_result {
    bool complete = false;
    bool valid = true;
};

static header_parse_result parse_headers(const uint8_t* data, size_t len, size_t& pos,
                                         std::vector<http_header>& headers) {
    size_t start_pos = pos;
    size_t header_index = headers.size();
    diag::log_tagged_fmt("proto", "parse_headers start pos=%zu len=%zu existing=%zu", pos, len, headers.size());
    while (pos + 1 < len) {
        if (data[pos] == '\r' && data[pos + 1] == '\n') {
            pos += 2;
            diag::log_tagged_fmt("proto", "parse_headers complete start=%zu end=%zu added=%zu", start_pos, pos, headers.size() - header_index);
            return { true, true };
        }
        size_t eol = find_crlf(data, len, pos);
        if (eol == std::string::npos) {
            diag::log_tagged_fmt("proto", "parse_headers incomplete pos=%zu remaining=%zu", pos, len - pos);
            return { false, true };
        }

        std::string line = make_string(data + pos, eol - pos);
        pos = eol + 2;

        if (!line.empty() && is_ows(line[0])) {
            if (headers.empty()) {
                diag::log_tagged("proto", "parse_headers invalid obs_fold_without_previous");
                return { true, false };
            }
            std::string folded = trim_ows(line);
            if (!folded.empty()) {
                if (!headers.back().value.empty())
                    headers.back().value.push_back(' ');
                headers.back().value += folded;
                diag::log_tagged_fmt("proto", "parse_headers obs_fold name=%s appended_len=%zu total_value_len=%zu",
                    headers.back().name.c_str(),
                    folded.size(),
                    headers.back().value.size());
            }
            continue;
        }

        size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0) {
            diag::log_tagged_fmt("proto", "parse_headers invalid_line colon=%lld line_len=%zu line=\"%s\" hex=%s",
                colon == std::string::npos ? -1LL : static_cast<long long>(colon),
                line.size(),
                escaped_preview(line).c_str(),
                hex_preview(line).c_str());
            return { true, false };
        }

        http_header hdr;
        hdr.name = line.substr(0, colon);
        if (!valid_token(hdr.name)) {
            diag::log_tagged_fmt("proto", "parse_headers invalid_name name_len=%zu", hdr.name.size());
            return { true, false };
        }
        size_t val_start = colon + 1;
        while (val_start < line.size() && is_ows(line[val_start])) val_start++;
        hdr.value = trim_ows(line.substr(val_start));
        diag::log_tagged_fmt("proto", "parse_headers header index=%zu name=%s value_len=%zu",
            headers.size(),
            hdr.name.c_str(),
            hdr.value.size());
        headers.push_back(std::move(hdr));
    }
    diag::log_tagged_fmt("proto", "parse_headers incomplete_tail pos=%zu len=%zu added=%zu", pos, len, headers.size() - header_index);
    return { false, true };
}

struct content_length_parse_result {
    bool present = false;
    bool valid = true;
    size_t value = 0;
};

static content_length_parse_result parse_content_lengths(const std::vector<http_header>& headers) {
    content_length_parse_result result;
    size_t matches = 0;
    for (const auto& h : headers) {
        if (!iequals(h.name, "Content-Length")) continue;
        ++matches;
        size_t start = 0;
        while (start <= h.value.size()) {
            size_t comma = h.value.find(',', start);
            std::string part = h.value.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            size_t parsed = 0;
            if (!parse_decimal_size(part, parsed)) {
                result.valid = false;
                diag::log_tagged_fmt("proto", "parse_content_lengths invalid token_index=%zu raw_len=%zu", matches, part.size());
                return result;
            }
            if (!result.present) {
                result.present = true;
                result.value = parsed;
            } else if (result.value != parsed) {
                result.valid = false;
                diag::log_tagged_fmt("proto", "parse_content_lengths conflict expected=%zu actual=%zu", result.value, parsed);
                return result;
            }
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    }
    diag::log_tagged_fmt("proto", "parse_content_lengths present=%d valid=%d value=%zu headers=%zu",
        static_cast<int>(result.present),
        static_cast<int>(result.valid),
        result.value,
        matches);
    return result;
}

struct transfer_encoding_parse_result {
    bool present = false;
    bool chunked = false;
    bool valid = true;
};

static transfer_encoding_parse_result parse_transfer_encoding(const std::vector<http_header>& headers) {
    transfer_encoding_parse_result result;
    std::vector<std::string> codings;
    size_t header_matches = 0;
    for (const auto& h : headers) {
        if (!iequals(h.name, "Transfer-Encoding")) continue;
        result.present = true;
        ++header_matches;
        size_t start = 0;
        while (start <= h.value.size()) {
            size_t comma = h.value.find(',', start);
            std::string part = trim_ows(h.value.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
            size_t semi = part.find(';');
            std::string token = to_lower(trim_ows(part.substr(0, semi)));
            if (token.empty() || !valid_token(token)) {
                result.valid = false;
                diag::log_tagged_fmt("proto", "parse_transfer_encoding invalid token_len=%zu headers=%zu", token.size(), header_matches);
                return result;
            }
            diag::log_tagged_fmt("proto", "parse_transfer_encoding coding index=%zu token=%s", codings.size(), token.c_str());
            codings.push_back(token);
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    }
    size_t chunked_count = 0;
    for (size_t i = 0; i < codings.size(); ++i) {
        if (codings[i] == "chunked") {
            result.chunked = true;
            ++chunked_count;
            if (i + 1 != codings.size()) result.valid = false;
        }
    }
    if (chunked_count > 1) result.valid = false;
    diag::log_tagged_fmt("proto", "parse_transfer_encoding present=%d valid=%d chunked=%d codings=%zu",
        static_cast<int>(result.present),
        static_cast<int>(result.valid),
        static_cast<int>(result.chunked),
        codings.size());
    return result;
}

struct chunked_decode_result {
    std::vector<uint8_t> body;
    bool complete = false;
    bool valid = true;
    size_t consumed = 0;
};

static chunked_decode_result decode_chunked(const uint8_t* data, size_t len) {
    chunked_decode_result result;
    size_t pos = 0;
    size_t chunk_index = 0;
    diag::log_tagged_fmt("proto", "decode_chunked start len=%zu", len);
    while (pos < len) {
        size_t eol = find_crlf(data, len, pos);
        if (eol == std::string::npos) {
            result.consumed = len;
            diag::log_tagged_fmt("proto", "decode_chunked incomplete_size_line pos=%zu len=%zu chunks=%zu", pos, len, chunk_index);
            return result;
        }

        std::string chunk_sz_str = make_string(data + pos, eol - pos);
        size_t ext_pos = chunk_sz_str.find(';');
        if (ext_pos != std::string::npos) chunk_sz_str.resize(ext_pos);

        size_t chunk_sz = 0;
        if (!parse_hex_size(chunk_sz_str, chunk_sz)) {
            result.valid = false;
            result.consumed = pos;
            diag::log_tagged_fmt("proto", "decode_chunked invalid_size chunk=%zu raw_len=%zu pos=%zu", chunk_index, chunk_sz_str.size(), pos);
            return result;
        }

        pos = eol + 2;
        diag::log_tagged_fmt("proto", "decode_chunked chunk=%zu size=%zu data_pos=%zu", chunk_index, chunk_sz, pos);
        if (chunk_sz == 0) {
            std::vector<http_header> trailers;
            size_t trailer_pos = pos;
            auto trailers_result = parse_headers(data, len, trailer_pos, trailers);
            if (!trailers_result.valid) {
                result.valid = false;
                result.consumed = trailer_pos;
                diag::log_tagged_fmt("proto", "decode_chunked invalid_trailers pos=%zu trailers=%zu", trailer_pos, trailers.size());
                return result;
            }
            if (!trailers_result.complete) {
                result.consumed = len;
                diag::log_tagged_fmt("proto", "decode_chunked incomplete_trailers pos=%zu len=%zu trailers=%zu", pos, len, trailers.size());
                return result;
            }
            result.complete = true;
            result.consumed = trailer_pos;
            diag::log_tagged_fmt("proto", "decode_chunked complete chunks=%zu body=%zu trailers=%zu consumed=%zu",
                chunk_index,
                result.body.size(),
                trailers.size(),
                result.consumed);
            return result;
        }
        if (chunk_sz > len - pos) {
            result.consumed = len;
            diag::log_tagged_fmt("proto", "decode_chunked incomplete_data chunk=%zu need=%zu have=%zu", chunk_index, chunk_sz, len - pos);
            return result;
        }

        result.body.insert(result.body.end(), data + pos, data + pos + chunk_sz);
        pos += chunk_sz;
        if (pos + 1 >= len) {
            result.consumed = len;
            diag::log_tagged_fmt("proto", "decode_chunked incomplete_crlf chunk=%zu pos=%zu len=%zu", chunk_index, pos, len);
            return result;
        }
        if (data[pos] != '\r' || data[pos + 1] != '\n') {
            result.valid = false;
            result.consumed = pos;
            diag::log_tagged_fmt("proto", "decode_chunked invalid_chunk_crlf chunk=%zu pos=%zu", chunk_index, pos);
            return result;
        }
        pos += 2;
        ++chunk_index;
    }
    result.consumed = pos;
    diag::log_tagged_fmt("proto", "decode_chunked incomplete_no_zero chunks=%zu body=%zu consumed=%zu", chunk_index, result.body.size(), result.consumed);
    return result;
}

static bool response_status_has_body(int status_code) {
    if (status_code >= 100 && status_code < 200) return false;
    return status_code != 204 && status_code != 304;
}

static bool valid_http_version(const std::string& version) {
    if (version.rfind("HTTP/", 0) != 0) return false;
    size_t dot = version.find('.', 5);
    if (dot == std::string::npos || dot == 5 || dot + 1 >= version.size()) return false;
    for (size_t i = 5; i < version.size(); ++i) {
        if (i == dot) continue;
        if (!std::isdigit(static_cast<unsigned char>(version[i]))) return false;
    }
    return true;
}

http_request parse_http_request(const uint8_t* data, size_t len) {
    diag::log_tagged_fmt("proto", "parse_http_request entry len=%zu", len);
    http_request req;
    if (!data || len == 0) {
        diag::log_tagged_fmt("proto", "parse_http_request too short len=%zu", len);
        return req;
    }

    size_t first_eol = find_crlf(data, len);
    if (first_eol == std::string::npos) {
        diag::log_tagged("proto", "parse_http_request no CRLF found");
        return req;
    }

    std::string request_line = make_string(data, first_eol);
    size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos) {
        diag::log_tagged_fmt("proto", "parse_http_request invalid request line: %s", request_line.c_str());
        return req;
    }
    size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos ||
        request_line.find(' ', sp2 + 1) != std::string::npos) {
        diag::log_tagged_fmt("proto", "parse_http_request invalid request line: %s", request_line.c_str());
        return req;
    }

    req.method = request_line.substr(0, sp1);
    req.uri = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = request_line.substr(sp2 + 1);
    diag::log_tagged_fmt("proto", "parse_http_request method=%s uri=%s version=%s", req.method.c_str(), req.uri.c_str(), req.version.c_str());

    if (!valid_token(req.method) || req.uri.empty() || !valid_http_version(req.version)) {
        diag::log_tagged_fmt("proto", "parse_http_request invalid start line fields method=%s uri=%s version=%s", req.method.c_str(), req.uri.c_str(), req.version.c_str());
        return req;
    }

    req.valid = true;
    size_t pos = first_eol + 2;

    auto headers_result = parse_headers(data, len, pos, req.headers);
    if (!headers_result.valid) {
        diag::log_tagged_fmt("proto", "parse_http_request malformed headers headers_count=%zu", req.headers.size());
        req.valid = false;
        req.complete = false;
        req.total_consumed = len;
        return req;
    }
    if (!headers_result.complete) {
        diag::log_tagged_fmt("proto", "parse_http_request parse_headers incomplete headers_count=%zu", req.headers.size());
        req.complete = false;
        req.total_consumed = len;
        return req;
    }
    diag::log_tagged_fmt("proto", "parse_http_request headers_count=%zu", req.headers.size());

    auto cl = parse_content_lengths(req.headers);
    auto te = parse_transfer_encoding(req.headers);
    if (!cl.valid || !te.valid || (te.present && cl.present) || (te.present && !te.chunked)) {
        diag::log_tagged_fmt("proto", "parse_http_request invalid framing cl_present=%d cl_valid=%d te_present=%d te_valid=%d te_chunked=%d",
            (int)cl.present, (int)cl.valid, (int)te.present, (int)te.valid, (int)te.chunked);
        req.valid = false;
        req.complete = false;
        req.total_consumed = len;
        return req;
    }

    if (te.chunked) {
        size_t body_start = pos;
        auto decoded = decode_chunked(data + body_start, len - body_start);
        if (!decoded.valid) {
            req.valid = false;
            req.complete = false;
            req.total_consumed = body_start + decoded.consumed;
            diag::log_tagged("proto", "parse_http_request invalid chunked body");
            return req;
        }
        req.body = std::move(decoded.body);
        req.complete = decoded.complete;
        req.total_consumed = decoded.complete ? body_start + decoded.consumed : len;
        diag::log_tagged_fmt("proto", "parse_http_request chunked body body_size=%zu", req.body.size());
    } else if (cl.present) {
        if (cl.value <= len - pos) {
            req.body.assign(data + pos, data + pos + cl.value);
            req.complete = true;
            req.total_consumed = pos + cl.value;
            diag::log_tagged_fmt("proto", "parse_http_request content-length body cl=%zu complete=true", cl.value);
        } else {
            req.body.assign(data + pos, data + len);
            req.complete = false;
            req.total_consumed = len;
            diag::log_tagged_fmt("proto", "parse_http_request content-length body partial cl=%zu have=%zu", cl.value, len - pos);
        }
    } else {
        req.complete = true;
        req.total_consumed = pos;
        diag::log_tagged("proto", "parse_http_request no body");
    }
    diag::log_tagged_fmt("proto", "parse_http_request result valid=%d complete=%d method=%s uri=%s body_size=%zu", (int)req.valid, (int)req.complete, req.method.c_str(), req.uri.c_str(), req.body.size());
    return req;
}

http_response parse_http_response(const uint8_t* data, size_t len) {
    diag::log_tagged_fmt("proto", "parse_http_response entry len=%zu", len);
    http_response resp;
    if (!data || len == 0) {
        diag::log_tagged_fmt("proto", "parse_http_response too short len=%zu", len);
        return resp;
    }

    size_t first_eol = find_crlf(data, len);
    if (first_eol == std::string::npos) {
        diag::log_tagged("proto", "parse_http_response no CRLF found");
        return resp;
    }

    std::string status_line = make_string(data, first_eol);
    if (status_line.substr(0, 5) != "HTTP/") {
        diag::log_tagged_fmt("proto", "parse_http_response invalid status line: %.40s", status_line.c_str());
        return resp;
    }

    size_t sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) {
        diag::log_tagged("proto", "parse_http_response no space in status line");
        return resp;
    }
    size_t sp2 = status_line.find(' ', sp1 + 1);

    resp.version = status_line.substr(0, sp1);
    std::string code_str = (sp2 != std::string::npos)
        ? status_line.substr(sp1 + 1, sp2 - sp1 - 1)
        : status_line.substr(sp1 + 1);

    if (!valid_http_version(resp.version) || code_str.size() != 3 ||
        !std::isdigit(static_cast<unsigned char>(code_str[0])) ||
        !std::isdigit(static_cast<unsigned char>(code_str[1])) ||
        !std::isdigit(static_cast<unsigned char>(code_str[2]))) {
        diag::log_tagged_fmt("proto", "parse_http_response invalid status/version status=%s version=%s", code_str.c_str(), resp.version.c_str());
        return resp;
    }
    resp.status_code = (code_str[0] - '0') * 100 + (code_str[1] - '0') * 10 + (code_str[2] - '0');
    if (sp2 != std::string::npos) resp.reason = status_line.substr(sp2 + 1);
    diag::log_tagged_fmt("proto", "parse_http_response status_code=%d reason=%s version=%s", resp.status_code, resp.reason.c_str(), resp.version.c_str());

    resp.valid = true;
    size_t pos = first_eol + 2;

    auto headers_result = parse_headers(data, len, pos, resp.headers);
    if (!headers_result.valid) {
        diag::log_tagged_fmt("proto", "parse_http_response malformed headers headers_count=%zu", resp.headers.size());
        resp.valid = false;
        resp.complete = false;
        resp.total_consumed = len;
        return resp;
    }
    if (!headers_result.complete) {
        diag::log_tagged_fmt("proto", "parse_http_response parse_headers incomplete headers_count=%zu", resp.headers.size());
        resp.complete = false;
        resp.total_consumed = len;
        return resp;
    }
    diag::log_tagged_fmt("proto", "parse_http_response headers_count=%zu", resp.headers.size());

    if (!response_status_has_body(resp.status_code)) {
        resp.complete = true;
        resp.total_consumed = pos;
        diag::log_tagged_fmt("proto", "parse_http_response no-body status=%d", resp.status_code);
        return resp;
    }

    auto cl = parse_content_lengths(resp.headers);
    auto te = parse_transfer_encoding(resp.headers);
    if (!cl.valid || !te.valid || (te.present && cl.present)) {
        diag::log_tagged_fmt("proto", "parse_http_response invalid framing cl_present=%d cl_valid=%d te_present=%d te_valid=%d te_chunked=%d",
            (int)cl.present, (int)cl.valid, (int)te.present, (int)te.valid, (int)te.chunked);
        resp.valid = false;
        resp.complete = false;
        resp.total_consumed = len;
        return resp;
    }

    if (te.chunked) {
        auto decoded = decode_chunked(data + pos, len - pos);
        if (!decoded.valid) {
            resp.valid = false;
            resp.complete = false;
            resp.total_consumed = pos + decoded.consumed;
            diag::log_tagged("proto", "parse_http_response invalid chunked body");
            return resp;
        }
        resp.body = std::move(decoded.body);
        resp.complete = decoded.complete;
        resp.total_consumed = decoded.complete ? pos + decoded.consumed : len;
        diag::log_tagged_fmt("proto", "parse_http_response chunked body body_size=%zu", resp.body.size());
    } else if (te.present) {
        resp.body.assign(data + pos, data + len);
        resp.complete = true;
        resp.total_consumed = len;
        diag::log_tagged_fmt("proto", "parse_http_response close-delimited transfer coding body_size=%zu", resp.body.size());
    } else if (cl.present) {
        if (cl.value <= len - pos) {
            resp.body.assign(data + pos, data + pos + cl.value);
            resp.complete = true;
            resp.total_consumed = pos + cl.value;
            diag::log_tagged_fmt("proto", "parse_http_response content-length body cl=%zu complete=true", cl.value);
        } else {
            resp.body.assign(data + pos, data + len);
            resp.complete = false;
            resp.total_consumed = len;
            diag::log_tagged_fmt("proto", "parse_http_response content-length partial cl=%zu have=%zu", cl.value, len - pos);
        }
    } else {
        resp.body.assign(data + pos, data + len);
        resp.complete = true;
        resp.total_consumed = len;
        diag::log_tagged_fmt("proto", "parse_http_response no cl/te body_size=%zu complete=%d", resp.body.size(), (int)resp.complete);
    }
    diag::log_tagged_fmt("proto", "parse_http_response result valid=%d complete=%d status=%d body_size=%zu", (int)resp.valid, (int)resp.complete, resp.status_code, resp.body.size());
    return resp;
}

std::string find_header(const std::vector<http_header>& headers, const std::string& name) {
    diag::log_tagged_fmt("proto", "find_header name=%s headers_count=%zu", name.c_str(), headers.size());
    for (auto& h : headers) {
        if (iequals(h.name, name)) {
            diag::log_tagged_fmt("proto", "find_header found name=%s value=%s", name.c_str(), h.value.c_str());
            return h.value;
        }
    }
    diag::log_tagged_fmt("proto", "find_header not found name=%s", name.c_str());
    return {};
}

std::vector<uint8_t> decompress_body(const std::vector<uint8_t>& body, const std::string& encoding) {
    diag::log_tagged_fmt("proto", "decompress_body entry encoding=%s body_size=%zu", encoding.c_str(), body.size());
    std::string enc = to_lower(encoding);

    if (enc == "gzip" || enc == "deflate" || enc == "x-gzip") {
        diag::log_tagged_fmt("proto", "decompress_body gzip/deflate branch enc=%s", enc.c_str());
        if (body.empty()) {
            diag::log_tagged("proto", "decompress_body empty body returning as-is");
            return body;
        }
        if (body.size() > static_cast<size_t>((std::numeric_limits<uInt>::max)()))
            return body;

        z_stream strm = {};
        strm.next_in = const_cast<Bytef*>(body.data());
        strm.avail_in = static_cast<uInt>(body.size());


        int window_bits = 15 + 32;
        if (inflateInit2(&strm, window_bits) != Z_OK) {
            diag::log_tagged("proto", "decompress_body inflateInit2 failed");
            return body;
        }

        std::vector<uint8_t> result;
        result.reserve(body.size() > kMaxDecompressedBodyBytes / 4
            ? kMaxDecompressedBodyBytes : body.size() * 4);

        uint8_t out_buf[16384];
        int ret;
        do {
            strm.next_out = out_buf;
            strm.avail_out = sizeof(out_buf);
            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR || ret == Z_BUF_ERROR) {
                diag::log_tagged_fmt("proto", "decompress_body inflate error ret=%d", ret);
                inflateEnd(&strm);
                return body;
            }
            size_t have = sizeof(out_buf) - strm.avail_out;
            if (ret != Z_STREAM_END && have == 0) {
                inflateEnd(&strm);
                return body;
            }
            if (have > kMaxDecompressedBodyBytes - result.size()) {
                diag::log_tagged_fmt("proto", "decompress_body output_limit input=%zu limit=%zu", body.size(), kMaxDecompressedBodyBytes);
                inflateEnd(&strm);
                return body;
            }
            result.insert(result.end(), out_buf, out_buf + have);
        } while (ret != Z_STREAM_END);

        inflateEnd(&strm);
        diag::log_tagged_fmt("proto", "decompress_body gzip success input=%zu output=%zu", body.size(), result.size());
        return result;
    }

    if (enc == "br") {
        diag::log_tagged_fmt("proto", "decompress_body brotli branch input=%zu", body.size());
        std::vector<uint8_t> result;
        result.reserve(body.size() > kMaxDecompressedBodyBytes / 4
            ? kMaxDecompressedBodyBytes : body.size() * 4);

        BrotliDecoderState* bs = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        if (!bs) {
            diag::log_tagged("proto", "decompress_body BrotliDecoderCreateInstance failed");
            return body;
        }

        const uint8_t* next_in = body.data();
        size_t avail_in = body.size();
        uint8_t out_buf[16384];
        size_t total_out = 0;

        BrotliDecoderResult br_res = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;
        while (br_res == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT ||
               br_res == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
            size_t avail_out = sizeof(out_buf);
            uint8_t* next_out = out_buf;
            const size_t before = total_out;
            const size_t input_before = avail_in;
            br_res = BrotliDecoderDecompressStream(bs, &avail_in, &next_in,
                &avail_out, &next_out, &total_out);
            const size_t produced = total_out - before;
            if (produced > kMaxDecompressedBodyBytes - result.size()) {
                diag::log_tagged_fmt("proto", "decompress_body brotli_output_limit input=%zu limit=%zu", body.size(), kMaxDecompressedBodyBytes);
                BrotliDecoderDestroyInstance(bs);
                return body;
            }
            result.insert(result.end(), out_buf, out_buf + produced);
            if (br_res == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && input_before == avail_in) {
                BrotliDecoderDestroyInstance(bs);
                return body;
            }
        }

        BrotliDecoderDestroyInstance(bs);

        if (br_res == BROTLI_DECODER_RESULT_SUCCESS) {
            diag::log_tagged_fmt("proto", "decompress_body brotli success input=%zu output=%zu", body.size(), total_out);
            return result;
        }
        diag::log_tagged_fmt("proto", "decompress_body brotli failed result=%d", (int)br_res);
        return body;
    }

    diag::log_tagged_fmt("proto", "decompress_body unknown encoding=%s returning as-is", encoding.c_str());
    return body;
}

content_type_t detect_content_type(const std::vector<http_header>& headers) {
    diag::log_tagged_fmt("proto", "detect_content_type headers_count=%zu", headers.size());
    std::string ct = to_lower(find_header(headers, "Content-Type"));
    if (ct.empty()) {
        diag::log_tagged("proto", "detect_content_type no Content-Type header -> unknown");
        return content_type_t::unknown;
    }
    content_type_t result = content_type_t::binary;
    if (ct.find("application/json") != std::string::npos) result = content_type_t::json;
    else if (ct.find("text/xml") != std::string::npos || ct.find("application/xml") != std::string::npos)
        result = content_type_t::xml;
    else if (ct.find("text/html") != std::string::npos) result = content_type_t::html;
    else if (ct.find("text/") != std::string::npos) result = content_type_t::text;
    else if (ct.find("application/x-www-form-urlencoded") != std::string::npos)
        result = content_type_t::form_urlencoded;
    else if (ct.find("multipart/") != std::string::npos) result = content_type_t::multipart;
    diag::log_tagged_fmt("proto", "detect_content_type ct=%s result=%s", ct.c_str(), content_type_name(result).c_str());
    return result;
}

std::string content_type_name(content_type_t ct) {
    switch (ct) {
        case content_type_t::json: return "JSON";
        case content_type_t::xml: return "XML";
        case content_type_t::html: return "HTML";
        case content_type_t::text: return "Text";
        case content_type_t::form_urlencoded: return "Form";
        case content_type_t::multipart: return "Multipart";
        case content_type_t::binary: return "Binary";
        default: return "Unknown";
    }
}


static uint32_t read_u24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
            static_cast<uint32_t>(p[2]);
}

static uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
            static_cast<uint32_t>(p[3]);
}

static uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

static bool validate_h2_frame(uint8_t type, uint32_t length, uint8_t flags,
                              uint32_t stream_id, const uint8_t* payload) {
    switch (static_cast<h2_frame_type>(type)) {
    case h2_frame_type::DATA:
        if (stream_id == 0) return false;
        if ((flags & 0x08) != 0 && length == 0) return false;
        return true;
    case h2_frame_type::HEADERS:
        if (stream_id == 0) return false;
        if ((flags & 0x08) != 0 && length == 0) return false;
        if ((flags & 0x20) != 0 && length < ((flags & 0x08) != 0 ? 6u : 5u)) return false;
        return true;
    case h2_frame_type::PRIORITY:
        return stream_id != 0 && length == 5;
    case h2_frame_type::RST_STREAM:
        return stream_id != 0 && length == 4;
    case h2_frame_type::SETTINGS:
        if (stream_id != 0) return false;
        if ((flags & 0x01) != 0) return length == 0;
        return (length % 6) == 0;
    case h2_frame_type::PUSH_PROMISE:
        if (stream_id == 0 || length < 4) return false;
        if ((flags & 0x08) != 0 && length < 5) return false;
        return true;
    case h2_frame_type::PING:
        return stream_id == 0 && length == 8;
    case h2_frame_type::GOAWAY:
        return stream_id == 0 && length >= 8;
    case h2_frame_type::WINDOW_UPDATE:
        if (length != 4 || !payload) return false;
        return (read_u32(payload) & 0x7FFFFFFF) != 0;
    case h2_frame_type::CONTINUATION:
        return stream_id != 0;
    default:
        return true;
    }
}

std::vector<h2_frame> parse_h2_frames(const uint8_t* data, size_t len) {
    diag::log_tagged_fmt("proto", "parse_h2_frames entry len=%zu", len);
    std::vector<h2_frame> frames;
    if (!data || len == 0) return frames;

    static const char h2_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t preface_len = 24;
    size_t offset = 0;
    bool has_preface = (len >= preface_len && memcmp(data, h2_preface, preface_len) == 0);
    if (has_preface) {
        offset = preface_len;
        diag::log_tagged("proto", "parse_h2_frames detected connection preface");
    }

    while (len - offset >= 9) {
        h2_frame f;
        f.length = read_u24(data + offset);
        f.type = static_cast<h2_frame_type>(data[offset + 3]);
        f.flags = data[offset + 4];
        f.stream_id = read_u32(data + offset + 5) & 0x7FFFFFFF;
        offset += 9;

        if (f.length > 16777215u) {
            diag::log_tagged_fmt("proto", "parse_h2_frames frame too large length=%u breaking", f.length);
            break;
        }
        if (f.length > len - offset) {
            diag::log_tagged_fmt("proto", "parse_h2_frames frame truncated need=%u have=%zu", f.length, len - offset);
            break;
        }

        if (!validate_h2_frame(static_cast<uint8_t>(f.type), f.length, f.flags, f.stream_id, data + offset)) {
            diag::log_tagged_fmt("proto", "parse_h2_frames invalid frame type=0x%02x flags=0x%02x stream_id=%u length=%u",
                static_cast<unsigned>(static_cast<uint8_t>(f.type)), f.flags, f.stream_id, f.length);
            break;
        }

        f.payload.assign(data + offset, data + offset + f.length);
        offset += f.length;
        diag::log_tagged_fmt("proto", "parse_h2_frames frame type=%s flags=0x%02x stream_id=%u length=%u", h2_frame_type_name(f.type).c_str(), f.flags, f.stream_id, f.length);
        frames.push_back(std::move(f));
    }
    diag::log_tagged_fmt("proto", "parse_h2_frames result frames_count=%zu", frames.size());
    return frames;
}

std::string h2_frame_type_name(h2_frame_type t) {
    switch (t) {
        case h2_frame_type::DATA:          return "DATA";
        case h2_frame_type::HEADERS:       return "HEADERS";
        case h2_frame_type::PRIORITY:      return "PRIORITY";
        case h2_frame_type::RST_STREAM:    return "RST_STREAM";
        case h2_frame_type::SETTINGS:      return "SETTINGS";
        case h2_frame_type::PUSH_PROMISE:  return "PUSH_PROMISE";
        case h2_frame_type::PING:          return "PING";
        case h2_frame_type::GOAWAY:        return "GOAWAY";
        case h2_frame_type::WINDOW_UPDATE: return "WINDOW_UPDATE";
        case h2_frame_type::CONTINUATION:  return "CONTINUATION";
        default: return "UNKNOWN(" + std::to_string(static_cast<int>(t)) + ")";
    }
}


static const h2_header_field hpack_static_table[] = {
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" }
};
static const size_t HPACK_STATIC_TABLE_SIZE = sizeof(hpack_static_table) / sizeof(hpack_static_table[0]);

static bool hpack_decode_integer(const uint8_t* data, size_t len, size_t& pos,
                                 uint8_t prefix_bits, uint32_t& out) {
    if (!data || pos >= len || prefix_bits == 0 || prefix_bits > 8) return false;
    uint32_t max_first = (1u << prefix_bits) - 1;
    uint32_t value = data[pos] & max_first;
    pos++;
    if (value < max_first) {
        out = value;
        return true;
    }

    uint32_t m = 0;
    bool terminated = false;
    while (pos < len) {
        uint8_t b = data[pos];
        pos++;
        if (m >= 32 || (static_cast<uint32_t>(b & 0x7F) >
            ((std::numeric_limits<uint32_t>::max)() - value) >> m)) return false;
        value += static_cast<uint32_t>(b & 0x7F) << m;
        if ((b & 0x80) == 0) {
            terminated = true;
            break;
        }
        m += 7;
        if (m > 28) return false;
    }
    if (!terminated) return false;
    out = value;
    return true;
}

static bool hpack_decode_string(const uint8_t* data, size_t len, size_t& pos, std::string& out) {
    if (!data || pos >= len) return false;
    bool huffman = (data[pos] & 0x80) != 0;
    uint32_t slen = 0;
    if (!hpack_decode_integer(data, len, pos, 7, slen) || slen > len - pos) return false;

    if (slen > kMaxHpackStringBytes) return false;
    if (!huffman) {
        out.assign(reinterpret_cast<const char*>(data + pos), slen);
        pos += slen;
        return true;
    }


    struct huff_entry { uint32_t code; uint8_t bits; uint16_t sym; };
    static const huff_entry huff_table[] = {
        {0x1ff8, 13, 0}, {0x7fffd8, 23, 1}, {0xfffffe2, 28, 2}, {0xfffffe3, 28, 3},
        {0xfffffe4, 28, 4}, {0xfffffe5, 28, 5}, {0xfffffe6, 28, 6}, {0xfffffe7, 28, 7},
        {0xfffffe8, 28, 8}, {0xffffea, 24, 9}, {0x3ffffffc, 30, 10}, {0xfffffe9, 28, 11},
        {0xfffffea, 28, 12}, {0x3ffffffd, 30, 13}, {0xfffffeb, 28, 14}, {0xfffffec, 28, 15},
        {0xfffffed, 28, 16}, {0xfffffee, 28, 17}, {0xfffffef, 28, 18}, {0xffffff0, 28, 19},
        {0xffffff1, 28, 20}, {0xffffff2, 28, 21}, {0x3ffffffe, 30, 22}, {0xffffff3, 28, 23},
        {0xffffff4, 28, 24}, {0xffffff5, 28, 25}, {0xffffff6, 28, 26}, {0xffffff7, 28, 27},
        {0xffffff8, 28, 28}, {0xffffff9, 28, 29}, {0xffffffa, 28, 30}, {0xffffffb, 28, 31},
        {0x14, 6, 32}, {0x3f8, 10, 33}, {0x3f9, 10, 34}, {0xffa, 12, 35},
        {0x1ff9, 13, 36}, {0x15, 6, 37}, {0xf8, 8, 38}, {0x7fa, 11, 39},
        {0x3fa, 10, 40}, {0x3fb, 10, 41}, {0xf9, 8, 42}, {0x7fb, 11, 43},
        {0xfa, 8, 44}, {0x16, 6, 45}, {0x17, 6, 46}, {0x18, 6, 47},
        {0x0, 5, 48}, {0x1, 5, 49}, {0x2, 5, 50}, {0x19, 6, 51},
        {0x1a, 6, 52}, {0x1b, 6, 53}, {0x1c, 6, 54}, {0x1d, 6, 55},
        {0x1e, 6, 56}, {0x1f, 6, 57}, {0x5c, 7, 58}, {0xfb, 8, 59},
        {0x7ffc, 15, 60}, {0x20, 6, 61}, {0xffb, 12, 62}, {0x3fc, 10, 63},
        {0x1ffa, 13, 64}, {0x21, 6, 65}, {0x5d, 7, 66}, {0x5e, 7, 67},
        {0x5f, 7, 68}, {0x60, 7, 69}, {0x61, 7, 70}, {0x62, 7, 71},
        {0x63, 7, 72}, {0x64, 7, 73}, {0x65, 7, 74}, {0x66, 7, 75},
        {0x67, 7, 76}, {0x68, 7, 77}, {0x69, 7, 78}, {0x6a, 7, 79},
        {0x6b, 7, 80}, {0x6c, 7, 81}, {0x6d, 7, 82}, {0x6e, 7, 83},
        {0x6f, 7, 84}, {0x70, 7, 85}, {0x71, 7, 86}, {0x72, 7, 87},
        {0xfc, 8, 88}, {0x73, 7, 89}, {0xfd, 8, 90}, {0x1ffb, 13, 91},
        {0x7fff0, 19, 92}, {0x1ffc, 13, 93}, {0x3ffc, 14, 94}, {0x22, 6, 95},
        {0x7ffd, 15, 96}, {0x3, 5, 97}, {0x23, 6, 98}, {0x4, 5, 99},
        {0x24, 6, 100}, {0x5, 5, 101}, {0x25, 6, 102}, {0x26, 6, 103},
        {0x27, 6, 104}, {0x6, 5, 105}, {0x74, 7, 106}, {0x75, 7, 107},
        {0x28, 6, 108}, {0x29, 6, 109}, {0x2a, 6, 110}, {0x7, 5, 111},
        {0x2b, 6, 112}, {0x76, 7, 113}, {0x2c, 6, 114}, {0x8, 5, 115},
        {0x9, 5, 116}, {0x2d, 6, 117}, {0x77, 7, 118}, {0x78, 7, 119},
        {0x79, 7, 120}, {0x7a, 7, 121}, {0x7b, 7, 122}, {0x7ffe, 15, 123},
        {0x7fc, 11, 124}, {0x3ffd, 14, 125}, {0x1ffd, 13, 126}, {0xffffffc, 28, 127},
        {0xfffe6, 20, 128}, {0x3fffd2, 22, 129}, {0xfffe7, 20, 130}, {0xfffe8, 20, 131},
        {0x3fffd3, 22, 132}, {0x3fffd4, 22, 133}, {0x3fffd5, 22, 134}, {0x7fffd9, 23, 135},
        {0x3fffd6, 22, 136}, {0x7fffda, 23, 137}, {0x7fffdb, 23, 138}, {0x7fffdc, 23, 139},
        {0x7fffdd, 23, 140}, {0x7fffde, 23, 141}, {0xffffeb, 24, 142}, {0x7fffdf, 23, 143},
        {0xffffec, 24, 144}, {0xffffed, 24, 145}, {0x3fffd7, 22, 146}, {0x7fffe0, 23, 147},
        {0xffffee, 24, 148}, {0x7fffe1, 23, 149}, {0x7fffe2, 23, 150}, {0x7fffe3, 23, 151},
        {0x7fffe4, 23, 152}, {0x1fffdc, 21, 153}, {0x3fffd8, 22, 154}, {0x7fffe5, 23, 155},
        {0x3fffd9, 22, 156}, {0x7fffe6, 23, 157}, {0x7fffe7, 23, 158}, {0xffffef, 24, 159},
        {0x3fffda, 22, 160}, {0x1fffdd, 21, 161}, {0xfffe9, 20, 162}, {0x3fffdb, 22, 163},
        {0x3fffdc, 22, 164}, {0x7fffe8, 23, 165}, {0x7fffe9, 23, 166}, {0x1fffde, 21, 167},
        {0x7fffea, 23, 168}, {0x3fffdd, 22, 169}, {0x3fffde, 22, 170}, {0xfffff0, 24, 171},
        {0x1fffdf, 21, 172}, {0x3fffdf, 22, 173}, {0x7fffeb, 23, 174}, {0x7fffec, 23, 175},
        {0x1fffe0, 21, 176}, {0x1fffe1, 21, 177}, {0x3fffe0, 22, 178}, {0x1fffe2, 21, 179},
        {0x7fffed, 23, 180}, {0x3fffe1, 22, 181}, {0x7fffee, 23, 182}, {0x7fffef, 23, 183},
        {0xfffea, 20, 184}, {0x3fffe2, 22, 185}, {0x3fffe3, 22, 186}, {0x3fffe4, 22, 187},
        {0x7ffff0, 23, 188}, {0x3fffe5, 22, 189}, {0x3fffe6, 22, 190}, {0x7ffff1, 23, 191},
        {0x3ffffe0, 26, 192}, {0x3ffffe1, 26, 193}, {0xfffeb, 20, 194}, {0x7fff1, 19, 195},
        {0x3fffe7, 22, 196}, {0x7ffff2, 23, 197}, {0x3fffe8, 22, 198}, {0x1ffffec, 25, 199},
        {0x3ffffe2, 26, 200}, {0x3ffffe3, 26, 201}, {0x3ffffe4, 26, 202}, {0x7ffffde, 27, 203},
        {0x7ffffdf, 27, 204}, {0x3ffffe5, 26, 205}, {0xfffff1, 24, 206}, {0x1ffffed, 25, 207},
        {0x7fff2, 19, 208}, {0x1fffe3, 21, 209}, {0x3ffffe6, 26, 210}, {0x7ffffe0, 27, 211},
        {0x7ffffe1, 27, 212}, {0x3ffffe7, 26, 213}, {0x7ffffe2, 27, 214}, {0xfffff2, 24, 215},
        {0x1fffe4, 21, 216}, {0x1fffe5, 21, 217}, {0x3ffffe8, 26, 218}, {0x3ffffe9, 26, 219},
        {0xffffffd, 28, 220}, {0x7ffffe3, 27, 221}, {0x7ffffe4, 27, 222}, {0x7ffffe5, 27, 223},
        {0xfffec, 20, 224}, {0xfffff3, 24, 225}, {0xfffed, 20, 226}, {0x1fffe6, 21, 227},
        {0x3fffe9, 22, 228}, {0x1fffe7, 21, 229}, {0x1fffe8, 21, 230}, {0x7ffff3, 23, 231},
        {0x3fffea, 22, 232}, {0x3fffeb, 22, 233}, {0x1ffffee, 25, 234}, {0x1ffffef, 25, 235},
        {0xfffff4, 24, 236}, {0xfffff5, 24, 237}, {0x3ffffea, 26, 238}, {0x7ffff4, 23, 239},
        {0x3ffffeb, 26, 240}, {0x7ffffe6, 27, 241}, {0x3ffffec, 26, 242}, {0x3ffffed, 26, 243},
        {0x7ffffe7, 27, 244}, {0x7ffffe8, 27, 245}, {0x7ffffe9, 27, 246}, {0x7ffffea, 27, 247},
        {0x7ffffeb, 27, 248}, {0xffffffe, 28, 249}, {0x7ffffec, 27, 250}, {0x7ffffed, 27, 251},
        {0x7ffffee, 27, 252}, {0x7ffffef, 27, 253}, {0x7fffff0, 27, 254}, {0x3ffffee, 26, 255},
        {0x3fffffff, 30, 256}
    };
    static const size_t HUFF_TABLE_SIZE = sizeof(huff_table) / sizeof(huff_table[0]);


    std::string result;
    uint64_t accum = 0;
    uint32_t bits = 0;
    const uint8_t* hdata = data + pos;

    for (uint32_t i = 0; i < slen; i++) {
        accum = (accum << 8) | hdata[i];
        bits += 8;

        while (bits >= 5) {
            bool found = false;
            for (size_t t = 0; t < HUFF_TABLE_SIZE - 1; t++) {
                if (huff_table[t].bits <= bits) {
                    uint32_t mask = (1u << huff_table[t].bits) - 1;
                    uint32_t candidate = static_cast<uint32_t>(accum >> (bits - huff_table[t].bits)) & mask;
                    if (candidate == huff_table[t].code) {
                        result += static_cast<char>(huff_table[t].sym);
                        bits -= huff_table[t].bits;
                        accum &= (static_cast<uint64_t>(1) << bits) - 1;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) break;
        }
    }

    pos += slen;
    out = std::move(result);
    return true;
}

static h2_header_field hpack_get_indexed(size_t index, const hpack_context& ctx) {
    if (index == 0) return {};
    if (index <= HPACK_STATIC_TABLE_SIZE) {
        return hpack_static_table[index - 1];
    }
    size_t dyn_idx = index - HPACK_STATIC_TABLE_SIZE - 1;
    if (dyn_idx < ctx.dynamic_table.size()) {
        return ctx.dynamic_table[dyn_idx];
    }
    return {};
}

static void hpack_add_to_dynamic(hpack_context& ctx, const h2_header_field& field) {
    if (field.name.size() > (std::numeric_limits<size_t>::max)() - field.value.size() - 32)
        return;
    size_t entry_size = field.name.size() + field.value.size() + 32;
    if (entry_size > ctx.max_dynamic_table_size) {
        ctx.dynamic_table.clear();
        ctx.dynamic_table_size = 0;
        return;
    }
    ctx.dynamic_table.insert(ctx.dynamic_table.begin(), field);
    ctx.dynamic_table_size += entry_size;

    while (ctx.dynamic_table_size > ctx.max_dynamic_table_size && !ctx.dynamic_table.empty()) {
        auto& last = ctx.dynamic_table.back();
        ctx.dynamic_table_size -= (last.name.size() + last.value.size() + 32);
        ctx.dynamic_table.pop_back();
    }
}

h2_parsed_headers decode_hpack(const uint8_t* data, size_t len, hpack_context& ctx) {
    diag::log_tagged_fmt("proto", "decode_hpack entry len=%zu dyn_table_size=%zu", len, ctx.dynamic_table.size());
    h2_parsed_headers result;
    if (!data || len > 16u * 1024u * 1024u || ctx.max_dynamic_table_size > 16u * 1024u * 1024u) return result;
    size_t pos = 0;

    while (pos < len) {
        uint8_t b = data[pos];

        if (b & 0x80) {
            uint32_t index = 0;
            if (!hpack_decode_integer(data, len, pos, 7, index)) return result;
            auto field = hpack_get_indexed(index, ctx);
            if (field.name.empty()) {
                result.valid = false;
                return result;
            }
            diag::log_tagged_fmt("proto", "decode_hpack indexed idx=%u name=%s value=%s", index, field.name.c_str(), field.value.c_str());
            if (result.fields.size() >= kMaxHpackFields) { result.valid = false; return result; }
            result.fields.push_back(field);
        }
        else if (b & 0x40) {
            uint32_t index = 0;
            if (!hpack_decode_integer(data, len, pos, 6, index)) return result;
            h2_header_field field;
            if (index > 0) {
                field = hpack_get_indexed(index, ctx);
                if (field.name.empty()) {
                    result.valid = false;
                    return result;
                }
                if (!hpack_decode_string(data, len, pos, field.value)) return result;
            } else {
                if (!hpack_decode_string(data, len, pos, field.name) ||
                    !hpack_decode_string(data, len, pos, field.value)) return result;
            }
            if (field.name.empty()) {
                result.valid = false;
                return result;
            }
            diag::log_tagged_fmt("proto", "decode_hpack literal-with-index name=%s value=%s", field.name.c_str(), field.value.c_str());
            hpack_add_to_dynamic(ctx, field);
            if (result.fields.size() >= kMaxHpackFields) { result.valid = false; return result; }
            result.fields.push_back(field);
        }
        else if (b & 0x20) {
            uint32_t new_size = 0;
            if (!hpack_decode_integer(data, len, pos, 5, new_size) || new_size > 16u * 1024u * 1024u) return result;
            diag::log_tagged_fmt("proto", "decode_hpack dynamic table size update new_size=%u", new_size);
            ctx.max_dynamic_table_size = new_size;
            while (ctx.dynamic_table_size > ctx.max_dynamic_table_size && !ctx.dynamic_table.empty()) {
                auto& last = ctx.dynamic_table.back();
                ctx.dynamic_table_size -= (last.name.size() + last.value.size() + 32);
                ctx.dynamic_table.pop_back();
            }
        }
        else {
            bool never_index = (b & 0x10) != 0;
            (void)never_index;
            uint32_t index = 0;
            if (!hpack_decode_integer(data, len, pos, 4, index)) return result;
            h2_header_field field;
            if (index > 0) {
                field = hpack_get_indexed(index, ctx);
                if (field.name.empty()) {
                    result.valid = false;
                    return result;
                }
                if (!hpack_decode_string(data, len, pos, field.value)) return result;
            } else {
                if (!hpack_decode_string(data, len, pos, field.name) ||
                    !hpack_decode_string(data, len, pos, field.value)) return result;
            }
            if (field.name.empty()) {
                result.valid = false;
                return result;
            }
            diag::log_tagged_fmt("proto", "decode_hpack literal-never-index=%d name=%s value=%s", (int)never_index, field.name.c_str(), field.value.c_str());
            if (result.fields.size() >= kMaxHpackFields) { result.valid = false; return result; }
            result.fields.push_back(field);
        }
    }
    result.valid = true;
    diag::log_tagged_fmt("proto", "decode_hpack result fields_count=%zu", result.fields.size());
    return result;
}


bool is_websocket_upgrade(const http_request& req) {
    diag::log_tagged_fmt("proto", "is_websocket_upgrade entry req_valid=%d method=%s uri=%s", (int)req.valid, req.method.c_str(), req.uri.c_str());
    if (!req.valid) {
        diag::log_tagged("proto", "is_websocket_upgrade req not valid -> false");
        return false;
    }
    std::string upgrade = to_lower(find_header(req.headers, "Upgrade"));
    std::string conn = to_lower(find_header(req.headers, "Connection"));
    bool result = upgrade.find("websocket") != std::string::npos &&
                  conn.find("upgrade") != std::string::npos;
    diag::log_tagged_fmt("proto", "is_websocket_upgrade upgrade=%s connection=%s result=%d", upgrade.c_str(), conn.c_str(), (int)result);
    return result;
}

bool is_websocket_accept(const http_response& resp) {
    diag::log_tagged_fmt("proto", "is_websocket_accept entry resp_valid=%d status=%d", (int)resp.valid, resp.status_code);
    if (!resp.valid) {
        diag::log_tagged("proto", "is_websocket_accept resp not valid -> false");
        return false;
    }
    if (resp.status_code != 101) {
        diag::log_tagged_fmt("proto", "is_websocket_accept status not 101 got=%d -> false", resp.status_code);
        return false;
    }
    std::string upgrade = to_lower(find_header(resp.headers, "Upgrade"));
    bool result = upgrade.find("websocket") != std::string::npos;
    diag::log_tagged_fmt("proto", "is_websocket_accept upgrade=%s result=%d", upgrade.c_str(), (int)result);
    return result;
}

ws_frame parse_ws_frame(const uint8_t* data, size_t len) {
    diag::log_tagged_fmt("proto", "parse_ws_frame entry len=%zu", len);
    ws_frame f;
    if (len < 2) {
        diag::log_tagged_fmt("proto", "parse_ws_frame too short len=%zu", len);
        return f;
    }

    f.fin = (data[0] & 0x80) != 0;
    f.opcode = static_cast<ws_opcode>(data[0] & 0x0F);
    f.masked = (data[1] & 0x80) != 0;
    diag::log_tagged_fmt("proto", "parse_ws_frame fin=%d opcode=%s masked=%d", (int)f.fin, ws_opcode_name(f.opcode).c_str(), (int)f.masked);

    uint64_t plen = data[1] & 0x7F;
    size_t hdr_size = 2;

    if (plen == 126) {
        if (len < 4) {
            diag::log_tagged("proto", "parse_ws_frame 2-byte plen but too short");
            return f;
        }
        plen = read_u16(data + 2);
        hdr_size = 4;
    } else if (plen == 127) {
        if (len < 10) {
            diag::log_tagged("proto", "parse_ws_frame 8-byte plen but too short");
            return f;
        }
        plen = 0;
        for (int i = 0; i < 8; i++)
            plen = (plen << 8) | data[2 + i];
        hdr_size = 10;
    }
    diag::log_tagged_fmt("proto", "parse_ws_frame payload_length=%llu hdr_size=%zu", (unsigned long long)plen, hdr_size);

    if (f.masked) {
        if (len < hdr_size + 4) {
            diag::log_tagged("proto", "parse_ws_frame masked but not enough for masking key");
            return f;
        }
        memcpy(f.masking_key, data + hdr_size, 4);
        hdr_size += 4;
    }

    f.payload_length = plen;
    if (plen > len - hdr_size || plen > static_cast<uint64_t>((std::numeric_limits<size_t>::max)() - hdr_size)) {
        diag::log_tagged_fmt("proto", "parse_ws_frame truncated hdr=%zu plen=%llu total_avail=%zu", hdr_size, (unsigned long long)plen, len);
        return f;
    }

    f.payload.assign(data + hdr_size, data + hdr_size + plen);
    f.valid = true;
    f.total_consumed = hdr_size + static_cast<size_t>(plen);
    diag::log_tagged_fmt("proto", "parse_ws_frame success opcode=%s plen=%llu fin=%d masked=%d consumed=%zu", ws_opcode_name(f.opcode).c_str(), (unsigned long long)plen, (int)f.fin, (int)f.masked, f.total_consumed);
    return f;
}

std::vector<uint8_t> unmask_payload(const ws_frame& frame) {
    diag::log_tagged_fmt("proto", "unmask_payload masked=%d payload_size=%zu", (int)frame.masked, frame.payload.size());
    if (!frame.masked || frame.payload.empty()) {
        diag::log_tagged("proto", "unmask_payload not masked or empty returning as-is");
        return frame.payload;
    }
    std::vector<uint8_t> result = frame.payload;
    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= frame.masking_key[i % 4];
    }
    diag::log_tagged_fmt("proto", "unmask_payload done size=%zu", result.size());
    return result;
}

std::string ws_opcode_name(ws_opcode op) {
    switch (op) {
        case ws_opcode::continuation: return "Continuation";
        case ws_opcode::text: return "Text";
        case ws_opcode::binary: return "Binary";
        case ws_opcode::close: return "Close";
        case ws_opcode::ping: return "Ping";
        case ws_opcode::pong: return "Pong";
        default: return "Unknown";
    }
}


bool is_quic_packet(const uint8_t* data, size_t len, uint16_t dst_port) {
    diag::log_tagged_fmt("proto", "is_quic_packet entry len=%zu dst_port=%u first_byte=0x%02x", len, dst_port, (len > 0 ? data[0] : 0));
    if (len < 5) {
        diag::log_tagged_fmt("proto", "is_quic_packet too short len=%zu -> false", len);
        return false;
    }

    if ((data[0] & 0x80) != 0) {
        uint32_t ver = read_u32(data + 1);
        bool quic_ver = (ver == 0x00000001 || ver == 0x6b3343cf || ver == 0xff000000 ||
                         (ver & 0xffffff00) == 0xff000000 || ver == 0);
        diag::log_tagged_fmt("proto", "is_quic_packet long header ver=0x%08x quic_ver=%d", ver, (int)quic_ver);
        if (quic_ver) return true;
    }

    if (dst_port == 443 && (data[0] & 0x40) != 0) {
        diag::log_tagged("proto", "is_quic_packet short header on port 443 -> true");
        return true;
    }
    diag::log_tagged("proto", "is_quic_packet -> false");
    return false;
}

quic_header parse_quic_header(const uint8_t* data, size_t len) {
    diag::log_tagged_fmt("proto", "parse_quic_header entry len=%zu", len);
    quic_header h;
    if (len < 5) {
        diag::log_tagged_fmt("proto", "parse_quic_header too short len=%zu", len);
        return h;
    }

    h.first_byte = data[0];
    h.is_long_header = (data[0] & 0x80) != 0;
    diag::log_tagged_fmt("proto", "parse_quic_header is_long_header=%d first_byte=0x%02x", (int)h.is_long_header, h.first_byte);

    if (h.is_long_header) {
        h.version = read_u32(data + 1);
        h.version_name = quic_version_name(h.version);
        diag::log_tagged_fmt("proto", "parse_quic_header long header version=0x%08x version_name=%s", h.version, h.version_name.c_str());

        if (len < 6) return h;
        uint8_t dcid_len = data[5];
        if (len < 6u + dcid_len + 1u) return h;
        h.dcid.assign(data + 6, data + 6 + dcid_len);

        size_t scid_off = 6 + dcid_len;
        uint8_t scid_len = data[scid_off];
        if (len < scid_off + 1 + scid_len) return h;
        h.scid.assign(data + scid_off + 1, data + scid_off + 1 + scid_len);

        size_t pos = scid_off + 1 + scid_len;

        if (h.version == 0) {
            h.is_version_negotiation = true;
            h.packet_type = "Version Negotiation";
            while (pos + 4 <= len) {
                h.supported_versions.push_back(read_u32(data + pos));
                pos += 4;
            }
            h.payload_offset = pos;
            h.valid = true;
        } else {
            uint8_t ptype = (data[0] & 0x30) >> 4;
            switch (ptype) {
                case 0: {
                    h.packet_type = "Initial";
                    if (pos < len) {
                        uint64_t token_len = 0;
                        size_t varint_bytes = 0;
                        uint8_t first = data[pos];
                        uint8_t prefix = first >> 6;
                        if (prefix == 0) {
                            token_len = first & 0x3F;
                            varint_bytes = 1;
                        } else if (prefix == 1 && pos + 2 <= len) {
                            token_len = (static_cast<uint64_t>(first & 0x3F) << 8)
                                      | data[pos + 1];
                            varint_bytes = 2;
                        } else if (prefix == 2 && pos + 4 <= len) {
                            token_len = (static_cast<uint64_t>(first & 0x3F) << 24)
                                      | (static_cast<uint64_t>(data[pos + 1]) << 16)
                                      | (static_cast<uint64_t>(data[pos + 2]) << 8)
                                      | data[pos + 3];
                            varint_bytes = 4;
                        }
                        pos += varint_bytes;
                        if (token_len > 0 && pos + token_len <= len) {
                            h.token.assign(data + pos, data + pos + token_len);
                            pos += static_cast<size_t>(token_len);
                        }
                    }
                    h.payload_offset = pos;
                    break;
                }
                case 1: h.packet_type = "0-RTT"; h.payload_offset = pos; break;
                case 2: h.packet_type = "Handshake"; h.payload_offset = pos; break;
                case 3: {
                    h.packet_type = "Retry";
                    if (pos < len) {
                        size_t integrity_tag_size = 16;
                        size_t token_end = (len >= integrity_tag_size) ? len - integrity_tag_size : len;
                        if (pos < token_end) {
                            h.token.assign(data + pos, data + token_end);
                        }
                        h.payload_offset = len;
                    }
                    break;
                }
            }
            h.valid = true;
        }
    } else {
        h.packet_type = "1-RTT (Short)";
        if (len > 1) {
            constexpr size_t kQuicDcidLenHeuristic = 20;
            size_t dcid_len = (std::min)(kQuicDcidLenHeuristic, len - 1);
            h.dcid.assign(data + 1, data + 1 + dcid_len);
        }
        h.payload_offset = 1 + h.dcid.size();
        h.valid = true;
        diag::log_tagged_fmt("proto", "parse_quic_header short header type=%s dcid_len=%zu", h.packet_type.c_str(), h.dcid.size());
    }
    diag::log_tagged_fmt("proto", "parse_quic_header result valid=%d type=%s version_name=%s", (int)h.valid, h.packet_type.c_str(), h.version_name.c_str());
    return h;
}

std::string quic_version_name(uint32_t version) {
    switch (version) {
        case 0x00000001: return "QUIC v1 (RFC 9000)";
        case 0x6b3343cf: return "QUIC v2 (RFC 9369)";
        case 0x00000000: return "Version Negotiation";
        default:
            if ((version & 0x0f0f0f0f) == 0x0a0a0a0a)
                return "QUIC Greasing";
            if ((version & 0xff000000) == 0xff000000)
                return "QUIC Draft-" + std::to_string(version & 0xFF);
            char buf[32];
            snprintf(buf, sizeof(buf), "Unknown (0x%08X)", version);
            return buf;
    }
}


tls_record parse_tls_record(const uint8_t* data, size_t len) {
    diag::log_tagged_fmt("proto", "parse_tls_record entry len=%zu", len);
    tls_record rec;
    if (len < 5) {
        diag::log_tagged_fmt("proto", "parse_tls_record too short len=%zu", len);
        return rec;
    }

    rec.content_type = data[0];
    rec.version = read_u16(data + 1);
    rec.length = read_u16(data + 3);
    diag::log_tagged_fmt("proto", "parse_tls_record content_type=%u(%s) version=%s record_len=%u", rec.content_type, tls_content_type_name(rec.content_type).c_str(), tls_version_name(rec.version).c_str(), rec.length);

    if (rec.content_type < 20 || (rec.content_type > 25 && rec.content_type != 255)) {
        diag::log_tagged_fmt("proto", "parse_tls_record invalid content_type=%u", rec.content_type);
        return rec;
    }

    if ((rec.version & 0xFF00) != 0x0300) {
        diag::log_tagged_fmt("proto", "parse_tls_record invalid version=0x%04x", rec.version);
        return rec;
    }

    if (rec.length > 16384 + 2048) {
        diag::log_tagged_fmt("proto", "parse_tls_record record too large length=%u", rec.length);
        return rec;
    }

    if (5 + rec.length <= len) {
        rec.fragment.assign(data + 5, data + 5 + rec.length);
    }
    rec.valid = true;
    diag::log_tagged_fmt("proto", "parse_tls_record success content_type=%s version=%s frag_size=%zu", tls_content_type_name(rec.content_type).c_str(), tls_version_name(rec.version).c_str(), rec.fragment.size());
    return rec;
}

tls_client_hello parse_client_hello(const uint8_t* data, size_t len) {
    diag::log_tagged_fmt("proto", "parse_client_hello entry len=%zu", len);
    tls_client_hello hello;

    auto rec = parse_tls_record(data, len);
    if (!rec.valid || rec.content_type != 22) {
        diag::log_tagged_fmt("proto", "parse_client_hello tls_record invalid or not handshake rec_valid=%d ct=%u", (int)rec.valid, rec.content_type);
        return hello;
    }

    const uint8_t* hs = rec.fragment.data();
    size_t hs_len = rec.fragment.size();
    if (hs_len < 4) {
        diag::log_tagged_fmt("proto", "parse_client_hello handshake too short hs_len=%zu", hs_len);
        return hello;
    }

    uint8_t hs_type = hs[0];
    diag::log_tagged_fmt("proto", "parse_client_hello handshake_type=%u (expected 1=ClientHello)", hs_type);
    if (hs_type != 1) {
        diag::log_tagged_fmt("proto", "parse_client_hello not ClientHello type=%u", hs_type);
        return hello;
    }

    uint32_t hs_length = read_u24(hs + 1);
    if (hs_length + 4 > hs_len) {
        diag::log_tagged_fmt("proto", "parse_client_hello hs_length mismatch hs_length=%u hs_len=%zu", hs_length, hs_len);
        return hello;
    }

    const uint8_t* ch = hs + 4;
    size_t ch_len = hs_length;
    size_t pos = 0;

    if (ch_len < 2 + 32) return hello;
    hello.version = read_u16(ch);
    pos = 2 + 32;


    if (pos >= ch_len) return hello;
    uint8_t sid_len = ch[pos]; pos++;
    pos += sid_len;


    if (pos + 2 > ch_len) return hello;
    uint16_t cs_len = read_u16(ch + pos); pos += 2;
    if (pos + cs_len > ch_len) return hello;
    for (uint16_t i = 0; i < cs_len; i += 2) {
        hello.cipher_suites.push_back(read_u16(ch + pos + i));
    }
    pos += cs_len;


    if (pos >= ch_len) return hello;
    uint8_t cm_len = ch[pos]; pos++;
    pos += cm_len;


    if (pos + 2 > ch_len) { hello.valid = true; return hello; }
    uint16_t ext_len = read_u16(ch + pos); pos += 2;
    size_t ext_end = pos + ext_len;
    if (ext_end > ch_len) ext_end = ch_len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = read_u16(ch + pos);
        uint16_t ext_data_len = read_u16(ch + pos + 2);
        pos += 4;
        if (pos + ext_data_len > ext_end) break;

        if (ext_type == 0x0000 && ext_data_len >= 2) {

            uint16_t sni_list_len = read_u16(ch + pos);
            size_t sni_pos = pos + 2;
            size_t sni_end = pos + sni_list_len + 2;
            if (sni_end > pos + ext_data_len) sni_end = pos + ext_data_len;

            while (sni_pos + 3 < sni_end) {
                uint8_t name_type = ch[sni_pos]; sni_pos++;
                uint16_t name_len = read_u16(ch + sni_pos); sni_pos += 2;
                if (name_type == 0 && sni_pos + name_len <= sni_end) {
                    hello.sni = std::string(reinterpret_cast<const char*>(ch + sni_pos), name_len);
                }
                sni_pos += name_len;
            }
        }
        else if (ext_type == 0x0010 && ext_data_len >= 2) {

            uint16_t alpn_list_len = read_u16(ch + pos);
            size_t alpn_pos = pos + 2;
            size_t alpn_end = pos + 2 + alpn_list_len;
            if (alpn_end > pos + ext_data_len) alpn_end = pos + ext_data_len;

            while (alpn_pos < alpn_end) {
                uint8_t proto_len = ch[alpn_pos]; alpn_pos++;
                if (alpn_pos + proto_len > alpn_end) break;
                hello.alpn_protocols.push_back(
                    std::string(reinterpret_cast<const char*>(ch + alpn_pos), proto_len));
                alpn_pos += proto_len;
            }
        }

        pos += ext_data_len;
    }

    hello.valid = true;
    diag::log_tagged_fmt("proto", "parse_client_hello success sni=%s cipher_count=%zu alpn_count=%zu version=0x%04x", hello.sni.c_str(), hello.cipher_suites.size(), hello.alpn_protocols.size(), hello.version);
    return hello;
}

std::string tls_content_type_name(uint8_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "ApplicationData";
        default: return "Unknown(" + std::to_string(ct) + ")";
    }
}

std::string tls_version_name(uint16_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%04X", ver);
            return buf;
        }
    }
}


detection_result detect_protocol(const uint8_t* data, size_t len,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint32_t ip_protocol) {
    diag::log_tagged_fmt("proto", "detect_protocol entry len=%zu src_port=%u dst_port=%u ip_proto=%u", len, src_port, dst_port, ip_protocol);
    detection_result r;
    if (!data || len == 0) {
        diag::log_tagged("proto", "detect_protocol null data or len=0");
        return r;
    }

    if (ip_protocol == 17 && (src_port == 53 || dst_port == 53) && len >= 12) {
        r.protocol = detected_protocol_t::dns;
        r.label = "DNS";
        r.summary = (src_port == 53) ? "DNS Response" : "DNS Query";
        diag::log_tagged_fmt("proto", "detect_protocol detected DNS summary=%s", r.summary.c_str());
        return r;
    }

    if (ip_protocol == 17 && is_quic_packet(data, len, dst_port)) {
        auto qh = parse_quic_header(data, len);
        r.protocol = detected_protocol_t::quic;
        r.label = "QUIC";
        if (qh.valid) {
            r.summary = qh.packet_type;
            if (!qh.version_name.empty()) r.summary += " " + qh.version_name;
            if (!qh.dcid.empty()) r.summary += " DCID=" + qh.dcid_hex();
            if (qh.is_version_negotiation && !qh.supported_versions.empty()) {
                r.summary += " (supports:";
                for (auto v : qh.supported_versions) {
                    r.summary += " " + quic_version_name(v);
                }
                r.summary += ")";
            }
            if (!qh.token.empty()) {
                r.summary += " token=" + std::to_string(qh.token.size()) + "B";
            }
            if (!qh.is_long_header) {
                r.summary += " (encrypted)";
            }
        } else {
            r.summary = "QUIC (encrypted)";
        }
        diag::log_tagged_fmt("proto", "detect_protocol detected QUIC summary=%s", r.summary.c_str());
        return r;
    }

    if (len >= 5 && data[0] >= 20 && data[0] <= 25 &&
        data[1] == 0x03 && data[2] <= 0x04) {
        diag::log_tagged("proto", "detect_protocol TLS record heuristic match trying parse");
        auto rec = parse_tls_record(data, len);
        if (rec.valid) {
            r.protocol = detected_protocol_t::tls;
            r.label = "TLS";
            r.summary = tls_content_type_name(rec.content_type) + " " + tls_version_name(rec.version);
            if (rec.content_type == 22 && !rec.fragment.empty() && rec.fragment[0] == 1) {
                auto hello = parse_client_hello(data, len);
                if (hello.valid && !hello.sni.empty())
                    r.summary += " SNI=" + hello.sni;
                diag::log_tagged_fmt("proto", "detect_protocol TLS ClientHello sni=%s cipher_count=%zu", hello.sni.c_str(), hello.cipher_suites.size());
            }
            diag::log_tagged_fmt("proto", "detect_protocol detected TLS summary=%s", r.summary.c_str());
            return r;
        }
    }

    if (len >= 24 && memcmp(data, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
        r.protocol = detected_protocol_t::http2;
        r.label = "HTTP/2";
        r.summary = "Connection Preface";
        diag::log_tagged("proto", "detect_protocol detected HTTP/2 connection preface");
        return r;
    }

    static const char* http_methods[] = { "GET ", "POST ", "PUT ", "DELETE ",
                                           "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE " };
    for (auto m : http_methods) {
        size_t mlen = strlen(m);
        if (len >= mlen && memcmp(data, m, mlen) == 0) {
            diag::log_tagged_fmt("proto", "detect_protocol HTTP method match: %s trying parse", m);
            auto req = parse_http_request(data, len);
            if (req.valid) {
                r.protocol = detected_protocol_t::http_request;
                r.label = "HTTP";
                r.summary = req.method + " " + req.uri;
                diag::log_tagged_fmt("proto", "detect_protocol detected HTTP_REQUEST summary=%s", r.summary.c_str());
                return r;
            }
        }
    }

    if (len >= 12 && memcmp(data, "HTTP/", 5) == 0) {
        diag::log_tagged("proto", "detect_protocol HTTP/ prefix match trying response parse");
        auto resp = parse_http_response(data, len);
        if (resp.valid) {
            r.protocol = detected_protocol_t::http_response;
            r.label = "HTTP";
            r.summary = std::to_string(resp.status_code) + " " + resp.reason;
            diag::log_tagged_fmt("proto", "detect_protocol detected HTTP_RESPONSE summary=%s", r.summary.c_str());
            return r;
        }
    }

    r.protocol = detected_protocol_t::unknown;
    r.label = (ip_protocol == 6) ? "TCP" : ((ip_protocol == 17) ? "UDP" : "");
    diag::log_tagged_fmt("proto", "detect_protocol unknown label=%s", r.label.c_str());
    return r;
}

}
