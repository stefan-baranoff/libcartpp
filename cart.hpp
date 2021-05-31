#include <array>
#include <cstdint>
#include <json/json.h>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <stdexcept>
#include <vector>
#include <zlib.h>

namespace json {
// Better would be not having to allocate/delete the reader every time, but this is better than alternatives
inline Json::Value from_string(const std::string& src)
{
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> pReader{builder.newCharReader()};

    Json::Value dst;
    std::string errors;
    if (!pReader->parse(src.c_str(), src.c_str() + src.length(), &dst, &errors)) {
        throw std::runtime_error("Failed to parse '" + src + "' as json with '" + errors + "'");
    }

    return dst;
}
}  // namespace json

class Rc4 {
   public:
    Rc4(std::array<uint8_t, 16> key)
    {
        rc4_openssl_context.reset(EVP_CIPHER_CTX_new());
        if (rc4_openssl_context == nullptr) {
            throw std::runtime_error("Cipher init failed.");
        }
        if (EVP_DecryptInit(rc4_openssl_context.get(), EVP_rc4(), key.data(), nullptr) == 0) {
            throw std::runtime_error("Decrypt init failed.");
        }
    }
    Rc4(const Rc4& other) = delete;
    Rc4(Rc4&& other) = delete;
    Rc4& operator=(const Rc4& other) = delete;
    Rc4& operator=(Rc4&& other) = delete;
    ~Rc4() = default;

    std::vector<uint8_t> decrypt_next(const std::vector<uint8_t>& input)
    {
        std::vector<uint8_t> return_val;
        // Allocate input size bytes to decrypt into
        return_val.resize(input.size());
        int bytes_written{0};
        if (EVP_DecryptUpdate(rc4_openssl_context.get(), return_val.data(), &bytes_written, input.data(),
                              input.size()) == 0) {
            throw std::runtime_error("Decrypt update failed.");
        }
        // Shrink back down to just decrypted bytes
        return_val.resize(bytes_written);
        return return_val;
    }

   private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> rc4_openssl_context{nullptr, EVP_CIPHER_CTX_free};
};

class ZlibInflate {
   public:
    ZlibInflate()
    {
        zlib_stream.next_in = nullptr;
        zlib_stream.avail_in = 0;
        zlib_stream.total_out = 0;
        zlib_stream.zalloc = Z_NULL;
        zlib_stream.zfree = Z_NULL;
        zlib_stream.opaque = Z_NULL;
        if (inflateInit(&zlib_stream) != Z_OK) {
            throw std::runtime_error("Inflate init failed.");
        }
    }
    ZlibInflate(const ZlibInflate& other) = delete;
    ZlibInflate(ZlibInflate&& other) = delete;
    ZlibInflate& operator=(const ZlibInflate& other) = delete;
    ZlibInflate& operator=(ZlibInflate&& other) = delete;
    ~ZlibInflate()
    {
        inflateEnd(&zlib_stream);
    };

    std::vector<uint8_t> inflate_next(const std::vector<uint8_t>& input)
    {
        std::vector<uint8_t> return_buffer;
        std::array<uint8_t, 65536> output_buffer;
        zlib_stream.next_in = const_cast<uint8_t*>(input.data());
        zlib_stream.avail_in = input.size();
        // Start as if we just finished an inflate round
        zlib_stream.avail_out = 0;
        int ret{Z_OK};
        while (zlib_stream.avail_in > 0 && ret == Z_OK && zlib_stream.avail_out == 0) {
            zlib_stream.next_out = output_buffer.data();
            zlib_stream.avail_out = output_buffer.max_size();
            int ret{inflate(&zlib_stream, Z_SYNC_FLUSH)};
            if (ret != Z_OK && ret != Z_STREAM_END) {
                throw std::runtime_error(std::string("Error while inflating: ") + zlib_stream.msg);
            }
            return_buffer.insert(return_buffer.end(), output_buffer.data(),
                                 reinterpret_cast<uint8_t*>(zlib_stream.next_out));
        }
        if (ret == Z_STREAM_END) {
            if (zlib_stream.avail_in != 0) {
                throw std::runtime_error("Trailing data was present after zlib decompression completed.");
            }
            else {
                if (inflateEnd(&zlib_stream) != Z_OK) {
                    throw std::runtime_error(std::string("Inflate end failed: ") + zlib_stream.msg);
                }
            }
        }
        return return_buffer;
    }

   private:
    z_stream zlib_stream;
};

// Mandatory header
struct CartHeader {
    char cart[4];  // Should be "CART"
    uint16_t version;
    uint64_t reserved;
    uint8_t rc4_key[16];
    uint64_t opt_header_len;
} __attribute__((packed));

// Opt header
// header = JSON object with string keys
// RC4(to_json(header))

// Data block
// RC4(ZLIB(data))

// Opt footer; must be smaller than BLOCK_SIZE
// footer = JSON object with string keys
// RC4(to_json(footer))

// Mandatory footer
struct CartFooter {
    char tarc[4];  // Should be "TARC"
    uint64_t reserved[2];
    uint64_t opt_footer_len;
} __attribute__((packed));

class CartObject {
   public:
    CartObject(std::vector<uint8_t> cart_input, std::array<uint8_t, 16> rc4_key = DEFAULT_RC4_KEY)
    {
        if (cart_input.size() < sizeof(CartHeader) + sizeof(CartFooter)) {
            throw std::runtime_error(
                "Provided CaRT data is not big enough for at least the mandatory header and footer; this is probably "
                "not a full CaRT file.");
        }
        cart_header = *reinterpret_cast<CartHeader*>(cart_input.data());
        if (cart_header.opt_header_len > 0) {
            std::vector<uint8_t> header_enc{cart_input.begin() + sizeof(CartHeader),
                                            cart_input.begin() + sizeof(CartHeader) + cart_header.opt_header_len};
            Rc4 rc4{rc4_key};
            header_enc = rc4.decrypt_next(header_enc);
            std::string opt_header_json;
            opt_header_json.append(std::string(reinterpret_cast<char*>(header_enc.data()), header_enc.size()));
            try {
                cart_opt_header = json::from_string(opt_header_json);
            }
            catch (const std::runtime_error& e) {
                throw std::runtime_error(std::string("CaRT optional header did not parse as valid JSON: ") + e.what());
            }
        }
        cart_footer = *reinterpret_cast<CartFooter*>(&cart_input.back() - sizeof(CartFooter) + 1);
        if (cart_footer.opt_footer_len > 0) {
            std::vector<uint8_t> footer_enc{cart_input.end() - sizeof(CartFooter) - cart_footer.opt_footer_len,
                                            cart_input.end() - sizeof(CartFooter)};
            Rc4 rc4{rc4_key};
            footer_enc = rc4.decrypt_next(footer_enc);
            std::string opt_footer_json;
            opt_footer_json.append(std::string(reinterpret_cast<char*>(footer_enc.data()), footer_enc.size()));
            try {
                cart_opt_footer = json::from_string(opt_footer_json);
            }
            catch (const std::runtime_error& e) {
                throw std::runtime_error(std::string("CaRT optional footer did not parse as valid JSON: ") + e.what());
            }
        }
        encoded_file = std::vector(cart_input.begin() + sizeof(CartHeader) + cart_header.opt_header_len,
                                   cart_input.end() - sizeof(CartFooter) - cart_footer.opt_footer_len);

        Rc4 rc4{rc4_key};
        decoded_file = rc4.decrypt_next(encoded_file);

        ZlibInflate zlib_inflate;
        decoded_file = zlib_inflate.inflate_next(decoded_file);
    }
    CartObject(const CartObject& other) = delete;
    CartObject(CartObject&& other) = delete;
    CartObject& operator=(const CartObject& other) = delete;
    CartObject& operator=(CartObject&& other) = delete;
    ~CartObject() = default;

    CartHeader cart_header;
    Json::Value cart_opt_header;
    std::vector<uint8_t> encoded_file;
    std::vector<uint8_t> decoded_file;
    Json::Value cart_opt_footer;
    CartFooter cart_footer;

    static constexpr std::array<uint8_t, 16> DEFAULT_RC4_KEY{3, 1, 4, 1, 5, 9, 2, 6, 3, 1, 4, 1, 5, 9, 2, 6};
    static constexpr uint64_t BLOCK_SIZE{64 * 1024};
};
