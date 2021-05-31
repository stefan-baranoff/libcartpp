#include <cart.hpp>
#include <clocale>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

std::string read_file(const std::string& file);
std::string read_file(const std::string& file)
{
    std::ifstream input_stream(file, std::ifstream::binary);
    std::stringstream file_buffer;
    file_buffer << input_stream.rdbuf();
    input_stream.close();

    return file_buffer.str();
}

class UnitTestEnvironment : public testing::Environment {
   public:
    virtual void SetUp() {}

    virtual void TearDown() {}
};

TEST(CartParse, txtFile1)
{
    std::string file_str{read_file("./tests/data/txtFile1.cart")};
    std::vector<uint8_t> file_buf{reinterpret_cast<uint8_t*>(&file_str.front()),
                                  reinterpret_cast<uint8_t*>(&file_str.back() + 1)};
    std::string orig_file_str{read_file("./tests/data/txtFile1")};
    std::vector<uint8_t> orig_file_buf{reinterpret_cast<uint8_t*>(&orig_file_str.front()),
                                       reinterpret_cast<uint8_t*>(&orig_file_str.back() + 1)};
    CartObject carted_file{file_buf};
    EXPECT_EQ(carted_file.decoded_file, orig_file_buf);
    ASSERT_EQ(carted_file.cart_opt_header.size(), 1);
    EXPECT_TRUE(carted_file.cart_opt_header.isMember("name"));
    EXPECT_EQ(carted_file.cart_opt_header["name"].asString(), "txtFile1");
    EXPECT_EQ(carted_file.cart_opt_footer.size(), 4);
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("length"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("md5"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("sha1"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("sha256"));
    EXPECT_EQ(carted_file.cart_opt_footer["length"].asString(), "27");
    EXPECT_EQ(carted_file.cart_opt_footer["md5"].asString(), "5707d69a86728d62548f483d8270543e");
    EXPECT_EQ(carted_file.cart_opt_footer["sha1"].asString(), "4d1b5e94651e1e484b61c18dc6fabb7f77db34b8");
    EXPECT_EQ(carted_file.cart_opt_footer["sha256"].asString(),
              "373002a85b3e92232828099a45892419689b90e3baf5b1c801d0126d43770f95");
}

TEST(CartParse, txtFile1CustomKey)
{
    std::string file_str{read_file("./tests/data/txtFile1-customkey.cart")};
    std::vector<uint8_t> file_buf{reinterpret_cast<uint8_t*>(&file_str.front()),
                                  reinterpret_cast<uint8_t*>(&file_str.back() + 1)};
    std::string orig_file_str{read_file("./tests/data/txtFile1")};
    std::vector<uint8_t> orig_file_buf{reinterpret_cast<uint8_t*>(&orig_file_str.front()),
                                       reinterpret_cast<uint8_t*>(&orig_file_str.back() + 1)};
    std::array<uint8_t, 16> key;
    memcpy(key.data(), "0123456789abcdef", 16);
    // Standard key shoould fail
    ASSERT_THROW(CartObject carted_file{file_buf}, std::runtime_error);
    CartObject carted_file{file_buf, key};
    EXPECT_EQ(carted_file.decoded_file, orig_file_buf);
    EXPECT_EQ(carted_file.cart_opt_header.size(), 1);
    ASSERT_TRUE(carted_file.cart_opt_header.isMember("name"));
    EXPECT_EQ(carted_file.cart_opt_header["name"].asString(), "txtFile1");
    EXPECT_EQ(carted_file.cart_opt_footer.size(), 4);
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("length"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("md5"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("sha1"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("sha256"));
    EXPECT_EQ(carted_file.cart_opt_footer["length"].asString(), "27");
    EXPECT_EQ(carted_file.cart_opt_footer["md5"].asString(), "5707d69a86728d62548f483d8270543e");
    EXPECT_EQ(carted_file.cart_opt_footer["sha1"].asString(), "4d1b5e94651e1e484b61c18dc6fabb7f77db34b8");
    EXPECT_EQ(carted_file.cart_opt_footer["sha256"].asString(),
              "373002a85b3e92232828099a45892419689b90e3baf5b1c801d0126d43770f95");
}

TEST(CartParse, AssemblylineDownload)
{
    std::string file_str{
        read_file("./tests/data/1e2c5f5597a92846330e08a49b4081684d7d8f67f6d1fe655f2bbb182b5727e5.cart")};
    std::vector<uint8_t> file_buf{reinterpret_cast<uint8_t*>(&file_str.front()),
                                  reinterpret_cast<uint8_t*>(&file_str.back() + 1)};
    std::string orig_file_str{
        read_file("./tests/data/1e2c5f5597a92846330e08a49b4081684d7d8f67f6d1fe655f2bbb182b5727e5")};
    std::vector<uint8_t> orig_file_buf{reinterpret_cast<uint8_t*>(&orig_file_str.front()),
                                       reinterpret_cast<uint8_t*>(&orig_file_str.back() + 1)};
    CartObject carted_file{file_buf};
    EXPECT_EQ(carted_file.decoded_file, orig_file_buf);
    EXPECT_EQ(carted_file.cart_opt_header.size(), 1);
    ASSERT_TRUE(carted_file.cart_opt_header.isMember("name"));
    EXPECT_EQ(carted_file.cart_opt_header["name"].asString(),
              "1e2c5f5597a92846330e08a49b4081684d7d8f67f6d1fe655f2bbb182b5727e5");
    EXPECT_EQ(carted_file.cart_opt_footer.size(), 4);
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("length"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("md5"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("sha1"));
    ASSERT_TRUE(carted_file.cart_opt_footer.isMember("sha256"));
    EXPECT_EQ(carted_file.cart_opt_footer["length"].asString(), "48");
    EXPECT_EQ(carted_file.cart_opt_footer["md5"].asString(), "3d11df49e7b9724d9585e3ed0960d3b8");
    EXPECT_EQ(carted_file.cart_opt_footer["sha1"].asString(), "a550adbae3bb0f64fea22f3be98e1c08d5b0dd00");
    EXPECT_EQ(carted_file.cart_opt_footer["sha256"].asString(),
              "1e2c5f5597a92846330e08a49b4081684d7d8f67f6d1fe655f2bbb182b5727e5");
}

int main(int argc, char** argv)
{
    std::setlocale(LC_ALL, "en_US.UTF-8");
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    testing::InitGoogleTest(&argc, argv);
    testing::AddGlobalTestEnvironment(new UnitTestEnvironment());
    int rt{RUN_ALL_TESTS()};
    return rt;
}
