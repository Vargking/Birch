#include "synthetic_apk.h"
#include "birch/guard/fake.h"
#include "birch/io/file.h"

#include <filesystem>
#include <iostream>

int main(int argc, char** argv) {
    try {
        if (argc != 2) return 2;
        const std::filesystem::path directory(argv[1]);
        std::filesystem::create_directories(directory);
        const auto dex = birch::guard::BuildFakeDex({"Lcli/test/", 2U, 2U, 42U});
        birch::io::WriteBinaryFile(directory / "classes.dex", dex);
        birch::io::WriteBinaryFile(directory / "input.apk", birch::test::ApkWithDex(dex).Write());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
