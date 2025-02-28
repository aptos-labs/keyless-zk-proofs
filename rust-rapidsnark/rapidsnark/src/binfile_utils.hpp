#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "fileloader.hpp"

namespace BinFileUtils
{

class BinFile
{
    std::unique_ptr<FileLoader> mapped_file_;

    char*          addr;
    std::uint64_t  size;
    std::ptrdiff_t pos;

    class Section
    {
        char*         start;
        std::uint64_t size;

    public:
        friend BinFile;

        Section(char* _start, std::uint64_t _size)
            : start(_start)
            , size(_size) {};
    };

    std::map<int, std::vector<Section>> sections;
    std::string                         type;
    std::uint32_t                       version;

    Section* readingSection;

private:
    char* data() const { return addr; }

public:
    BinFile() = delete; // No default construction

    BinFile(std::unique_ptr<FileLoader>&& mapped_file,
            std::string expected_type, uint32_t maxVersion);

    void* getSetcionData(std::uint32_t sectionId, std::uint32_t sectionPos = 0);

    template <class T>
    T bit_cast_section_data(std::uint32_t sectionId,
                            std::uint32_t sectionPos = 0)
    {
        static_assert(std::is_trivially_copyable_v<T> &&
                          std::is_trivially_constructible_v<T>,
                      "This implementation requires destination type to be "
                      "trivially copyable and trivially constructible");

        auto it = sections.find(sectionId);
        if (it == sections.end())
        {
            throw std::range_error("Section does not exist: " +
                                   std::to_string(sectionId));
        }

        auto const& section = it->second;

        if (sectionPos + sizeof(T) >= section.size())
        {
            throw std::range_error("Section pos too big. There are " +
                                   std::to_string(section.size()) +
                                   " and it's trying to access section: " +
                                   std::to_string(sectionPos));
        }

        T ret;

        std::memcpy(&ret, std::addressof(section.at(sectionId)), sizeof(T));
        return ret;
    }

    void startReadSection(std::uint32_t sectionId, std::uint32_t setionPos = 0);
    void endReadSection(bool check = true);

    void* getSectionData(std::uint32_t sectionId, std::uint32_t sectionPos = 0);
    std::uint64_t getSectionSize(std::uint32_t sectionId,
                                 std::uint32_t sectionPos = 0);

    std::uint32_t readU32LE();
    std::uint64_t readU64LE();

    void* read(uint64_t l);

    static std::unique_ptr<BinFile> make_from_file(std::string   filename,
                                                   std::string   type,
                                                   std::uint32_t maxVersion)
    {

        auto mapped_file = std::make_unique<FileLoader>(filename);

        // There was a possible memory leak
        return std::make_unique<BinFile>(std::move(mapped_file), type,
                                         maxVersion);
    }
};

} // namespace BinFileUtils
