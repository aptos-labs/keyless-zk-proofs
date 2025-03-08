#pragma once

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace BinFileUtils
{

class FileLoader
{
public:
    FileLoader(std::string_view const& fileName)
    {
        struct stat sb;

        fd = ::open(fileName.data(), O_RDONLY);
        if (fd == -1)
        {
            throw std::system_error(errno, std::generic_category(), "open");
        }

        if (::fstat(fd, &sb) == -1)
        { /* To obtain file size */
            ::close(fd);
            throw std::system_error(errno, std::generic_category(), "fstat");
        }

        size = sb.st_size;

        auto mapped = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mapped == MAP_FAILED)
        {
            ::close(fd);
            throw std::system_error(errno, std::generic_category(), "mmap");
        }

        addr = reinterpret_cast<char*>(mapped);
    }

    ~FileLoader()
    {
        ::munmap(addr, size);
        ::close(fd);
    }

    char*       dataBuffer() { return addr; }
    std::size_t dataSize() const { return size; }

private:
    char*       addr;
    std::size_t size;
    int         fd;
};

} // namespace BinFileUtils
