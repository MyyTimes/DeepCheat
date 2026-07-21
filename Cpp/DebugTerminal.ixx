export module DebugTerminal;

import std;

export namespace Terminal
{
    inline constexpr std::string_view RESET    = "\033[0m";
    inline constexpr std::string_view RED      = "\033[31m";
    inline constexpr std::string_view GREEN    = "\033[32m";
    inline constexpr std::string_view YELLOW   = "\033[33m";
    inline constexpr std::string_view BLUE     = "\033[34m";
    inline constexpr std::string_view MAGENTA  = "\033[35m";
    inline constexpr std::string_view CYAN     = "\033[36m";

    // Bold colors
    inline constexpr std::string_view BBLACK   = "\033[1;30m";
    inline constexpr std::string_view BRED     = "\033[1;31m";
    inline constexpr std::string_view BGREEN   = "\033[1;32m";
    inline constexpr std::string_view BYELLOW  = "\033[1;33m";
    inline constexpr std::string_view BBLUE    = "\033[1;34m";
    inline constexpr std::string_view BMAGENTA = "\033[1;35m";
    inline constexpr std::string_view BCYAN    = "\033[1;36m";
    inline constexpr std::string_view BWHITE   = "\033[1;37m";

    inline constexpr std::string_view BackGround = "\033[48;5;236m";

    // Colored print functions
    template<typename... Args>
    void PrintError(std::format_string<Args...> fmt, Args&&... args)
    {
        std::print("{}", RED);
        std::print(fmt, std::forward<Args>(args)...);
        std::print("{}", RESET);
    }

    template<typename... Args>
    void PrintInfo(std::format_string<Args...> fmt, Args&&... args)
    {
        std::print("{}", YELLOW);
        std::print(fmt, std::forward<Args>(args)...);
        std::print("{}", RESET);
    }

}
