cmake_minimum_required(VERSION 3.14)

project(QtDHCPServer LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Core Network REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core Network REQUIRED)

#add_executable(DHCPServer
#  dhcpserver.h
#  dhcpserver.cpp
#  main.cpp
#)

add_library(DHCPServer OBJECT
  dhcpserver.h
  dhcpserver.cpp
)

target_link_libraries(DHCPServer
    PRIVATE Qt${QT_VERSION_MAJOR}::Core
    PRIVATE Qt${QT_VERSION_MAJOR}::Network
)
