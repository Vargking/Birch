set(BIRCH_IMGUI_DIR "${PROJECT_SOURCE_DIR}/ImGUI/imgui-1.93.0")
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
set(GLFW_LIBRARY_TYPE STATIC CACHE STRING "" FORCE)
add_subdirectory("${PROJECT_SOURCE_DIR}/ImGUI/glfw-3.4" "${CMAKE_CURRENT_BINARY_DIR}/glfw")
find_package(OpenGL REQUIRED)
find_package(Threads REQUIRED)
add_library(BirchImGui STATIC
    ${BIRCH_IMGUI_DIR}/imgui.cpp
    ${BIRCH_IMGUI_DIR}/imgui_draw.cpp
    ${BIRCH_IMGUI_DIR}/imgui_tables.cpp
    ${BIRCH_IMGUI_DIR}/imgui_widgets.cpp
    ${BIRCH_IMGUI_DIR}/misc/cpp/imgui_stdlib.cpp
    ${BIRCH_IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${BIRCH_IMGUI_DIR}/backends/imgui_impl_opengl3.cpp)
target_include_directories(BirchImGui PUBLIC ${BIRCH_IMGUI_DIR} ${BIRCH_IMGUI_DIR}/backends)
target_link_libraries(BirchImGui PUBLIC glfw OpenGL::GL)
add_library(BirchGuiModel STATIC settings_model.cpp job_controller.cpp)
target_include_directories(BirchGuiModel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(BirchGuiModel PUBLIC BirchGuardLib Threads::Threads)
add_executable(BirchGuardGUI main.cpp guard_window.cpp ios_theme.cpp frame_capture.cpp)
target_link_libraries(BirchGuardGUI PRIVATE BirchImGui BirchGuiModel)
if(WIN32)
    set_target_properties(BirchGuardGUI PROPERTIES WIN32_EXECUTABLE TRUE)
endif()
if(MSVC)
    target_compile_options(BirchGuiModel PRIVATE /W4)
    target_compile_options(BirchGuardGUI PRIVATE /W4)
else()
    target_compile_options(BirchGuiModel PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    target_compile_options(BirchGuardGUI PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()
install(TARGETS BirchGuardGUI RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
