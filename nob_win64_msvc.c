#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "./src/nob.h"

#define BUILD_DIR "build"
#define RAYLIB_BUILD_DIR BUILD_DIR"\\raylib"

#define RAYLIB_SRC_DIR "deps\\raylib-5.5\\src"
#define RAYLIB_BIN_DIR RAYLIB_BUILD_DIR"\\msvc"

#define cc_with_flags(cmd)                      \
    cmd_append((cmd),                           \
               "cl.exe",                        \
               "/Z7",                           \
               "/std:c11",                      \
               "/I", RAYLIB_SRC_DIR)            \

#define cc_add_libs(cmd)                        \
    cmd_append((cmd),                           \
               "/link",                         \
               "/LIBPATH:"RAYLIB_BIN_DIR,       \
               "raylib.lib",                    \
               "Winmm.lib", "gdi32.lib",        \
               "User32.lib", "Shell32.lib",     \
               "Ole32.lib", "comdlg32.lib")     \

#define cc_with_raylib_flags(cmd)                               \
    cmd_append((cmd),                                           \
               "cl.exe",                                        \
               "/Z7",                                           \
               "/DPLATFORM_DESKTOP",                            \
               "/I", RAYLIB_SRC_DIR"\\external\\glfw\\include") \

#define cc_no_link(cmd) cmd_append((cmd), "/c")
#define cc_output_obj(cmd, output_path) cmd_append((cmd), nob_temp_sprintf("/Fo%s", (output_path)))
#define cc_output_exe(cmd, output_path) cmd_append((cmd), nob_temp_sprintf("/Fe%s", (output_path)))
#define cc_input(cmd, ...) cmd_append((cmd), __VA_ARGS__)

bool build_raylib(Cmd *cmd) {
    if (!nob_mkdir_if_not_exists(RAYLIB_BUILD_DIR)) {
        return false;
    }
    if (!nob_mkdir_if_not_exists(RAYLIB_BIN_DIR)) {
        return false;
    }

    const char *modules[] = {
        "rcore",
        "raudio",
        "rglfw",
        "rmodels",
        "rshapes",
        "rtext",
        "rtextures",
        "utils",
    };

    Procs procs = {0};
    for (size_t i = 0; i < NOB_ARRAY_LEN(modules); ++i) {
        const char *input_path = nob_temp_sprintf(RAYLIB_SRC_DIR"\\%s.c", modules[i]);
        const char *output_path = nob_temp_sprintf("%s\\%s.obj", RAYLIB_BIN_DIR, modules[i]);

        if (nob_needs_rebuild(output_path, &input_path, 1)) {
            cc_with_raylib_flags(cmd);
            cc_no_link(cmd);
            cc_input(cmd, input_path);
            cc_output_obj(cmd, output_path);
            da_append(&procs, nob_cmd_run_async_and_reset(cmd));
        }
    }

    if (!nob_procs_wait_and_reset(&procs)) {
        return false;
    }

    nob_cmd_append(cmd, "lib");
    for (size_t i = 0; i < NOB_ARRAY_LEN(modules); ++i) {
        const char *input_path = nob_temp_sprintf("%s\\%s.obj", RAYLIB_BIN_DIR, modules[i]);
        nob_cmd_append(cmd, input_path);
    }
    nob_cmd_append(cmd, nob_temp_sprintf("/OUT:%s\\raylib.lib", RAYLIB_BIN_DIR));
    if (!nob_cmd_run_sync_and_reset(cmd)) {
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF_PLUS(argc, argv, "src/nob.h");

    if (!nob_mkdir_if_not_exists(BUILD_DIR)) {
        exit(1);
    }

    Cmd cmd = {0};
    if (!build_raylib(&cmd)) {
        nob_log(NOB_ERROR, "could not build raylib");
        exit(1);
    }

    cc_with_flags(&cmd);
    cc_output_obj(&cmd, BUILD_DIR"\\");
    cc_output_exe(&cmd, BUILD_DIR"\\filestein.exe");
    cc_input(&cmd, "src\\main.c", "src\\fs.c", "src\\scan.c");
    cc_add_libs(&cmd);
    if (!nob_cmd_run_sync_and_reset(&cmd)) {
        nob_log(NOB_ERROR, "could not build filestein");
        exit(1);
    }

    return 0;
}
