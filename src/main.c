#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <raylib.h>

#define RAYGUI_WINDOWBOX_STATUSBAR_HEIGHT 32

#include "./fs.h"
#define NOB_IMPLEMENTATION
#include "./nob.h"
#define ARENA_IMPLEMENTATION
#include "./arena.h"
#define RAYGUI_IMPLEMENTATION
#include "./raygui.h"

#define WINDOW_WIDTH 1280
#define WINDOW_HEIGHT 720

enum ui_preview_kind {
    UI_PREVIEW_BIN,
    UI_PREVIEW_PNG,
};

struct ui_preview {
    enum ui_preview_kind kind;
    Image image;
    Texture texture;
};

void ui_load_preview(struct ui_preview *preview, struct fs_file *file) {
    switch (file->type) {
    case FS_FILE_TYPE_PNG: {
        preview->image = LoadImageFromMemory(".png", file->bytes.items, file->bytes.count);
        preview->texture = LoadTextureFromImage(preview->image);
        preview->kind = UI_PREVIEW_PNG;
    } break;
    default:
        preview->kind = UI_PREVIEW_BIN;
    }
}

void ui_unload_preview(struct ui_preview *preview) {
    switch (preview->kind) {
    case UI_PREVIEW_PNG:
        if (IsImageValid(preview->image)) UnloadImage(preview->image);
        if (IsTextureValid(preview->texture)) UnloadTexture(preview->texture);
        memset(&preview->image, 0, sizeof(preview->image));
        memset(&preview->texture, 0, sizeof(preview->texture));
        break;
    case UI_PREVIEW_BIN:
        break; // Nothing
    default:
        assert(0 && "unreachable");
    }
}

struct ui_text_list {
    char **items;
    size_t count;
    size_t capacity;
};

void ui_text_list_reset(struct ui_text_list *list) {
    for (size_t i = 0; i < list->count; ++i) {
        free(list->items[i]);
    }
    list->count = 0;
}

void ui_text_list_add(struct ui_text_list *list, const char *text, const char *subtext) {
    size_t full_text_size = strlen(text) + strlen(subtext) + 4;
    char *full_text = malloc(full_text_size);
    snprintf(full_text, full_text_size, "%s (%s)", text, subtext);
    full_text[full_text_size - 1] = '\0';
    nob_da_append(list, full_text);
}

void DrawProgressReport(struct fs_progress_report report) {
    int margin = 10;
    int bar_h = 30;

    int report_w = 360;
    int report_h = RAYGUI_WINDOWBOX_STATUSBAR_HEIGHT
        + (report.bars_count * (bar_h + margin)) + margin;

    int report_x = (WINDOW_WIDTH - report_w) / 2;
    int report_y = (WINDOW_HEIGHT - report_h) / 2;

    Rectangle report_rect = { report_x, report_y, report_w, report_h };
    GuiPanel(report_rect, "Scanning...");

    for (size_t i = 0; i < report.bars_count; ++i) {
        float value = (float) report.bars[i].value;
        float max_value = (report.bars[i].max_value == 0)
            ? (float) 1
            : (float) report.bars[i].max_value;

        Rectangle rect = {
            report_x + margin,
            report_y + RAYGUI_WINDOWBOX_STATUSBAR_HEIGHT + margin + ((bar_h + margin) * i),
            report_w - (margin * 2),
            bar_h,
        };
        GuiProgressBar(rect, NULL, NULL, &value, 0.0f, max_value);
    }
}

void DrawFileInfo(Rectangle rect, struct ui_preview *preview, struct fs_file *file) {
    int button_h = 60;
    int label_h = 70;
    int margin = 10;

    Rectangle label_rect = { rect.x + margin, rect.y, rect.width - (margin * 2), label_h };
    GuiLabel(label_rect, TextFormat("File size: %zu byte(s)\n", file->bytes.count));

    Rectangle preview_rect = {
        rect.x + margin,
        rect.y + 30,
        rect.width - (margin * 2),
        rect.height - 110,
    };

    switch (preview->kind) {
    case UI_PREVIEW_PNG: {
        Rectangle source = {0, 0, preview->texture.width, preview->texture.height};
        DrawTexturePro(preview->texture, source, preview_rect, (Vector2){0}, 0.0f, WHITE);
    } break;
    case UI_PREVIEW_BIN:
        break; // TODO
    default:
        assert(0 && "unreachable");
    }

    Rectangle button_rect = {
        rect.x + margin,
        rect.y + rect.height - button_h - margin,
        rect.width - margin * 2,
        button_h,
    };

    if (GuiButton(button_rect, "RECOVER FILE")) {
        const char *file_ext = fs_file_type_get_ext(file->type);
        SaveFileData(TextFormat("recovered.%s", file_ext), file->bytes.items, file->bytes.count);
    }
}

int main(void) {
    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WINDOW_WIDTH, WINDOW_HEIGHT, "Filestein");

    Arena arena = {0};
    Arena recovered_files_arena = {0};

    struct fs_files recovered_files = {0};
    struct fs_mount_points mount_points = {0};
    if (!fs_get_mount_points(&arena, &mount_points)) {
        fprintf(stderr, "Error: could not get mount points\n");
        exit(1);
    }

    if (mount_points.count <= 0) {
        fprintf(stderr, "Error: no valid mount points were found\n");
        exit(1);
    }

    Nob_String_Builder mount_list = {0};
    nob_sb_append_cstr(&mount_list, "CHOOSE DEVICE;");
    for (size_t i = 0; i < mount_points.count; ++i) {
        struct fs_mount_point *mount_point = &mount_points.items[i];
        nob_sb_appendf(&mount_list, "%s (%s)", mount_point->path, mount_point->device_path);
        if (i < mount_points.count - 1) nob_sb_append_cstr(&mount_list, ";");
    }
    nob_sb_append_null(&mount_list);

    struct ui_preview preview = {0};
    struct ui_text_list file_list = {0};
    int scroll_index = 0;
    int last_file_index = -1;
    int file_index = -1;
    void *scan_id = NULL;
    bool edit_mode = false;
    int device_index = 0;

    Font font = LoadFont("assets/Iosevka-Regular.ttf");
    SetTextureFilter(font.texture, TEXTURE_FILTER_TRILINEAR);
    GuiSetFont(font);

    GuiSetStyle(DEFAULT, TEXT_SIZE, 26);
    GuiSetStyle(DEFAULT, TEXT_COLOR_NORMAL, 0x444444FF);
    GuiSetStyle(DEFAULT, TEXT_COLOR_FOCUSED, 0x444444FF);
    GuiSetStyle(DEFAULT, TEXT_COLOR_PRESSED, 0x444444FF);
    GuiSetStyle(DEFAULT, TEXT_SPACING, 2);
    GuiSetStyle(DEFAULT, TEXT_PADDING, 4);
    GuiSetStyle(DEFAULT, BORDER_COLOR_FOCUSED, GuiGetStyle(DEFAULT, BORDER_COLOR_NORMAL));
    GuiSetStyle(DEFAULT, TEXT_LINE_SPACING, 26);
    GuiSetStyle(LISTVIEW, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
    GuiSetStyle(DROPDOWNBOX, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
    GuiSetStyle(PROGRESSBAR, PROGRESS_PADDING, 0);

    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(GetColor(GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));

        if (scan_id != NULL) GuiDisable();

        if (edit_mode) GuiLock();
        Rectangle file_list_rect = { 10, 60, 860, 650 };
        GuiListViewEx(file_list_rect, (const char **)file_list.items, file_list.count, &scroll_index, &file_index, NULL);
        GuiUnlock();

        Rectangle mounts_dropdown_rect = { 10, 10, 600, 40 };
        if (GuiDropdownBox(mounts_dropdown_rect, mount_list.items, &device_index, edit_mode)) {
            edit_mode = !edit_mode;
        }

        if (device_index == 0) GuiDisable();
        Rectangle scan_button_rect = { 620, 10, 100, 40 };
        if (GuiButton(scan_button_rect, "SCAN")) {
            ui_text_list_reset(&file_list);
            file_index = -1;
            recovered_files.count = 0;
            arena_reset(&recovered_files_arena);

            struct fs_mount_point *mount_point = &mount_points.items[device_index - 1];
            scan_id = fs_scan_mount_point(&recovered_files_arena, mount_point, &recovered_files);
            if (scan_id == NULL) {
                fprintf(stderr, "Error: could not begin scan of `%s`\n", mount_point->path);
            }
        }
        GuiEnable();

        Rectangle file_info_panel = { 880, 60, 390, 650 };
        GuiPanel(file_info_panel, "FILE INFO");

        Rectangle file_info_rect = file_info_panel;
        file_info_rect.y += RAYGUI_WINDOWBOX_STATUSBAR_HEIGHT;
        file_info_rect.height -= RAYGUI_WINDOWBOX_STATUSBAR_HEIGHT;

        if (file_index >= 0 && (size_t) file_index < recovered_files.count) {
            struct fs_file *file = &recovered_files.items[file_index];
            DrawFileInfo(file_info_rect, &preview, file);
        } else {
            GuiSetStyle(LABEL, TEXT_ALIGNMENT, TEXT_ALIGN_MIDDLE);
            GuiLabel(file_info_rect, "SELECT A FILE TO\nSEE ITS INFORMATION");
            GuiSetStyle(LABEL, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
        }

        if (last_file_index != file_index) {
            ui_unload_preview(&preview);
            if (file_index >= 0) {
                struct fs_file *file = &recovered_files.items[file_index];
                ui_load_preview(&preview, file);
            }
        }

        if (scan_id != NULL) {
            struct fs_progress_report report = fs_scan_get_progress_report(scan_id);
            if (report.done) {
                for (size_t i = 0; i < recovered_files.count; ++i) {
                    struct fs_file *file = &recovered_files.items[i];
                    ui_text_list_add(&file_list, file->name, fs_file_type_to_cstr(file->type));
                }
                scan_id = NULL;
            }
            DrawProgressReport(report);
        }

        last_file_index = file_index;
        EndDrawing();
    }

    arena_free(&recovered_files_arena);
    arena_free(&arena);
    CloseWindow();
    return 0;
}
