#include <jni2hook/utils/class_file.h>
#include <miniz.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

typedef struct
{
    size_t classes;
    size_t signatures;
    size_t extracted;
    size_t failures;
} dump_stats;

static bool read_file(const char *path, unsigned char **out_data, size_t *out_size)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return false;

    bool ok = fseek(file, 0, SEEK_END) == 0;
    const long length = ok ? ftell(file) : -1;
    ok = length >= 0 && fseek(file, 0, SEEK_SET) == 0;

    unsigned char *data = NULL;
    if (ok)
    {
        const size_t size = (size_t)length;
        data = malloc(size == 0 ? 1 : size);
        ok = data != NULL && fread(data, 1, size, file) == size;
        if (ok)
        {
            *out_data = data;
            *out_size = size;
        }
    }

    if (!ok)
        free(data);
    fclose(file);
    return ok;
}

static bool has_suffix(const char *text, const char *suffix)
{
    const size_t text_length = strlen(text);
    const size_t suffix_length = strlen(suffix);
    return text_length >= suffix_length && strcmp(text + text_length - suffix_length, suffix) == 0;
}

static bool make_directory(const char *path)
{
#if defined(_WIN32)
    const int result = _mkdir(path);
#else
    const int result = mkdir(path, 0755);
#endif
    return result == 0 || errno == EEXIST;
}

static bool create_directories(const char *path)
{
    const size_t length = strlen(path);
    char *copy = malloc(length + 1);
    if (copy == NULL)
        return false;
    memcpy(copy, path, length + 1);

    for (size_t i = 0; i < length; i++)
        if (copy[i] == '\\')
            copy[i] = '/';

    bool ok = true;
    for (size_t i = 1; i < length; i++)
    {
        if (copy[i] != '/')
            continue;
        if (i == 2 && copy[1] == ':')
            continue;

        copy[i] = '\0';
        if (copy[0] != '\0' && !make_directory(copy))
        {
            ok = false;
            break;
        }
        copy[i] = '/';
    }

    if (ok && length != 0)
        ok = make_directory(copy);
    free(copy);
    return ok;
}

static bool archive_path_is_safe(const char *path)
{
    if (path[0] == '\0' || path[0] == '/' || path[0] == '\\')
        return false;

    const char *component = path;
    for (const char *cursor = path;; cursor++)
    {
        if (*cursor == ':')
            return false;
        if (*cursor != '/' && *cursor != '\\' && *cursor != '\0')
            continue;

        const size_t length = (size_t)(cursor - component);
        if (length == 2 && component[0] == '.' && component[1] == '.')
            return false;
        if (*cursor == '\0')
            return true;
        component = cursor + 1;
    }
}

static char *extracted_path(const char *directory, const char *entry)
{
    const size_t directory_length = strlen(directory);
    const size_t entry_length = strlen(entry);
    const bool separator = directory_length != 0 && directory[directory_length - 1] != '/' &&
                           directory[directory_length - 1] != '\\';
    char *path = malloc(directory_length + (separator ? 1u : 0u) + entry_length + 1u);
    if (path == NULL)
        return NULL;

    memcpy(path, directory, directory_length);
    size_t offset = directory_length;
    if (separator)
        path[offset++] = '/';
    for (size_t i = 0; i < entry_length; i++)
        path[offset++] = entry[i] == '\\' ? '/' : entry[i];
    path[offset] = '\0';
    return path;
}

static bool create_parent_directories(char *path)
{
    char *separator = strrchr(path, '/');
    if (separator == NULL)
        return true;

    *separator = '\0';
    const bool ok = create_directories(path);
    *separator = '/';
    return ok;
}

static bool extract_entry(mz_zip_archive *archive, mz_uint index,
                          const mz_zip_archive_file_stat *file,
                          const char *directory, bool is_directory)
{
    if (!archive_path_is_safe(file->m_filename))
    {
        fprintf(stderr, "refusing unsafe archive path: %s\n", file->m_filename);
        return false;
    }

    char *path = extracted_path(directory, file->m_filename);
    if (path == NULL)
        return false;

    bool ok;
    if (is_directory)
        ok = create_directories(path);
    else
        ok = create_parent_directories(path) &&
             mz_zip_reader_extract_to_file(archive, index, path, 0);

    if (!ok)
        fprintf(stderr, "cannot extract %s\n", file->m_filename);
    free(path);
    return ok;
}

static bool get_class_name(const ClassFile *class_file, const u1 **out_name, u2 *out_length)
{
    const cp_info *entry = constant_pool_at(&class_file->constant_pool, class_file->this_class);
    return entry != NULL && entry->tag == JVM_CONSTANT_Class &&
           constant_pool_utf8(&class_file->constant_pool, entry->u.class_info.name_index, out_name, out_length);
}

static bool write_class_name(FILE *output, const u1 *name, u2 length)
{
    for (u2 i = 0; i < length; i++)
    {
        const int character = name[i] == '/' ? '.' : name[i];
        if (fputc(character, output) == EOF)
            return false;
    }
    return true;
}

static bool write_utf8(FILE *output, const u1 *text, u2 length)
{
    return length == 0 || fwrite(text, 1, length, output) == length;
}

static void mask_bytes(bool *masked, u4 code_length, u4 start, u4 count)
{
    if (start >= code_length)
        return;
    if (count > code_length - start)
        count = code_length - start;
    for (u4 i = 0; i < count; i++)
        masked[start + i] = true;
}

static bool write_signature(FILE *output, const code_attribute *code)
{
    instruction_list instructions;
    const classfile_status parse_status = instruction_list_parse(code->code, code->code_length, &instructions);
    if (parse_status != CLASSFILE_OK)
        return false;

    bool *masked = calloc(code->code_length == 0 ? 1 : code->code_length, sizeof(*masked));
    if (masked == NULL)
    {
        instruction_list_free(&instructions);
        return false;
    }

    for (u4 i = 0; i < instructions.count; i++)
    {
        const instruction *node = &instructions.items[i];
        const u4 operand = node->offset + 1u + (node->wide ? 1u : 0u);

        switch (node->kind)
        {
        case OPERAND_CONSTANT:
            mask_bytes(masked, code->code_length, operand, node->opcode == JVM_OPC_ldc ? 1u : 2u);
            break;
        case OPERAND_CP_INDEX:
        case OPERAND_INVOKE_INTERFACE:
        case OPERAND_INVOKE_DYNAMIC:
        case OPERAND_MULTIANEWARRAY:
            mask_bytes(masked, code->code_length, operand, 2u);
            break;
        case OPERAND_BRANCH:
            mask_bytes(masked, code->code_length, operand, 2u);
            break;
        case OPERAND_BRANCH_WIDE:
            mask_bytes(masked, code->code_length, operand, 4u);
            break;
        case OPERAND_TABLE_SWITCH:
        case OPERAND_LOOKUP_SWITCH:
        {
            const u4 length = instruction_length_at(node, node->offset);
            if (length > 1u)
                mask_bytes(masked, code->code_length, node->offset + 1u, length - 1u);
            break;
        }
        default:
            break;
        }
    }

    bool ok = true;
    for (u4 i = 0; i < code->code_length; i++)
    {
        if (i != 0 && fputc(' ', output) == EOF)
        {
            ok = false;
            break;
        }

        if (masked[i])
            ok = fputs("??", output) >= 0;
        else
            ok = fprintf(output, "%02X", (unsigned int)code->code[i]) >= 0;

        if (!ok)
            break;
    }

    free(masked);
    instruction_list_free(&instructions);
    return ok;
}

static bool dump_class(FILE *output, const unsigned char *data, size_t size, const char *source, dump_stats *stats)
{
    ClassFile *class_file = NULL;
    const classfile_status parse_status = classfile_parse(data, size, &class_file);
    if (parse_status != CLASSFILE_OK)
    {
        fprintf(stderr, "%s: %s\n", source, classfile_status_message(parse_status));
        stats->failures++;
        return false;
    }

    const u1 *class_name = NULL;
    u2 class_name_length = 0;
    if (!get_class_name(class_file, &class_name, &class_name_length))
    {
        fprintf(stderr, "%s: invalid class name\n", source);
        classFile_destroy(class_file);
        stats->failures++;
        return false;
    }

    bool ok = true;
    stats->classes++;
    for (u2 i = 0; i < class_file->methods.count; i++)
    {
        const member_info *method = &class_file->methods.items[i];
        const u1 *method_name = NULL;
        const u1 *descriptor = NULL;
        u2 method_name_length = 0;
        u2 descriptor_length = 0;
        if (!constant_pool_utf8(&class_file->constant_pool, method->name_index,
                                &method_name, &method_name_length) ||
            !constant_pool_utf8(&class_file->constant_pool, method->descriptor_index,
                                &descriptor, &descriptor_length))
        {
            fprintf(stderr, "%s: invalid method name or descriptor\n", source);
            stats->failures++;
            ok = false;
            continue;
        }

        const attribute_info *attribute =
            attribute_list_find(&method->attributes, &class_file->constant_pool, "Code");
        if (attribute == NULL)
            continue;

        code_attribute code;
        code_attribute_init(&code);
        const classfile_status code_status = code_attribute_parse(attribute, &code);
        if (code_status != CLASSFILE_OK)
        {
            fprintf(stderr, "%s: %s\n", source, classfile_status_message(code_status));
            code_attribute_free(&code);
            stats->failures++;
            ok = false;
            continue;
        }

        const bool written =
            write_class_name(output, class_name, class_name_length) &&
            fputc('.', output) != EOF &&
            write_utf8(output, method_name, method_name_length) &&
            write_utf8(output, descriptor, descriptor_length) &&
            fputs(" | ", output) >= 0 && write_signature(output, &code) &&
            fputc('\n', output) != EOF;
        code_attribute_free(&code);

        if (!written)
        {
            fprintf(stderr, "%s: could not write signature\n", source);
            stats->failures++;
            ok = false;
            break;
        }
        stats->signatures++;
    }

    classFile_destroy(class_file);
    return ok;
}

static bool dump_class_file(FILE *output, const char *target, dump_stats *stats)
{
    unsigned char *data = NULL;
    size_t size = 0;
    if (!read_file(target, &data, &size))
    {
        fprintf(stderr, "cannot read %s\n", target);
        return false;
    }

    const bool ok = dump_class(output, data, size, target, stats);
    free(data);
    return ok;
}

static bool dump_archive(FILE *output, const char *target,
                         const char *extract_directory, dump_stats *stats)
{
    mz_zip_archive archive;
    memset(&archive, 0, sizeof(archive));

    if (!mz_zip_reader_init_file(&archive, target, 0))
    {
        fprintf(stderr, "cannot open %s: %s\n", target, mz_zip_get_error_string(mz_zip_get_last_error(&archive)));
        return false;
    }

    bool ok = extract_directory == NULL || create_directories(extract_directory);
    if (!ok)
        fprintf(stderr, "cannot create extraction directory %s\n", extract_directory);

    const mz_uint file_count = mz_zip_reader_get_num_files(&archive);
    for (mz_uint i = 0; i < file_count; i++)
    {
        mz_zip_archive_file_stat file;
        if (!mz_zip_reader_file_stat(&archive, i, &file))
        {
            fprintf(stderr, "%s: cannot read archive entry %u\n", target, i);
            stats->failures++;
            ok = false;
            continue;
        }

        const bool is_directory = mz_zip_reader_is_file_a_directory(&archive, i);
        if (extract_directory != NULL)
        {
            if (extract_entry(&archive, i, &file, extract_directory, is_directory))
            {
                if (!is_directory)
                    stats->extracted++;
            }
            else
            {
                stats->failures++;
                ok = false;
            }
        }

        if (is_directory || !has_suffix(file.m_filename, ".class"))
            continue;

        size_t size = 0;
        void *data = mz_zip_reader_extract_to_heap(&archive, i, &size, 0);
        if (data == NULL)
        {
            fprintf(stderr, "%s: cannot extract %s\n", target, file.m_filename);
            stats->failures++;
            ok = false;
            continue;
        }

        if (!dump_class(output, data, size, file.m_filename, stats))
            ok = false;
        mz_free(data);
    }

    if (!mz_zip_reader_end(&archive))
        ok = false;
    return ok;
}

static int target_kind(const char *target)
{
    unsigned char magic[4];
    FILE *file = fopen(target, "rb");
    if (file == NULL)
        return 0;
    const bool read = fread(magic, 1, sizeof(magic), file) == sizeof(magic);
    fclose(file);

    if (!read)
        return 0;
    if (magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE)
        return 1;
    if (magic[0] == 'P' && magic[1] == 'K')
        return 2;
    return 0;
}

int main(int argc, char **argv)
{
    const bool extract_requested = argc == 5 &&
                                   (strcmp(argv[3], "--extract") == 0 ||
                                    strcmp(argv[3], "-x") == 0);
    if (argc != 3 && !extract_requested)
    {
        fprintf(stderr,
                "usage: %s <target.class|target.jar> <output.txt> "
                "[--extract <directory>]\n",
                argv[0]);
        return 2;
    }

    if (strcmp(argv[1], argv[2]) == 0)
    {
        fprintf(stderr, "target and output must be different files\n");
        return 2;
    }

    const int kind = target_kind(argv[1]);
    if (kind == 0)
    {
        fprintf(stderr, "%s is not a class file or ZIP/JAR archive\n", argv[1]);
        return 1;
    }
    if (extract_requested && kind != 2)
    {
        fprintf(stderr, "--extract requires a ZIP/JAR archive\n");
        return 2;
    }

    FILE *output = fopen(argv[2], "w");
    if (output == NULL)
    {
        fprintf(stderr, "cannot create %s\n", argv[2]);
        return 1;
    }

    dump_stats stats = {0};
    const bool dumped = kind == 1 ? dump_class_file(output, argv[1], &stats)
                                  : dump_archive(output, argv[1],
                                                 extract_requested ? argv[4] : NULL,
                                                 &stats);
    const bool closed = fclose(output) == 0;

    if (!dumped || !closed || stats.failures != 0 || stats.signatures == 0)
    {
        if (stats.signatures == 0)
            fprintf(stderr, "no bytecode signatures found\n");
        return 1;
    }

    printf("wrote %zu signatures from %zu classes to %s\n", stats.signatures, stats.classes, argv[2]);
    if (extract_requested)
        printf("extracted %zu files to %s\n", stats.extracted, argv[4]);
    return 0;
}
