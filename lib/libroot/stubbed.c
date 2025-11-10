#include <stdio.h>

#define STUB_WARNING() \
    fprintf(stderr, "STUB CALLED: %s() in %s:%d\n", __func__, __FILE__, __LINE__)

/* driver API */
void delete_driver_settings(void)           { STUB_WARNING(); }
void get_driver_settings(void)              { STUB_WARNING(); }
void get_driver_settings_string(void)       { STUB_WARNING(); }
void parse_driver_settings_string(void)     { STUB_WARNING(); }
void load_driver_settings(void)             { STUB_WARNING(); }
void unload_driver_settings(void)           { STUB_WARNING(); }
void load_driver_settings_file(void)        { STUB_WARNING(); }

/* conversion */
void convert_from_stat_beos(void)           { STUB_WARNING(); }
void convert_to_stat_beos(void)             { STUB_WARNING(); }
void __swap_double(void)                    { STUB_WARNING(); }
void get_architectures(void)                { STUB_WARNING(); }
void get_secondary_architectures(void)      { STUB_WARNING(); }

/* filesystem */
void find_path_etc(void)                    { STUB_WARNING(); }
void find_paths_etc(void)                   { STUB_WARNING(); }
void find_path_for_path_etc(void)           { STUB_WARNING(); }
void fs_stat_index(void)                    { STUB_WARNING(); }
void fs_create_index(void)                  { STUB_WARNING(); }
void find_directory(void)                   { STUB_WARNING(); }

/* kernel */
void _kern_transfer_area(void)              { STUB_WARNING(); }
void _kern_get_safemode_option(void)        { STUB_WARNING(); }
