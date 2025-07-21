

void delete_driver_settings(void);
void get_driver_settings(void);
void get_driver_settings_string(void);
void parse_driver_settings_string(void);
void load_driver_settings(void);
void unload_driver_settings(void);
void load_driver_settings_file(void);
void convert_from_stat_beos(void);
void convert_to_stat_beos(void);
void __swap_double(void);
void get_architectures(void);
void get_secondary_architectures(void);
void find_path_etc(void);
void find_paths_etc(void);
void find_path_for_path_etc(void);
void fs_stat_index(void);
void fs_create_index(void);
void find_directory(void);
void _kern_transfer_area(void);
void _kern_get_safemode_option(void);


/* driver API */
void delete_driver_settings(void) {}
void get_driver_settings(void) {}
void get_driver_settings_string(void) {}
void parse_driver_settings_string(void) {}
void load_driver_settings(void) {}
void unload_driver_settings(void) {}
void load_driver_settings_file(void) {}

/* ?? */
void convert_from_stat_beos(void) {}
void convert_to_stat_beos(void) {}
void __swap_double(void) {}
void get_architectures(void) {}
void get_secondary_architectures(void) {}

/* filesystem or similar */
void find_path_etc(void) {}
void find_paths_etc(void) {}
void find_path_for_path_etc(void) {}
void fs_stat_index(void) {}
void fs_create_index(void) {}
void find_directory(void) {}

/* kernel */
void _kern_transfer_area(void) {}
void _kern_get_safemode_option(void) { }
