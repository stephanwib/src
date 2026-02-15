#include <stdio.h>
#include "OS.h"

#define STUB_WARNING() \
    fprintf(stderr, "STUB CALLED: %s() in %s:%d\n", __func__, __FILE__, __LINE__)

/* Prototypes */
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
void _kern_transfer_area(void);
void _kern_get_safemode_option(void);
void _kern_get_next_disk_device_id(void);
void _kern_find_disk_device(void);
void _kern_find_partition(void);
void _kern_find_file_disk_device(void);
void _kern_get_disk_device_data(void);
void _kern_register_file_device(void);
void _kern_unregister_file_device(void);
void _kern_get_file_disk_device_path(void);
void _kern_get_disk_system_info(void);
void _kern_get_next_disk_system_info(void);
void _kern_find_disk_system(void);
void _kern_defragment_partition(void);
void _kern_repair_partition(void);
void _kern_resize_partition(void);
void _kern_move_partition(void);
void _kern_set_partition_name(void);
void _kern_set_partition_content_name(void);
void _kern_set_partition_type(void);
void _kern_set_partition_parameters(void);
void _kern_set_partition_content_parameters(void);
void _kern_initialize_partition(void);
void _kern_uninitialize_partition(void);
void _kern_create_child_partition(void);
void _kern_delete_child_partition(void);
void _kern_start_watching_disks(void);
void _kern_stop_watching_disks(void);
void fs_mount_volume(void);
void fs_unmount_volume(void);

status_t __start_watching_system(int32 object, uint32 flags, port_id port, int32 token);
status_t __stop_watching_system(int32 object, uint32 flags, port_id port, int32 token);

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

/* kernel */
void _kern_transfer_area(void)              { STUB_WARNING(); }
void _kern_get_safemode_option(void)        { STUB_WARNING(); }

/* disk device */
void _kern_get_next_disk_device_id(void) { STUB_WARNING(); }
void _kern_find_disk_device(void) { STUB_WARNING(); }
void _kern_find_partition(void) { STUB_WARNING(); }
void _kern_find_file_disk_device(void) { STUB_WARNING(); }
void _kern_get_disk_device_data(void) { STUB_WARNING(); }
void _kern_register_file_device(void) { STUB_WARNING(); }
void _kern_unregister_file_device(void) { STUB_WARNING(); }
void _kern_get_file_disk_device_path(void) { STUB_WARNING(); }

/* disk systems */
void _kern_get_disk_system_info(void) { STUB_WARNING(); }
void _kern_get_next_disk_system_info(void) { STUB_WARNING(); }
void _kern_find_disk_system(void) { STUB_WARNING(); }

/* disk device modification */
void _kern_defragment_partition(void) { STUB_WARNING(); }
void _kern_repair_partition(void) { STUB_WARNING(); }
void _kern_resize_partition(void) { STUB_WARNING(); }
void _kern_move_partition(void) { STUB_WARNING(); }
void _kern_set_partition_name(void) { STUB_WARNING(); }
void _kern_set_partition_content_name(void) { STUB_WARNING(); }
void _kern_set_partition_type(void) { STUB_WARNING(); }
void _kern_set_partition_parameters(void) { STUB_WARNING(); }
void _kern_set_partition_content_parameters(void) { STUB_WARNING(); }
void _kern_initialize_partition(void) { STUB_WARNING(); }
void _kern_uninitialize_partition(void) { STUB_WARNING(); }
void _kern_create_child_partition(void) { STUB_WARNING(); }
void _kern_delete_child_partition(void) { STUB_WARNING(); }

/* disk change notification */
void _kern_start_watching_disks(void) { STUB_WARNING(); }
void _kern_stop_watching_disks(void) { STUB_WARNING(); }


void fs_mount_volume(void) { STUB_WARNING(); }
void fs_unmount_volume(void) { STUB_WARNING(); }



status_t
__start_watching_system(int32 object, uint32 flags, port_id port, int32 token)
{
	return B_ERROR;
}


status_t
__stop_watching_system(int32 object, uint32 flags, port_id port, int32 token)
{
	return B_ERROR;
}

