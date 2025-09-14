#ifndef NTFS_H_
#define NTFS_H_

#include <stdint.h>

#pragma pack(push, 1)

struct ntfs_pbs {
    uint8_t x86_insts[3];
    uint64_t magic;
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t unused1;
    uint8_t unused2[3];
    uint16_t unused3;
    uint8_t media_descriptor;
    uint16_t unused4;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint32_t hidden_sectors;
    uint32_t unused5;
    uint32_t unused6;
    uint64_t total_sectors;
    uint64_t mft_cluster_number;
    uint64_t mft_mirror_cluster_number;
    uint8_t bytes_or_clusters_per_file_record_segment;
    uint8_t unused7[3];
    uint8_t bytes_or_clusters_per_index_buffer;
    uint8_t unused8[3];
    uint64_t volume_serial_number;
    uint32_t checksum;
    uint8_t bootstrap_code[426];
    uint16_t end_of_sector_marker;
};

struct ntfs_record {
    char record_type[4];
    uint16_t update_sequence_offset;
    uint16_t update_sequence_length;
    uint64_t log_file_sequence_number;
    uint16_t record_sequence_number;
    uint16_t hard_link_count;
    uint16_t attributes_offset;
    uint16_t flags;
    uint32_t bytes_in_use;
    uint32_t bytes_allocated;
    uint64_t parent_record_number;
    uint32_t next_attribute_index;
    uint32_t reserved;
    uint64_t record_number;
};

struct ntfs_attr_standard_info {
    uint64_t creation_time;
    uint64_t altered_time;
    uint64_t mft_changed_time;
    uint64_t last_read_time;
    uint32_t dos_perms;
    uint32_t max_number_versions;
    uint32_t version_number;
    uint32_t class_id;
    uint32_t owner_id;
    uint32_t security_id;
    uint64_t quota_charged;
    uint64_t update_sequence_number;
};

#pragma pack(pop)

#endif // NTFS_H_
