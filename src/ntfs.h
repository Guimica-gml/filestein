#ifndef NTFS_H_
#define NTFS_H_

#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
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
} Ntfs_Pbs;

typedef struct {
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
} Ntfs_Record;

typedef struct {
    uint32_t attr_type;
    uint32_t length;
    uint8_t non_resident_flag;
    uint8_t name_length;
    uint16_t offset_to_name;
    uint16_t flags;
    uint16_t attr_id;
    union {
        struct {
            uint32_t attr_length;
            uint16_t offset_to_attr;
            uint8_t indexed_flag;
            uint8_t padding;
        } resident;
        struct {
            uint64_t starting_vcn;
            uint64_t last_vcn;
            uint16_t data_runs_offset;
            uint16_t compression_unit_size;
            uint32_t padding;
            uint64_t allocated_attr_length;
            uint64_t real_attr_length;
            uint64_t initialized_stream_length;
        } non_resident;
    };
    char *name;
    uint8_t *content;
} Ntfs_Attr;

#pragma pack(pop)

#endif // NTFS_H_
