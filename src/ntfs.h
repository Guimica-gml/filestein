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

#pragma pack(pop)

#endif // NTFS_H_
