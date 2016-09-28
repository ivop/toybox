/* mkdosfs.c - make an MS-DOS FAT12/16/32 filesystem
 *
 * Copyright (C) 2013 Ivo van Poorten <ivopvp@gmail.com>

USE_MKDOSFS(NEWTOY(mkdosfs, "<1>2vS#s#R#r#n:Ii#h#F#f#Ca", TOYFLAG_SBIN))

config MKDOSFS
  bool "mkdosfs"
  default y
  help
    usage: mkdosfs [options] device [block-count]

    create an MS-DOS FAT12/16/32 filesystem

    options:

    -a          do not align on clusters [default:align]
    -C          create file 'device' of block-count size
    -f num      number of FATs on disk [default:2]
    -F num      size of FAT entries [12, 16 or 32 bits, default:best fit]
    -h num      number of hidden sectors preceding the partition [default:0]
    -i num      volume id [default:time/date based]
    -I          allow full device, i.e. not a partition [default:deny]
    -n string   volume name [default:NO NAME]
    -r num      number of root entries [default:112/224 for fd, 512 for hd]
    -R num      number of reserved sectors [default:1, FAT32:32]
    -s num      sectors per cluster, power of 2, 1-128
    -S num      bytes per logical sector, power of 2, 512-32768
    -v          be verbose
*/

/* options not implemented (yet?)
 *
 * -A       Atari ST variant of FAT12
 * -b num   sector number of boot sector backup, FAT32 only.
 * -c       check for bad blocks
 * -l file  read bad blocks from file
 * -m file  read failed boot message from file
 */

/* extra options for newfs_msdos (not implemented yet):
 * (newfs options between parenthesis, not sure yet how to map them to
 * new mkdosfs options)
 *
 * - don't create a file system: just print out parameters. (-N)
 * - get bootstrap from file. (-B file)
 * - OEM string. (-O string)
 * - block size. (-b num)
 * - templates (-f num (720, 1440, etc...))
 * - override number of drive heads (-h num)
 * - location of info sector (-i num)
 * - override media descriptor (-m num)
 * - override sectors per track (-u num)
 */

/* extra option that neither mkdosfs nor newfs_msdos implements:
 *
 * - specify first cluster of root directory (FAT32 only)
 */

/* [hidden sectors precede the partition/filesystem]
 * --
 * reserved area {
 *      boot sector
 *      [unused space, fat32: fs info sector and backup sector(s)]
 * }
 * fat area {
 *      FAT
 *      optionally backup FAT(s)
 * }
 * root directory area {    ---> FAT12 and FAT16 only(!)
 *      root directory
 * }
 * data area {
 *      1st data sector...
 * }
 * unused { }
 *
 * - some FAT12/16 code does not support more than 1 reserved sector,
 *   therefore it is best to use -a for all FAT12/16 file systems
 * - FAT32 defaults to 32 reserved sectors
 *
 * 0     < FAT12 <= 4084 clusters
 * 4084  < FAT16 <= 65525 clusters
 * 65525 < FAT32
 *
 * - it is best to stay plus or minus 16 clusters away from these borders
 *   because there is a lot of bad FAT code around that miscalculates
 *   the number of clusters
 * - never create a FAT32 fs that can have an allocatable cluster >= 0x0ffffff7
 * - fat_size_16/32 may be bigger than actually needed in order to align
 *   the backup FAT(s) on cluster borders, MUST be padded with zeroes
 * - for FAT32 one MUST use fat_size_32 (fat_size_16 must be 0)
 * - linux does not support more than 1 backup FAT (i.e. 2 in total)
 * - it seems that as of 2004 the backup boot sector MUST (not shall) be at
 *   sector 6
 * - idem for the location of the file system info sector (sector 1)
 *   and its backup (sector 7)
 * - hence, mkdosfs's -b option and newfs_msdos's -i option SHOULD be
 *   ignored, or at least print a big fat warning
 * - number_of_root_entries/32 SHOULD be equal to bytes per sector
 * - note that number of root entries is always 0 on FAT32
 * - on FAT32, the root directory can be anywhere in the data area and
 *   is allocated appropriately in the FAT.
 * - similarly, if the backup root and/or fsinfo sectors are in the data
 *   area, the full cluster must be allocated (see note above about
 *   sectors 6 and 7)
 * - the 1st data cluster (which contains the 1st data sector) is
 *   always called cluster 2. ALWAYS.
 * - fat entries for cluster 0 and 1 are reserved and have special meaning
 * - maximum cluster size is 32kB (32768 bytes), i.e. bytes_per_sector *
 *   sectors_per_cluster MUST NOT exceed this.
 */

#define _LARGEFILE64_SOURCE
#define __STDC_FORMAT_MACROS

#define FOR_mkdosfs
#include "toys.h"
#include <mntent.h>

GLOBALS(
    long f, F, h, i;
    char *n;
    long r, R, s, S;
)

static struct boot_sector {
    uint8_t jump_instruction[3],
            oem_name[8],
            bytes_per_sector[2],
            sectors_per_cluster[1],
            reserved_sectors[2],
            number_of_fats[1],
            number_of_root_entries[2],
            total_number_of_sectors_16[2],
            media_type[1],
            fat_size_16[2],
            sectors_per_track[2],
            number_of_heads[2],
            hidden_sectors[4],
            total_number_of_sectors_32[4];
    union {
        struct {
            uint8_t drive_number[1],
                    reserved1[1],
                    boot_signature[1],
                    volume_id[4],
                    volume_label[11],
                    file_system_type[8];
        } fat1216;
        struct {
            uint8_t fat_size_32[4],
                    extra_flags[2],
                    file_system_version[2],
                    first_cluster_of_root_directory[4],
                    sector_of_file_system_info[2],
                    sector_number_of_backup_boot_sector[2],
                    reserved[12],
                    driver_number[1],
                    reserved1[1],
                    boot_signature[1],
                    volume_id[4],
                    volume_label[11],
                    file_system_type[8];
        } fat32;
    };
    uint8_t empty[420];             /* put "No OS"-code here */
    uint8_t fat_signature[2];       /* 0x55 0xaa */
} *const boot_sector = (void*)toybuf;

static const char *const jump_instruction =
    "\xeb\x58"              /* jmp    0x7c5a */
    "\x90";                 /* nop */

static const char *const bootcode =
    "\xbe\x6d\x7c"          /* mov    $0x7c6d,%si */
    "\xac"                  /* lods   %ds:(%si),%al */
    "\x08\xc0"              /* or     %al,%al */
    "\x74\x09"              /* je     0x7c6b */
    "\xb4\x0e"              /* mov    $0xe,%ah */
    "\xbb\x04\x00"          /* mov    $0x4,%bx */
    "\xcd\x10"              /* int    $0x10 */
    "\xeb\xf2"              /* jmp    0x7c5d */
    "\x74\xfe"              /* je     0x7c6b */
    "No Operating System found\r\n";

static char *oem_name = "MSWIN4.1"; /* recommended OEM name */

static char *volume_label = "NO NAME    ";

static const char *const fat_signature = "\x55\xaa";

/* FAT32 only */

static struct file_system_info_sector {
    uint8_t lead_signature[4],
            reserved1[480],
            structure_signature[4],
            free_count[4],
            next_free[4],
            reserved2[12],
            trail_signature[4];
} *const file_system_info_sector = (void*)toybuf+512;

static unsigned int number_of_heads, sectors_per_track, hidden_sectors,
                    fat_type, bytes_per_sector, sectors_per_cluster,
                    device_number_of_sectors, volume_number_of_sectors,
                    device_number_of_clusters, data_number_of_clusters,
                    cluster_size;

static const char *const fat_type_to_string[] = { "FAT12", "FAT16", "FAT32" };
static const int fat_type_max_clusters[] = { 4084, 65525, 0x0ffffff7 };
static const int fat_bits_per_entry[] = { 12, 16, 32 };

static int power_of_2(int v) {
    int x, y;
    for (x=y=0; x<sizeof(v)*8; x++)
        y += v&1, v>>=1;
    return y==1;
}

/* possibly move to lib/lib.c */
static void xfprintf(FILE *stream, const char *format, ...) {
    va_list va;
    va_start(va, format);
    if (vfprintf(stream, format, va) < 0) perror_exit("write");
}

#define verbose(...) if (flags&FLAG_v) xprintf(__VA_ARGS__)
#define warn(...) xfprintf(stderr, __VA_ARGS__)

void mkdosfs_main(void) {
    unsigned long flags = toys.optflags;
    off64_t device_size, block_count, block_size = BLOCK_SIZE;
    char *device_name = *toys.optargs;
    struct stat statbuf;
    int fd;
 
    memset(toybuf, 0, 1024);  /* XXX check if this is needed */

    /* (create and) open device and determine size */

    if ((fd = open(device_name, O_RDWR)) < 0) {
        if (flags & FLAG_C) {
            char *s = toys.optargs[1], *e;
            if (!s || *s == '\0')
                error_exit("no block-count specified");
            block_count = strtol(s, &e, 10);
            if (*e != '\0')
                error_exit("invalid block-count");
            device_size = block_count * block_size;
            verbose("creating '%s' with %lli blocks of %lli bytes ",
                 device_name, (long long) block_count, (long long) block_size);
            /* create sparse file */
            fd = xcreate(device_name, O_RDWR|O_CREAT|O_TRUNC, 0666);
            xwrite(fd, "\0", 1);
            xlseek(fd, device_size-1, SEEK_SET);
            xwrite(fd, "\0", 1);
        } else perror_exit("cannot open '%s'", device_name);
    }

    device_size = xlseek(fd, 0, SEEK_END);

    verbose("device size = %"PRIi64" bytes\n", device_size);

    /* default values */

    number_of_heads   = 16;
    sectors_per_track = 63;
    hidden_sectors    = 0;
    bytes_per_sector  = 0;

    /* check if it is a block device, if it's mounted, et cetera */

    if (fstat(fd, &statbuf) < 0) perror_exit("fstat");

    if (S_ISBLK(statbuf.st_mode)) {
        struct stat statbuf2;
        struct mntent *entry;
        FILE *mtab;

        /* root fs might not be specified in mtab */
        if (!stat("/dev/root", &statbuf2)) {
            if (statbuf.st_ino == statbuf2.st_ino)
                error_exit("%s is mounted", device_name);
        }

        if (!(mtab = setmntent("/etc/mtab", "r")))
            perror_exit("setmntent");

        while ((entry = getmntent(mtab))) {
            if (!(strcmp(device_name, entry->mnt_fsname)))
                error_exit("%s is mounted", device_name);
        }
        endmntent(mtab);

        if (!(statbuf.st_rdev & 0x000f) && !(flags & FLAG_I))
            error_exit("won't use full device");

        if (1) {    /* linux specific */
            #include <linux/hdreg.h>
            struct hd_geometry geom;
            if (!ioctl(fd, HDIO_GETGEO, &geom)) {
                number_of_heads   = geom.heads;
                sectors_per_track = geom.sectors;
                hidden_sectors    = geom.start;
            };
        }

        /* override with command line values */
        if (flags & FLAG_h) hidden_sectors = TT.h;

        ioctl(fd, BLKSSZGET, &bytes_per_sector);
    }

    if      (flags & FLAG_S)    bytes_per_sector = TT.S;
    else if (!bytes_per_sector) bytes_per_sector = 512;

    if (!power_of_2(bytes_per_sector))
        error_exit("bytes per sector not a power of 2");

    if (bytes_per_sector < 512 || bytes_per_sector > 32768)
        error_exit("bytes per sector out of range");

    verbose("using %i bytes per sector\n", bytes_per_sector);

    /* due to a circular dependency, select fat type by device size */

    if      (device_size <= (  4*1024*1024)) fat_type = 12;
    else if (device_size <= (512*1024*1024)) fat_type = 16;
    else                                     fat_type = 32;

    if      (flags & FLAG_F)                 fat_type = TT.F;

    if (fat_type != 12 && fat_type != 16 && fat_type != 32)
        error_exit("invalid FAT type");

    /* turn 12,16,32 into 0,1,2 */
    fat_type >>= 3;
    fat_type  -= 1;
    if (fat_type == 3) fat_type--;

    verbose("using %s\n", fat_type_to_string[fat_type]);

    device_number_of_sectors = device_size / bytes_per_sector;

    verbose("device has %i sectors\n", device_number_of_sectors);

    if (device_size % bytes_per_sector)
        warn("device size is not a multiple of its sector size\n");

    if (flags & FLAG_s) sectors_per_cluster = TT.s;
    else {
        sectors_per_cluster = 2;
        while (device_number_of_sectors / sectors_per_cluster
                                    > fat_type_max_clusters[fat_type]) {
            sectors_per_cluster <<= 1;
        }
        if (sectors_per_cluster > 128)
            error_exit("device too large for %s", fat_type_to_string[fat_type]);
    }

    if (!power_of_2(sectors_per_cluster))
        error_exit("sectors per cluster is not a power of 2");
    if (sectors_per_cluster < 1 || sectors_per_cluster > 128)
        error_exit("sectors per cluster out of range");

    verbose("using %i sectors per cluster\n", sectors_per_cluster);

    cluster_size = bytes_per_sector * sectors_per_cluster;

    verbose("cluster size = %i bytes\n", cluster_size);

    if (cluster_size > 32768) error_exit("cluster size larger than 32kB");

    device_number_of_clusters = device_number_of_sectors / sectors_per_cluster;

    verbose("device has %i clusters\n", device_number_of_clusters);

    if (device_number_of_clusters > fat_type_max_clusters[fat_type])
        error_exit("too many clusters for %s\n", fat_type_to_string[fat_type]);

    if (device_number_of_clusters > fat_type_max_clusters[fat_type] - 16)
        warn("number of clusters is close to its upper limit. "
             "some systems might not support this!\n");

    if (fat_type) {  /* fat16 and fat32 only */
        if (device_number_of_clusters <= fat_type_max_clusters[fat_type-1] + 16)
            warn("number of clusters is close to its lower limit. "
                 "some systems might not support this!\n");
        if (device_number_of_clusters <= fat_type_max_clusters[fat_type-1])
            warn("number of clusters below %s's lower limit. "
                 "most systems will detect this as %s and misbehave.\n",
                 fat_type_to_string[fat_type], fat_type_to_string[fat_type-1]);
    }

    volume_number_of_sectors = device_number_of_clusters * sectors_per_cluster;

    verbose("volume has %i sectors\n", volume_number_of_sectors);

    /* determine fat_size in sectors, opt. align to cluster size */
    /* number of fats */

    close(fd);
}
