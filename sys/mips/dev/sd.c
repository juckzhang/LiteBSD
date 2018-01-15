/*
 * SD flash card disk driver.
 *
 * Copyright (C) 2014 Serge Vakulenko, <serge@vak.ru>
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that the copyright notice and this
 * permission notice and warranty disclaimer appear in supporting
 * documentation, and that the name of the author not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * The author disclaim all warranties with regard to this
 * software, including all implied warranties of merchantability
 * and fitness.  In no event shall the author be liable for any
 * special, indirect or consequential damages or any damages
 * whatsoever resulting from loss of use, data or profits, whether
 * in an action of contract, negligence or other tortious action,
 * arising out of or in connection with the use or performance of
 * this software.
 */
#include "sd.h"
#if NSD > 0

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/disklabel.h>
#include <sys/systm.h>
#include <sys/dkstat.h>

#include <mips/dev/device.h>
#include <mips/dev/spi.h>
#include <machine/pic32mz.h>

#include <machine/pic32_gpio.h>

#define sdunit(dev)     ((minor(dev) & 8) >> 3)
#define sdpart(dev)     ((minor(dev) & 7))
#define RAWPART         0           /* whole disk */

#define NPARTITIONS     4
#define SECTSIZE        512
#define MBR_MAGIC       0xaa55

#ifndef SD_KHZ
#define SD_KHZ          12500       /* speed 12.5 MHz */
#endif
#ifndef SD_FAST_KHZ
#define SD_FAST_KHZ     25000       /* up to 25 Mhz is allowed by the spec */
#endif
#ifndef SD_FASTEST_KHZ
#define SD_FASTEST_KHZ  50000       /* max speed for pic32mz SPI is 50 MHz */
#endif

#if DEV_BSIZE != 512
#error Only 512-byte block size supported.
#endif

/*
 * The structure of a disk drive.
 */
struct disk {
    /*
     * Partition table.
     */
    struct diskpart part [NPARTITIONS+1];

    /*
     * Card type.
     */
    int     card_type;
#define TYPE_UNKNOWN    0
#define TYPE_SD_LEGACY  1
#define TYPE_SD_II      2
#define TYPE_SDHC       3

    struct spiio spiio;     /* interface to SPI port */
    int     unit;           /* physical unit number */
    int     open;           /* open/closed refcnt */
    int     wlabel;         /* label writable? */
    int     dkindex;        /* disk index for statistics */
    u_int   copenpart;      /* character units open on this drive */
    u_int   bopenpart;      /* block units open on this drive */
    u_int   openpart;       /* all units open on this drive */
    u_char  ocr[4];         /* operation condition register */
    u_char  csd[16];        /* card-specific data */
#define TRANS_SPEED_25MHZ   0x32
#define TRANS_SPEED_50MHZ   0x5a
#define TRANS_SPEED_100MHZ  0x0b
#define TRANS_SPEED_200MHZ  0x2b

    u_short group[6];       /* function group bitmasks */
    int     ma;             /* power consumption */
};

static struct disk sddrives[NSD];       /* Table of units */

#define TIMO_WAIT_WDONE 400000
#define TIMO_WAIT_WIDLE 399000
#define TIMO_WAIT_CMD   100000
#define TIMO_WAIT_WDATA 30000
#define TIMO_READ       90000
#define TIMO_SEND_OP    8000
#define TIMO_CMD        7000
#define TIMO_SEND_CSD   6000
#define TIMO_WAIT_WSTOP 5000

int sd_timo_cmd;                /* Max timeouts, for sysctl */
int sd_timo_send_op;
int sd_timo_send_csd;
int sd_timo_read;
int sd_timo_wait_cmd;
int sd_timo_wait_wdata;
int sd_timo_wait_wdone;
int sd_timo_wait_wstop;
int sd_timo_wait_widle;

/*
 * Definitions for MMC/SDC commands.
 */
#define CMD_GO_IDLE             0       /* CMD0 */
#define CMD_SEND_OP_MMC         1       /* CMD1 (MMC) */
#define CMD_SWITCH_FUNC         6
#define CMD_SEND_IF_COND        8
#define CMD_SEND_CSD            9
#define CMD_SEND_CID            10
#define CMD_STOP                12
#define CMD_SEND_STATUS         13      /* CMD13 */
#define CMD_SET_BLEN            16
#define CMD_READ_SINGLE         17
#define CMD_READ_MULTIPLE       18
#define CMD_SET_BCOUNT          23      /* (MMC) */
#define CMD_SET_WBECNT          23      /* ACMD23 (SDC) */
#define CMD_WRITE_SINGLE        24
#define CMD_WRITE_MULTIPLE      25
#define CMD_SEND_OP_SDC         41      /* ACMD41 (SDC) */
#define CMD_APP                 55      /* CMD55 */
#define CMD_READ_OCR            58

#define DATA_START_BLOCK        0xFE    /* start data for single block */
#define STOP_TRAN_TOKEN         0xFD    /* stop token for write multiple */
#define WRITE_MULTIPLE_TOKEN    0xFC    /* start data for write multiple */

/*
 * Wait while busy, up to 300 msec.
 */
static void sd_wait_ready(struct spiio *io, int limit, int *maxcount)
{
    int i;

    spi_transfer(io, 0xFF);
    for (i=0; i<limit; i++) {
        if (spi_transfer(io, 0xFF) == 0xFF) {
            if (*maxcount < i)
                *maxcount = i;
            return;
        }
    }
    printf("sd: wait_ready(%d) failed\n", limit);
}

/*
 * Send a command and address to SD media.
 * Return response:
 *   FF - timeout
 *   00 - command accepted
 *   01 - command received, card in idle state
 *
 * Other codes:
 *   bit 0 = Idle state
 *   bit 1 = Erase Reset
 *   bit 2 = Illegal command
 *   bit 3 = Communication CRC error
 *   bit 4 = Erase sequence error
 *   bit 5 = Address error
 *   bit 6 = Parameter error
 *   bit 7 = Always 0
 */
static int card_cmd(unsigned int unit, unsigned int cmd, unsigned int addr)
{
    struct spiio *io = &sddrives[unit].spiio;
    int i, reply;

    /* Wait for not busy, up to 300 msec. */
    if (cmd != CMD_GO_IDLE)
        sd_wait_ready(io, TIMO_WAIT_CMD, &sd_timo_wait_cmd);

    /* Send a comand packet (6 bytes). */
    spi_transfer(io, cmd | 0x40);
    spi_transfer(io, addr >> 24);
    spi_transfer(io, addr >> 16);
    spi_transfer(io, addr >> 8);
    spi_transfer(io, addr);

    /* Send cmd checksum for CMD_GO_IDLE.
     * For all other commands, CRC is ignored. */
    if (cmd == CMD_GO_IDLE)
        spi_transfer(io, 0x95);
    else if (cmd == CMD_SEND_IF_COND)
        spi_transfer(io, 0x87);
    else
        spi_transfer(io, 0xFF);

    /* Wait for a response. */
    for (i=0; i<TIMO_CMD; i++)
    {
        reply = spi_transfer(io, 0xFF);
        if (! (reply & 0x80))
        {
            if (sd_timo_cmd < i)
                sd_timo_cmd = i;
            return reply;
        }
    }
    if (cmd != CMD_GO_IDLE)
    {
        printf("sd%d: card_cmd timeout, cmd=%02x, addr=%08x, reply=%02x\n",
            unit, cmd, addr, reply);
    }
    return reply;
}

/*
 * Control an LED to show SD activity
 */
static inline void
sd_led(int val)
{
#ifdef SD_LED_PORT
#ifndef SD_LED_INVERT
    if (val)
        LAT_SET(SD_LED_PORT) = 1 << SD_LED_PIN;
    else
        LAT_CLR(SD_LED_PORT) = 1 << SD_LED_PIN;
#else
    if (val)
        LAT_CLR(SD_LED_PORT) = 1 << SD_LED_PIN;
    else
        LAT_SET(SD_LED_PORT) = 1 << SD_LED_PIN;
#endif
#endif
}

/*
 * Add extra clocks after a deselect
 */
static inline void
sd_deselect(struct spiio *io)
{
    spi_deselect(io);
    spi_transfer(io, 0xFF);
    sd_led(0);
}

/*
 * Select the SPI port, and light the LED
 */
static inline void
sd_select(struct spiio *io)
{
    sd_led(1);
    spi_select(io);
}

/*
 * Initialize a card.
 * Return nonzero if successful.
 */
static int card_init(int unit)
{
    struct disk *u = &sddrives[unit];
    struct spiio *io = &u->spiio;
    int i, reply;
    int timeout = 4;

    /* Slow speed: 250 kHz */
    spi_set_speed(io, 250);

    u->card_type = TYPE_UNKNOWN;

    do {
        /* Unselect the card. */
        sd_deselect(io);

        /* Send 80 clock cycles for start up. */
        for (i=0; i<10; i++)
            spi_transfer(io, 0xFF);

        /* Select the card and send a single GO_IDLE command. */
        sd_select(io);
        timeout--;
        reply = card_cmd(unit, CMD_GO_IDLE, 0);

    } while ((reply != 0x01) && (timeout != 0));

    sd_deselect(io);
    if (reply != 1)
    {
        /* It must return Idle. */
        return 0;
    }

    /* Check SD version. */
    sd_select(io);
    reply = card_cmd(unit, CMD_SEND_IF_COND, 0x1AA);
    if (reply & 4)
    {
        /* Illegal command: card type 1. */
        sd_deselect(io);
        u->card_type = TYPE_SD_LEGACY;
    } else {
        unsigned char response[4];
        response[0] = spi_transfer(io, 0xFF);
        response[1] = spi_transfer(io, 0xFF);
        response[2] = spi_transfer(io, 0xFF);
        response[3] = spi_transfer(io, 0xFF);
        sd_deselect(io);
        if (response[3] != 0xAA)
        {
            printf("sd%d: cannot detect card type, response=%02x-%02x-%02x-%02x\n",
                unit, response[0], response[1], response[2], response[3]);
            return 0;
        }
        u->card_type = TYPE_SD_II;
    }


    /* Send repeatedly SEND_OP until Idle terminates. */
    for (i=0; ; i++)
    {
        sd_select(io);
        card_cmd(unit, CMD_APP, 0);
        reply = card_cmd(unit, CMD_SEND_OP_SDC,
                         (u->card_type == TYPE_SD_II) ? 0x40000000 : 0);
        sd_select(io);
        if (reply == 0)
            break;
        if (i >= TIMO_SEND_OP)
        {
            /* Init timed out. */
            printf("card_init: SEND_OP timed out, reply = %d\n", reply);
            return 0;
        }
    }
    if (sd_timo_send_op < i)
        sd_timo_send_op = i;

    /* If SD2 read OCR register to check for SDHC card. */
    if (u->card_type == TYPE_SD_II)
    {
        sd_select(io);
        reply = card_cmd(unit, CMD_READ_OCR, 0);
        if (reply != 0)
        {
            sd_deselect(io);
            printf("sd%d: READ_OCR failed, reply=%02x\n", unit, reply);
            return 0;
        }
        u->ocr[0] = spi_transfer(io, 0xFF);
        u->ocr[1] = spi_transfer(io, 0xFF);
        u->ocr[2] = spi_transfer(io, 0xFF);
        u->ocr[3] = spi_transfer(io, 0xFF);
        sd_deselect(io);
        if ((u->ocr[0] & 0xC0) == 0xC0)
        {
            u->card_type = TYPE_SDHC;
        }
    }

    /* Fast speed. */
    spi_set_speed(io, SD_KHZ);
    return 1;
}

/*
 * Get the value of CSD register.
 */
static int card_read_csd(int unit)
{
    struct disk *u = &sddrives[unit];
    struct spiio *io = &u->spiio;
    int reply, i;

    sd_select(io);
    reply = card_cmd(unit, CMD_SEND_CSD, 0);
    if (reply != 0) {
        /* Command rejected. */
        sd_deselect(io);
        return 0;
    }
    /* Wait for a response. */
    for (i=0; ; i++) {
        reply = spi_transfer(io, 0xFF);
        if (reply == DATA_START_BLOCK)
            break;
        if (i >= TIMO_SEND_CSD)
        {
            /* Command timed out. */
            sd_deselect(io);
            printf("sd%d: card_size: SEND_CSD timed out, reply = %d\n",
                unit, reply);
            return 0;
        }
    }
    if (sd_timo_send_csd < i)
        sd_timo_send_csd = i;

    /* Read data. */
    for (i=0; i<16; i++) {
        u->csd[i] = spi_transfer(io, 0xFF);
    }
    /* Ignore CRC. */
    spi_transfer(io, 0xFF);
    spi_transfer(io, 0xFF);

    /* Disable the card. */
    sd_deselect(io);
    return 1;
}

/*
 * Get number of sectors on the disk.
 * Return nonzero if successful.
 */
static int card_size(int unit)
{
    struct disk *u = &sddrives[unit];
    unsigned csize, n;
    int nsectors;

    if (! card_read_csd(unit))
        return 0;

    /* CSD register has different structure
     * depending upon protocol version. */
    switch (u->csd[0] >> 6) {
    case 1:                 /* SDC ver 2.00 */
        csize = u->csd[9] + (u->csd[8] << 8) + 1;
        nsectors = csize << 10;
        break;
    case 0:                 /* SDC ver 1.XX or MMC. */
        n = (u->csd[5] & 15) + ((u->csd[10] & 128) >> 7) +
            ((u->csd[9] & 3) << 1) + 2;
        csize = (u->csd[8] >> 6) + (u->csd[7] << 2) +
            ((u->csd[6] & 3) << 10) + 1;
        nsectors = csize << (n - 9);
        break;
    default:                /* Unknown version. */
        return 0;
    }
    return nsectors;
}

/*
 * Use CMD6 to enable high-speed mode.
 */
static void card_high_speed(int unit)
{
    int reply, i;
    struct disk *u = &sddrives[unit];
    struct spiio *io = &u->spiio;
    unsigned char status[64];

    /* Here we set HighSpeed 50MHz.
     * We do not tackle the power and io driver strength yet. */
    spi_select(io);
    reply = card_cmd(unit, CMD_SWITCH_FUNC, 0x80000001);
    if (reply != 0) {
        /* Command rejected. */
        sd_deselect(io);
        return;
    }

    /* Wait for a response. */
    for (i=0; ; i++) {
        reply = spi_transfer(io, 0xFF);
        if (reply == DATA_START_BLOCK)
            break;
        if (i >= 5000) {
            /* Command timed out. */
            sd_deselect(io);
            printf("sd%d: card_size: SWITCH_FUNC timed out, reply = %d\n",
                unit, reply);
            return;
        }
    }

    /* Read 64-byte status. */
    for (i=0; i<64; i++)
        status[i] = spi_transfer(io, 0xFF);

    /* Do at least 8 _slow_ clocks to switch into the HS mode. */
    spi_transfer(io, 0xFF);
    spi_transfer(io, 0xFF);
    sd_deselect(io);

    if ((status[16] & 0xF) == 1) {
        /* The card has switched to high-speed mode. */
        int khz;

        card_read_csd(unit);
        switch (u->csd[3]) {
        default:
            printf("sd%d: Unknown speed csd[3] = %02x\n", unit, u->csd[3]);
            /* fall through... */
        case TRANS_SPEED_25MHZ:
            /* 25 MHz - default clock for high speed mode. */
            khz = SD_FAST_KHZ;
            break;
        case TRANS_SPEED_50MHZ:
            /* 50 MHz - typical clock for SDHC cards. */
            khz = SD_FASTEST_KHZ;
            break;
        case TRANS_SPEED_100MHZ:
            printf("sd%d: fast clock 100MHz\n", unit);
            khz = SD_FASTEST_KHZ;
            break;
        case TRANS_SPEED_200MHZ:
            printf("sd%d: fast clock 200MHz\n", unit);
            khz = SD_FASTEST_KHZ;
            break;
        }
        spi_set_speed(io, khz);
    }

    /* Save function group information for later use. */
    u->ma = status[0] << 8 | status[1];
    u->group[0] = status[12] << 8 | status[13];
    u->group[1] = status[10] << 8 | status[11];
    u->group[2] = status[8] << 8 | status[9];
    u->group[3] = status[6] << 8 | status[7];
    u->group[4] = status[4] << 8 | status[5];
    u->group[5] = status[2] << 8 | status[3];

    printf("sd%d: function groups %x/%x/%x/%x/%x/%x", unit,
        u->group[5] & 0x7fff, u->group[4] & 0x7fff,
        u->group[3] & 0x7fff, u->group[2] & 0x7fff,
        u->group[1] & 0x7fff, u->group[0] & 0x7fff);
    if (u->ma > 0)
        printf(", max current %u mA", u->ma);
    printf("\n");
}

/*
 * Read a block of data.
 * Return nonzero if successful.
 */
static int
card_read(int unit, unsigned int offset, char *data, unsigned int bcount)
{
    struct disk *u = &sddrives[unit];
    struct spiio *io = &u->spiio;
    int reply, i;
//printf("--- %s: unit = %d, blkno = %d, bcount = %d\n", __func__, unit, offset, bcount);

    /* Send read-multiple command. */
    sd_select(io);
    if (u->card_type != TYPE_SDHC)
        offset <<= 9;
//printf("%s: sd_type = %u, offset = %08x\n", __func__, u->card_type, offset);
    reply = card_cmd(unit, CMD_READ_MULTIPLE, offset);
    if (reply != 0)
    {
        /* Command rejected. */
        printf("sd%d: card_read: bad READ_MULTIPLE reply = %d, offset = %08x\n",
            unit, reply, offset);
        sd_deselect(io);
        return 0;
    }

again:
    /* Wait for a response. */
    for (i=0; ; i++)
    {
        reply = spi_transfer(io, 0xFF);
        if (reply == DATA_START_BLOCK)
            break;
        if (i >= TIMO_READ)
        {
            /* Command timed out. */
            printf("sd%d: card_read: READ_MULTIPLE timed out, reply = %d\n",
                unit, reply);
            sd_deselect(io);
            return 0;
        }
    }
    if (sd_timo_read < i)
        sd_timo_read = i;

    /* Read data. */
    if (bcount >= SECTSIZE)
    {
        spi_bulk_read32_be(io, SECTSIZE/4, (int*)data);
//printf("    %08x %08x %08x %08x ...\n",
//((int*)data)[0], ((int*)data)[1], ((int*)data)[2], ((int*)data)[3]);
        data += SECTSIZE;
    } else {
        spi_bulk_read(io, bcount, (unsigned char *)data);
//printf("    %08x %08x %08x %08x ...\n",
//((int*)data)[0], ((int*)data)[1], ((int*)data)[2], ((int*)data)[3]);
        data += bcount;
        for (i=bcount; i<SECTSIZE; i++)
            spi_transfer(io, 0xFF);
    }
    /* Ignore CRC. */
    spi_transfer(io, 0xFF);
    spi_transfer(io, 0xFF);

    if (bcount > SECTSIZE)
    {
        /* Next sector. */
        bcount -= SECTSIZE;
        goto again;
    }

    /* Stop a read-multiple sequence. */
    card_cmd(unit, CMD_STOP, 0);
    sd_deselect(io);
//printf("%s: done\n", __func__);
    return 1;
}

/*
 * Write a block of data.
 * Return nonzero if successful.
 */
static int
card_write(int unit, unsigned offset, char *data, unsigned bcount)
{
    struct disk *u = &sddrives[unit];
    struct spiio *io = &sddrives[unit].spiio;
    unsigned reply, i;
//printf("--- %s: unit = %d, blkno = %d, bcount = %d\n", __func__, unit, offset, bcount);

    /* Send pre-erase count. */
    sd_select(io);
    card_cmd(unit, CMD_APP, 0);
    reply = card_cmd(unit, CMD_SET_WBECNT, (bcount + SECTSIZE - 1) / SECTSIZE);
    if (reply != 0)
    {
        /* Command rejected. */
        sd_deselect(io);
        printf("sd%d: card_write: bad SET_WBECNT reply = %02x, count = %u\n",
            unit, reply, (bcount + SECTSIZE - 1) / SECTSIZE);
        return 0;
    }

    /* Send write-multiple command. */
    if (u->card_type != TYPE_SDHC)
        offset <<= 9;
    reply = card_cmd(unit, CMD_WRITE_MULTIPLE, offset);
    if (reply != 0)
    {
        /* Command rejected. */
        sd_deselect(io);
        printf("sd%d: card_write: bad WRITE_MULTIPLE reply = %02x\n", unit, reply);
        return 0;
    }
    sd_deselect(io);
again:
    /* Select, wait while busy. */
    sd_select(io);
    sd_wait_ready(io, TIMO_WAIT_WDATA, &sd_timo_wait_wdata);

    /* Send data. */
    spi_transfer(io, WRITE_MULTIPLE_TOKEN);
    if (bcount >= SECTSIZE)
    {
        spi_bulk_write32_be(io, SECTSIZE/4, (int*)data);
        data += SECTSIZE;
    } else {
        spi_bulk_write(io, bcount, (unsigned char *)data);
        data += bcount;
        for (i=bcount; i<SECTSIZE; i++)
            spi_transfer(io, 0xFF);
    }
    /* Send dummy CRC. */
    spi_transfer(io, 0xFF);
    spi_transfer(io, 0xFF);

    /* Check if data accepted. */
    reply = spi_transfer(io, 0xFF);
    if ((reply & 0x1f) != 0x05)
    {
        /* Data rejected. */
        sd_deselect(io);
        printf("sd%d: card_write: data rejected, reply = %02x\n", unit,reply);
        return 0;
    }

    /* Wait for write completion. */
    sd_wait_ready(io, TIMO_WAIT_WDONE, &sd_timo_wait_wdone);
    sd_deselect(io);

    if (bcount > SECTSIZE)
    {
        /* Next sector. */
        bcount -= SECTSIZE;
        goto again;
    }

    /* Stop a write-multiple sequence. */
    sd_select(io);
    sd_wait_ready(io, TIMO_WAIT_WSTOP, &sd_timo_wait_wstop);
    spi_transfer(io, STOP_TRAN_TOKEN);
    sd_wait_ready(io, TIMO_WAIT_WIDLE, &sd_timo_wait_widle);
    sd_deselect(io);
    return 1;
}

/*
 * Setup the SD card interface.
 * Get the card type and size.
 * Read a partition table.
 * Return 0 on failure.
 */
static int
sd_setup(struct disk *u)
{
    int unit = u->unit;

    if (! card_init(unit)) {
        printf("sd%d: no SD card detected\n", unit);
        return 0;
    }
    /* Get the size of raw partition. */
    bzero(u->part, sizeof(u->part));
    u->part[RAWPART].dp_offset = 0;
    u->part[RAWPART].dp_size = card_size(unit);
    if (u->part[RAWPART].dp_size == 0) {
        printf("sd%d: cannot get card size\n", unit);
        return 0;
    }

    /* Switch to the high speed mode, if possible. */
    if (u->csd[4] & 0x40) {
        /* Class 10 card: switch to high-speed mode.
         * SPI interface of pic32 allows up to 25MHz clock rate. */
        card_high_speed(unit);
    }
    printf("sd%d: type %s, size %u kbytes, speed %u Mbit/sec\n", unit,
        u->card_type==TYPE_SDHC ? "SDHC" :
        u->card_type==TYPE_SD_II ? "II" : "I",
        u->part[RAWPART].dp_size / 2,
        spi_get_speed(&u->spiio) / 1000);

    /* Read partition table. */
    u_int16_t buf[256];
    int s = splbio();
    if (! card_read(unit, 0, (char*)buf, sizeof(buf))) {
        splx(s);
        printf("sd%d: cannot read partition table\n", unit);
        return 0;
    }
    splx(s);
    if (buf[255] == MBR_MAGIC) {
        bcopy(&buf[223], &u->part[1], 64);
#if 1
        int i;
        for (i=1; i<=NPARTITIONS; i++) {
            if (u->part[i].dp_type != 0)
                printf("sd%d%c: partition type %02x, sector %u, size %u kbytes\n",
                    unit, i+'a'-1, u->part[i].dp_type,
                    u->part[i].dp_offset,
                    u->part[i].dp_size / 2);
        }
#endif
    }
    return 1;
}

/*
 * Initialize a drive.
 */
int
sdopen(dev, flags, mode, p)
    dev_t dev;
    int flags, mode;
    struct proc *p;
{
    struct disk *u;
    int unit = sdunit(dev);
    int part = sdpart(dev);
    unsigned mask, i;

    if (unit >= NSD || part > NPARTITIONS)
        return ENXIO;
    u = &sddrives[unit];
    u->unit = unit;

    /*
     * Setup the SD card interface.
     */
    if (u->part[RAWPART].dp_size == 0) {
        if (! sd_setup(u)) {
            return ENODEV;
        }
    }
    u->open++;

    /*
     * Warn if a partion is opened
     * that overlaps another partition which is open
     * unless one is the "raw" partition (whole disk).
     */
    mask = 1 << part;
    if (part != RAWPART && ! (u->openpart & mask)) {
        unsigned start = u->part[part].dp_offset;
        unsigned end = start + u->part[part].dp_size;

        /* Check for overlapped partitions. */
        for (i=0; i<=NPARTITIONS; i++) {
            struct diskpart *pp = &u->part[i];

            if (i == part || i == RAWPART)
                continue;

            if (pp->dp_offset + pp->dp_size <= start ||
                pp->dp_offset >= end)
                continue;

            if (u->openpart & (1 << i))
                log(LOG_WARNING, "sd%d%c: overlaps open partition (sd%d%c)\n",
                    unit, part + 'a' - 1,
                    unit, pp - u->part + 'a' - 1);
        }
    }

    u->openpart |= mask;
    switch (mode) {
    case S_IFCHR:
        u->copenpart |= mask;
        break;
    case S_IFBLK:
        u->bopenpart |= mask;
        break;
    }
    return 0;
}

/*
 * Read/write routine for a buffer.  Finds the proper unit, range checks
 * arguments, and schedules the transfer.  Does not wait for the transfer
 * to complete.  Multi-page transfers are supported.  All I/O requests must
 * be a multiple of a sector in length.
 */
void
sdstrategy(bp)
    struct buf *bp;
{
    struct disk *u;    /* Disk unit to do the IO.  */
    int unit = sdunit(bp->b_dev);
    int s;
    unsigned offset;
//printf("%s: unit = %d, blkno = %d, bcount = %d\n", __func__, unit, bp->b_blkno, bp->b_bcount);

    if (unit >= NSD || bp->b_blkno < 0) {
        printf("sdstrategy: unit = %d, blkno = %d, bcount = %d\n",
            unit, bp->b_blkno, bp->b_bcount);
        bp->b_error = EINVAL;
        goto bad;
    }
    u = &sddrives[unit];
    offset = bp->b_blkno;
    if (u->open) {
        /*
         * Determine the size of the transfer, and make sure it is
         * within the boundaries of the partition.
         */
        struct diskpart *p = &u->part[sdpart(bp->b_dev)];
        long maxsz = p->dp_size;
        long sz = (bp->b_bcount + DEV_BSIZE - 1) >> DEV_BSHIFT;

        offset += p->dp_offset;
//printf("%s: sdpart=%u, offset=%u, maxsz=%u, sz=%u\n", __func__, sdpart(bp->b_dev), offset, maxsz, sz);
        if (offset == 0 &&
            ! (bp->b_flags & B_READ) && ! u->wlabel) {
                /* Write to partition table not allowed. */
                bp->b_error = EROFS;
                goto bad;
        }
        if (bp->b_blkno + sz > maxsz) {
                /* if exactly at end of disk, return an EOF */
                if (bp->b_blkno == maxsz) {
                        bp->b_resid = bp->b_bcount;
                        biodone(bp);
//printf("%s: done EOF\n", __func__);
                        return;
                }
                /* or truncate if part of it fits */
                sz = maxsz - bp->b_blkno;
                if (sz <= 0) {
                        bp->b_error = EINVAL;
                        goto bad;
                }
                bp->b_bcount = sz << DEV_BSHIFT;
        }
    } else {
        /* Reading the partition table. */
//printf("%s: reading the partition table\n", __func__);
        offset = 0;
    }
    if (u->dkindex >= 0) {
        /* Update disk statistics. */
        dk_busy |= 1 << u->dkindex;
        dk_xfer[u->dkindex]++;
        dk_wds[u->dkindex] += bp->b_bcount >> 6;
    }

    s = splbio();
    if (bp->b_flags & B_READ) {
        card_read(unit, offset, bp->b_un.b_addr, bp->b_bcount);
    } else {
        card_write(unit, offset, bp->b_un.b_addr, bp->b_bcount);
    }
    biodone(bp);
    splx(s);
//printf("%s: done OK\n", __func__);

    if (u->dkindex >= 0)
        dk_busy &= ~(1 << u->dkindex);
    return;

bad:
    bp->b_flags |= B_ERROR;
    biodone(bp);
//printf("%s: failed \n", __func__);
}

int
sdsize(dev)
    dev_t dev;
{
    int unit = sdunit(dev);
    int part = sdpart(dev);
    struct disk *u = &sddrives[unit];

    if (unit >= NSD || part > NPARTITIONS)
        return -1;

    /*
     * Setup the SD card interface, if not done yet.
     */
    if (u->part[RAWPART].dp_size == 0) {
        if (! sd_setup(u)) {
            return -1;
        }
    }
    return u->part[part].dp_size;
}

int
sdioctl(dev, cmd, data, flag, p)
    dev_t dev;
    u_long cmd;
    caddr_t data;
    int flag;
    struct proc *p;
{
    int unit = sdunit(dev);
    int part = sdpart(dev);
    struct diskpart *pp;
    int error = 0;

    switch (cmd) {

    case DIOCGETPART:
        /* Get partition table entry. */
        pp = &sddrives[unit].part[part];
//printf("--- %s: DIOCGETPART unit = %d, part = %d, type = %u, size = %u\n", __func__, unit, part, pp->dp_type, pp->dp_size);
        *(struct diskpart*) data = *pp;
        break;

    default:
        error = ENOTTY;
        break;
    }
    return error;
}

/*
 * Non-interrupt driven, non-dma dump routine.
 */
int
sddump(dev)
    dev_t dev;
{
    // TODO
    return ENXIO;
}

int
sdread(dev, uio)
    dev_t dev;
    struct uio *uio;
{
    return physio(sdstrategy, 0, dev, B_READ, minphys, uio);
}

int
sdwrite(dev, uio)
    dev_t dev;
    struct uio *uio;
{
    return physio(sdstrategy, 0, dev, B_WRITE, minphys, uio);
}

/*
 * Test to see if device is present.
 * Return true if found and initialized ok.
 */
static int
sdprobe(config)
    struct conf_device *config;
{
    int unit = config->dev_unit;
    struct disk *u = &sddrives[unit];
    struct spiio *io;

    if (unit < 0 || unit >= NSD)
        return 0;
    io = &u->spiio;

    if (spi_setup(io, config->dev_ctlr, config->dev_pins[0]) != 0) {
        printf("sd%u: cannot open SPI%u port\n", unit, config->dev_ctlr);
        return 0;
    }

    spi_set_speed(io, 250);
    spi_set(io, PIC32_SPICON_CKE);

    printf("sd%u at port %s, pin cs=R%c%d\n", unit,
        spi_name(io), spi_csname(io), spi_cspin(io));

    /* Assign disk index. */
    if (dk_ndrive < DK_NDRIVE) {
        u->dkindex = dk_ndrive++;

        /* Estimated transfer rate in 16-bit words per second. */
        dk_wpms[u->dkindex] = SD_KHZ / 32;
    } else
        u->dkindex = -1;

    /* Configure LED pin as output. */
#ifdef SD_LED_PORT
    ANSEL_CLR(SD_LED_PORT) = 1 << SD_LED_PIN;
    TRIS_CLR(SD_LED_PORT) = 1 << SD_LED_PIN;
#endif
    return 1;
}

struct driver sddriver = {
    "sd", sdprobe,
};
#endif
