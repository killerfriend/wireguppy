/*
 * Copyright © 2012 Bart Massey
 * [This program is licensed under the "MIT License"]
 * Please see the file COPYING in the source
 * distribution of this software for license terms.
 */

/* Decode captured packet stream */

#include <assert.h>
#include <stdio.h>
#include <string.h>

void print_ether() {
    int i;
    printf("%02x", getchar());
    for (i = 1; i < 6; i++)
        printf(":%02x", getchar());
}

int get16(void) {
    int b1 = getchar();
    int b2 = getchar();
    return ((b1 << 8) & 0xff00) | (b2 & 0xff);
}

int get32(void) {
    int b1 = getchar();
    int b2 = getchar();
    int b3 = getchar();
    int b4 = getchar();
    return
        ((b1 << 24) & 0xff000000) |
        ((b2 << 16) & 0xff0000) |
        ((b3 << 8) & 0xff00) |
        (b4 & 0xff);
}

int flip32(int x) {
    return
        ((x >> 24) & 0xff) |
        ((x >> 8) & 0xff00) |
        ((x << 8) & 0xff0000) |
        ((x << 24) & 0xff000000);
}

int decode_length_type() {
    int length_type = get16();
    if (length_type == 0x8100) {
        printf("VLAN: 0x%04x\n", get16());
        length_type = get16();
    }
    printf("length/type:          0x%04x\n", length_type);
    return length_type;
}

/* inserted functions */
void ip_display(int address)
{

	 unsigned int nib;
	 nib = ((address & 0xff000000) >> 24);
	 printf("%u.", nib);
	 nib = ((address & 0xff0000) >> 16);
	 printf("%u.", nib);
	 nib = ((address & 0xff00) >> 8);
	 printf("%u.", nib);
	 nib = (address & 0xff);
	 printf("%u", nib);

}

void show_udp(int size)
{
	int i, src, dest, length, cksum;
	src = get16();
	dest = get16();
	length = get16();
	cksum = get16();

	printf("UDP source port:      %d\n",  src);
	printf("UDP destination port: %d\n",  dest);
	printf("UDP length (bytes):   %d\n",  length);
	printf("UDP checksum:         0x%04x\n",cksum);

	for(i = 0; i < (size - 8); i++)
		(void) getchar();

}

void show_tcp(int size)
{
    int i, src, dest, seq_num, ack, head_len, flags, win_size, cksum, urg_pntr;
    src = get16();
    dest = get16();
    seq_num = get32();
	 ack = get32();
    head_len = (((getchar()) & 0xF0) >> 4);
	 flags = getchar();
	 win_size = get16();
	 cksum = get16();
	 urg_pntr = get16();

	 for(i = 0; i < (head_len - 5); i++)
	 {
		printf("TCP option word#%02d:   0x%08x\n", i, get32());
	 }

    printf("TCP Source Port:      %d\n",     src);
    printf("TCP Destination Port: %d\n",     dest);
    printf("TCP Sequence num:     0x%08x\n",   seq_num);

	 if((flags & 0x10))
    	printf("TCP ACK num:          0x%04x\n", ack);

    printf("TCP header length:    %d\n", head_len);
    printf("TCP window size:      %d\n", win_size);
    printf("TCP checksum:         0x%04x\n", cksum);

	 if((flags & 0x20))
	 {
    	printf("TCP Urgent Pointer:   0x%04x\n", urg_pntr);
    	printf("TCP Urg Offset:       0x%04x\n", urg_pntr + seq_num);
	 }

 	 for (i = 0; i < (size - (head_len * 4)); i++)
        (void) getchar();

}

/* ASSIGNMENT: MODIFY THIS TO PRINT INFORMATION ABOUT
   ENCAPSULATED PAYLOAD. */
int show_ip() {
    int length, ID, flg, offset, TTL, proto, cksum;
    (void) get16();
    length = get16();
    printf("IP length:            %d\n", length);

	 ID = get16();
	 printf("IP ID:                0x%04x\n", ID);

	 flg = get16();
	 offset = (flg & 0x1fffffff);
	 flg = (flg >> 29);
	 printf("IP flags:             0x%01x\n", flg);
	 printf("IP offset:            0x%08x\n", offset);
	 
	 TTL = getchar();
	 printf("IP TTL:               %d\n", TTL);

	 proto = getchar();
	 if(proto == 17)
		printf("IP Protocol:          UDP\n");
	 else if(proto == 6)
		printf("IP Protocol:          TCP\n");
	 else
		printf("IP Protocol:           %d\n",     proto);

	 cksum = get16();
	 printf("IP checksum:          0x%04x\n", cksum);

	 printf("IP source:            ");
	 ip_display(get32());
	 printf("\n");

	 printf("IP destination:       ");
	 ip_display(get32());
	 printf("\n");
	 
	 if(proto == 6)
	   show_tcp(length - 20);
	 else
		show_udp(length - 20);

	 return length;
}

void show_payload(int lt) {
    int i;
    for (i = 0; i < lt; i++)
        getchar();
}

int raw_mode = 0;

int main(int argc, char **argv) {
    int i;
    if (argc == 2) {
        assert(!strcmp(argv[1], "-r"));
        raw_mode = 1;
    } else {
        assert(argc == 1);
    }
    if (!raw_mode) {
        /* XXX Should check link type and
           record snapshot length. */
        for (i = 0; i < 6; i++)
            printf("h%d: %08x\n", i, get32());
        printf("\n");
    }
    while (1) {
        int lt, ch, paylen;
        if (!raw_mode) {
            /* XXX Should use length information
               in decoding below. */
            (void) get32();
            (void) get32();
            paylen = flip32(get32());
            printf("paylen: %d (%d)\n", paylen, flip32(get32()));
        }
        printf("src:                  ");
        print_ether();
        printf("\n");
        printf("dst:                  ");
        print_ether();
        printf("\n");
        lt = decode_length_type();
        if (lt == 0x0800)
            lt = show_ip();
        else if (lt <= 1500)
            show_payload(lt);
        else
            assert(0);
        assert(paylen >= lt - 14);
        if (!raw_mode) {
            paylen -= 14; /* ethernet header */
            paylen -= lt; /* IP packet */
				printf("pad length:           %d\n", paylen);
            for (i = 0; i < paylen; i++)
                printf("pad%d: %02x\n", i, getchar() & 0xff);
        }
        ch = getchar();
        if (ch == EOF)
            break;
        (void) ungetc(ch, stdin);
        printf("\n");
    }
    return 0;
}
