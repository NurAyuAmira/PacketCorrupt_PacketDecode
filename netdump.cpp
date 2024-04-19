#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstring>
using namespace std;

FILE *input;

#define NULL 0
#define TCPDUMP_MAGIC 0xa1b2c3d4      /* Tcpdump Magic Number (Preamble) */
#define PCAP_VERSION_MAJOR 2           /* Tcpdump Version Major (Preamble) */
#define PCAP_VERSION_MINOR 4           /* Tcpdump Version Minor (Preamble) */

#define DLT_NULL 0                    /* Data Link Type Null  */
#define DLT_EN10MB 1                   /* Data Link Type for Ethernet II 100 MB and above */
#define DLT_EN3MB 2                    /* Data Link Type for 3 Mb Experimental Ethernet */

// Ethernet Header
#define ETHER_ADDR_LEN 6

typedef struct packet_header
{
    unsigned int magic;                /* Tcpdump Magic Number  */
    unsigned short version_major;      /* Tcpdump Version Major */
    unsigned short version_minor;      /* Tcpdump Version Minor */
    unsigned int thiszone;             /* GMT to Local Correction */
    unsigned int sigfigs;              /* Accuracy of timestamps */
    unsigned int snaplen;              /* Max Length of Portion of Saved Packet */
    unsigned int linktype;             /* Data Link Type */
} hdr;

typedef struct packet_timestamp
{
    unsigned int tv_sec;                /* Timestamp in Seconds */
    unsigned int tv_usec;               /* Timestamp in Micro Seconds */
    /* Total Length of Packet Portion (Ethernet Length until the End of Each Packet) */
    unsigned int caplen;
    unsigned int len;                   /* Length of the Packet (Off Wire) */
} tt;

typedef struct ether_header
{
    unsigned char edst[ETHER_ADDR_LEN]; /* Ethernet Destination Address */
    unsigned char esrc[ETHER_ADDR_LEN]; /* Ethernet Source Address */
    unsigned short etype;               /* Ethernet Protocol Type */
} eth;

//MOFIFY BY AYU: IP Header
typedef struct ip_header
{
    unsigned char version_ihl;       // Version (4 bits) + Internet header length (4 bits)
    unsigned char dscp_ecn;          // DSCP (6 bits) + ECN (2 bits)
    unsigned short total_length;     // Total length
    unsigned short identification;   // Identification
    unsigned short flags_fragoffset; // Flags (3 bits) + Fragment offset (13 bits)
    unsigned char ttl;               // Time to Live
    unsigned char protocol;          // Protocol
    unsigned short checksum;         // Header checksum
    unsigned int src_ip;             // Source IP address
    unsigned int dest_ip;            // Destination IP address
} ip_hdr;

//MODIFY BY AYU: Define corruption parameters structure
struct CorruptionParams {
    bool corrupt_ttl;
    bool corrupt_protocol;
    bool swap_src_dst;
    bool set_multicast_src;
    bool length_mismatch;
} corruptionParams;


//MODIFY BY AYU: Helper function to write an integer in network byte order
void writeNetworkByteOrder(FILE *file, unsigned int value) {
    unsigned char bytes[4];
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
    fwrite(bytes, sizeof(bytes), 1, file);
}


int main(int argc, char *argv[])
{
    unsigned int remain_len = 0;
    unsigned char temp = 0;
    int i, count = 0;

    struct packet_header hdr;           /* Initialize Packet Header Structure */
    struct packet_timestamp tt;         /* Initialize Timestamp Structure */
    struct ether_header eth;           /* Initialize Ethernet Structure */
    struct ip_header ip;               /* Initialize IP Header Structure */
    unsigned char buff, array[1500];

    //MODIFY BY AYU: Ask user for corruption parameters
    cout << "Do you want to corrupt TTL? (1 for yes, 0 for no): ";
    cin >> corruptionParams.corrupt_ttl;

    cout << "Do you want to corrupt the protocol? (1 for yes, 0 for no): ";
    cin >> corruptionParams.corrupt_protocol;

    cout << "Do you want to corrupt the source and destination address? (1 for yes, 0 for no): ";
    cin >> corruptionParams.swap_src_dst;

    cout << "Do you want to corrupt the IP multicast address? (1 for yes, 0 for no): ";
    cin >> corruptionParams.set_multicast_src;

    cout << "Do you want to corrupt the IP data length mismatch with UDP data length? (1 for yes, 0 for no): ";
    cin >> corruptionParams.length_mismatch;

    FILE *output;
    input = fopen("abc.pcap", "rb"); /* Open Input File */
    output = fopen("xyz.pcap", "wb"); // Open output file

    if (input == NULL)
    {
        cout << "Cannot open saved windump file" << endl;
        return 1;
    }

    fread((char *)&hdr, sizeof(hdr), 1, input); /* Read & Display Packet Header Information */

    cout << "\n* ********** PACKET HEADER ********** ***********" << endl;
    cout << "Preamble " << endl;
    cout << "Packet Header Length : " << sizeof(hdr) << endl;
    cout << " Magic Number : " << hdr.magic << endl;
    cout << "Version Major : " << hdr.version_major << endl;
    cout << "Version Minor : " << hdr.version_minor << endl;
    cout << "GMT to Local Correction : " << hdr.thiszone << endl;
    cout << "Jacked Packet with Length of : " << hdr.snaplen << endl;
    cout << "Accuracy to Timestamp   :  " << hdr.sigfigs << endl;
    cout << "Data Link Type (Ethernet Type II = 1)  : " << hdr.linktype << endl;


    // Write the pcap header to the output file before starting the packet processing
    fwrite((char *)&hdr, sizeof(hdr), 1, output);

    /* Use While Loop to Set the Packet Boundary */
    while (fread((char *)&tt, sizeof(tt), 1, input) && fread((char *)&eth, sizeof(eth), 1, input)) /* Read & Display Timestamp and Ethernet Header Information */
    {
        ++count;

        cout << "********* TIMESTAMP & ETHERNET FRAME ****" << endl;
        cout << " Packet Number: " << count << endl; /* Display Packet Number */
        cout << " The Packets are Captured in : " << tt.tv_sec << " Seconds" << endl;
        cout << "The Packets are Captured in : " << tt.tv_usec << " Micro-seconds" << endl;

        /* Use caplen to Find the Remaining Data Segment */
        cout << "The Actual Packet Length: " << tt.caplen << " Bytes" << endl;
        cout << "Packet Length (Off Wire): " << tt.len << " Bytes" << endl;

        // Read and display Ethernet header information
        cout << "Ethernet Header Length  : " << sizeof(eth) << " bytes" << endl;
        printf("MAC Destination Address    : [hex] %x :%x :%x :%x :%x :%x \n\t\t\t  [dec] %d :%d :%d :%d :%d :%d\n",
               eth.edst[0], eth.edst[1],
               eth.edst[2], eth.edst[3], eth.edst[4], eth.edst[5], eth.edst[0], eth.edst[1],
               eth.edst[2], eth.edst[3], eth.edst[4], eth.edst[5], eth.edst[6]);

        printf("MAC Source Address    : [hex] %x :%x :%x :%x :%x :%x \n\t\t\t  [dec] %d :%d :%d :%d :%d :%d\n",
               eth.esrc[0], eth.esrc[1], eth.esrc[2],
               eth.esrc[3], eth.esrc[4], eth.esrc[5], eth.esrc[0], eth.esrc[1],
               eth.esrc[2], eth.esrc[3], eth.esrc[4], eth.esrc[5]);

        // *********************** FOR ASSIGNMENT NOT INVOLVING WRITING BACK TO A FILE ******
        // *************************BEGIN MODIFICATION HERE.********************************************
        //  *********************** It is recommended to add Your Code here **********
        // ****Nevertheless, in some of the questions you may need to add some code
        //  ** elsewhere in the program. ********************
        //  ......  Your Code

        //MODIFY BY AYU: Read and display IP header information
        fread((char *)&ip, sizeof(ip), 1, input);
        cout << "IP Source Address      : " << ((ip.src_ip >> 0) & 0xFF) << "." << ((ip.src_ip >> 8) & 0xFF)
             << "." << ((ip.src_ip >> 16) & 0xFF) << "." << ((ip.src_ip >> 24) & 0xFF) << endl;

        cout << "IP Destination Address : " << ((ip.dest_ip >> 0) & 0xFF) << "." << ((ip.dest_ip >> 8) & 0xFF)
             << "." << ((ip.dest_ip >> 16) & 0xFF) << "." << ((ip.dest_ip >> 24) & 0xFF) << endl;

        //MODIFY BY AYU: Apply the corruptions based on user input
        if (corruptionParams.corrupt_ttl) {
            ip.ttl = 0;
        }

        if (corruptionParams.corrupt_protocol) {
            ip.protocol = 0xFF; // An undefined protocol
        }

        if (corruptionParams.swap_src_dst) {
            unsigned int temp_ip = ip.src_ip;
            ip.src_ip = ip.dest_ip;
            ip.dest_ip = temp_ip;
        }

        if (corruptionParams.set_multicast_src) {
            // Set the first four bytes of the source IP to a multicast address
            ip.src_ip = 0xE00000AB;
        }

        if (corruptionParams.length_mismatch) {
            // Increment the IP total length by 1 to create a mismatch
            ip.total_length += 1;
        }

        //MODIFY BY AYU: Now write the corrupted packet back to the output file
        fwrite((char *)&tt, sizeof(tt), 1, output);
        fwrite((char *)&eth, sizeof(eth), 1, output);
        writeNetworkByteOrder(output, ip.src_ip);
        writeNetworkByteOrder(output, ip.dest_ip);
        fwrite((char *)&ip + 8, sizeof(ip) - 8, 1, output); // Write the rest of the IP header
        fwrite((char *)array, tt.caplen - sizeof(eth) - sizeof(ip), 1, output);

        //  ****** END OF MODIFICATION HERE **********************
        //  WARNING: Try not to modify the while loop, the fread statement as you may affect
        //  the packet boundary and the whole program may not work after that.

        for (i = 0; i < tt.caplen - sizeof(eth) - sizeof(ip); i++)
        {
            fread((char *)&buff, sizeof(buff), 1, input);
            printf(" %x", buff); // you may remove the printf line if necessary
            array[i] = buff;
        }

        printf("\n ");
    } // end while

    fclose(input); // Close input file
    fclose(output);

    return (0);
}
