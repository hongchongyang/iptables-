#include "ip2str.h"

void ip2str(char* ipaddr, int size, uint32_t ip)
{
        snprintf(ipaddr, size, "%d.%d.%d.%d", ( ip >> 24 ) & 0xff
                                        , ( ip >> 16 ) & 0xff
                                        , ( ip >> 8 ) & 0xff
                                        , ip & 0xff);
}
