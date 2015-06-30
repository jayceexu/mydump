#include "util.h"

int32_t gmt2local(time_t t)
{
	int dt, dir;
	struct tm *gmt, *loc;
	struct tm sgmt;

	if (t == 0)
		t = time(NULL);
	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);
	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
	    (loc->tm_min - gmt->tm_min) * 60;

	dir = loc->tm_year - gmt->tm_year;
	if (dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;
	dt += dir * 24 * 60 * 60;

	return (dt);
}

char * ts_format(int sec, int usec)
{
        static char buf[sizeof("00:00:00.000000")];
        (void)snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%06u",
               sec / 3600, (sec % 3600) / 60, sec % 60, usec);

        return buf;
}

void ts_print(const struct timeval *tvp)
{
	int s;
	struct tm *tm;
	time_t Time;
        int32_t thiszone = gmt2local(0);
        s = (tvp->tv_sec + thiszone) % 86400;
        Time = (tvp->tv_sec + thiszone) - s;
        tm = gmtime (&Time);
        if (!tm)
            printf("Date fail  ");
        else
            printf("%04d-%02d-%02d %s ",
                   tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
                   ts_format(s, tvp->tv_usec));
}

 
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02X ", *ch);
        ch++;
    }
    if (len < 8) {
        printf(" ");
    }
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
    return;
}

// GET/POST resource
int print_get_post_resource(u_char * payload, u_char * output)
{
    char * hd = strstr(payload, "GET");
    if (!hd) {
        hd = strstr(payload, "POST");
        if (!hd) {
            return -1;            
        }
    }
    char * tail = strstr(hd, " ");
    if (!tail) {
        return -1;
    }
    tail = strstr(tail+1, " ");
    if (!tail) {
        return -1;
    }

    int len = tail - hd;
    if (len >= SEARCH_STRING_LEN) {
        return -1;
    }
    memcpy(output, hd, len);
    output[len] = 0;
    return 0;
}


