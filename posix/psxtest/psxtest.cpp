#include <io.h>
#include <fcntl.h>
#include <stdio.h>

int main()
{
    int fd, s;
    char buffer[128];
    char *fname = "/glob/c:/windows/win.ini";

    printf ("fname = %s\n", fname);

    fd = open (fname, O_RDONLY);

    printf ("fd = %d\n", fd);

    if (fd != -1)
    {
        s = read (fd, buffer, sizeof(buffer)-1);

        printf("read = %d\n", s);

        if (s != -1)
        {
            buffer[s] = 0;
            printf("%s\n", buffer);
        }
        else printf("could not read %s\n", fname);

        close (fd);
    }
    else printf("could not open %s\n", fname);

    write (1, "completed\n", 10);
    write (2, "stderr\n", 7);

    return 0;
}
