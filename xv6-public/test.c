#include "types.h"
#include "user.h"

char *str = "You can't change a character!";

int main(void)  // xv6 main requires void
{
    str[1] = 'O';  // This should cause a trap after our protection changes
    
    // xv6 printf requires fd as first argument (1 is stdout)
    printf(1, "%s\n", str);
    
    exit();  // xv6 requires explicit exit() instead of return
}
