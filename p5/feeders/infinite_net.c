#include <stdlib.h>
#include <stdio.h>
#include "../system.h"

int main()
{
  for (;;)
  {
    system("ping -c 1 google.com");
    us_sleep(10000);
  }

  return 0;
}