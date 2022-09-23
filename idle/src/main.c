/*
** Jason Brillante "Damdoshi"
** Pentacle Technologie 2008-2022
** Hanged Bunny Studio 2014-2021
** EFRITS SAS 2022
**
** WorkSpy Idle
*/

#include	<string.h>
#include	<errno.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<assert.h>

void		usleep(unsigned int);

int		main(int	argc,
		     char	**argv)
{
  char		buffer[1024 * 16];
  char		name[256];
  char		mac[256];
  char		dat[256];
  char		users[1024];
  FILE		*pop;

  if (argc != 2)
    {
      printf("%s: Usage is:\n\t%s server_url\n", argv[1], argv[1]);
      return (EXIT_FAILURE);
    }

  assert((pop = popen("cat /sys/class/net/eno1/address | base32 | tr -d '\n'", "r")));
  assert(fread(&mac[0], sizeof(mac), sizeof(mac[0]), pop) >= 0);
  puts(&mac[0]);
  fclose(pop);

  assert((pop = popen("cat /proc/sys/kernel/hostname | base32 | tr -d '\n'", "r")));
  assert(fread(&name[0], sizeof(name), sizeof(name[0]), pop) >= 0);
  puts(&name[0]);
  fclose(pop);

  do
    {
      assert((pop = popen("who | cut -d ' ' -f 1 | base32 | tr -d '\n'", "r")));
      assert(fread(&users[0], sizeof(users), sizeof(users[0]), pop) >= 0);
      fclose(pop);

      assert((pop = popen("date | base32 | tr -d '\n'", "r")));
      assert(fread(&dat[0], sizeof(dat), sizeof(dat[0]), pop) >= 0);
      fclose(pop);

      // IL FAUT COMPLETER IP ET MAC
      snprintf(&buffer[0], sizeof(buffer),
	       "curl -X POST -d \"connected=%s&mac=%s&name=%s&date=%s\" %s",
	       &users[0], &mac[0], &name[0], &dat[0],
	       argv[1]);
      puts(&buffer[0]);
      //system(&buffer[0]);
      usleep(5 * 1e6 + rand() % 1000000); // Toutes les 5 secondes environ
    }
  while (1);
  return (EXIT_SUCCESS);
}

