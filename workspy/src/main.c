/*
** Jason Brillante "Damdoshi"
** Pentacle Technologie 2008-2022
** Hanged Bunny Studio 2014-2021
** EFRITS SAS 2022
**
** WorkSpy
*/

#include	<stdio.h>
#include	<time.h>

int		main(int	argc,
		     char	**argv)
{
  char		buffer[4096];
  FILE		*pop;

  if (argc != 2)
    {
      printf("%s: Usage is:\n\t%s server_url\n", argv[1], argv[1]);
      return (EXIT_FAILURE);
    }
  srand(time(NULL));

  // IL FAUT AUSSI ECOUTER LES TERMINAUX - VOIR COMMENT FAIRE
  while ((pop = popen("xev -root", "r")) == NULL)
    usleep(1e6);

  while (fread(&buffer[0], sizeof(buffer), sizeof(buffer[0]), pop) > 0)
    {
      // IL FAUT COMPLETER IP ET MAC
      snprintf(&buffer[0], sizeof(buffer), "curl -X POST -d \"connected=`who | base64`&ip=``&mac=``\" %s", argv[1]);
      system(&buffer[0]);
      usleep(5 * 1e6 + rand() % 1e6); // Toutes les 5 secondes environ
    }
  fclose(pop);
  return (EXIT_SUCCESS);
}

