#include <stdio.h>

int gdk_pixbuf_new (int           has_alpha,
                int           bits_per_sample,
                int           width,
                int           height)
{
	//guchar *buf;
	int channels;
	int rowstride;

	if (!(bits_per_sample == 8)) {
          printf("Fail 1");
          return NULL;
          }
        printf("Pass 1");
	if (!(width > 0)) {
          printf("Fail 2");
          return NULL;
          }
        printf("Pass 2");
	if (!(height > 0)) {
          printf("Fail 3");
          return NULL;
          }
        printf("Pass 3");

	channels = has_alpha ? 4 : 3;
        rowstride = width * channels;
        if (rowstride / channels != width || rowstride + 3 < 0) /* overflow */
                return NULL;

	/* Always align rows to 32-bit boundaries */
	rowstride = (rowstride + 3) & ~3;

	//buf = g_try_malloc_n (height, rowstride);
	//if (!buf)
	//	return NULL;

	return 1;
}


int main ( int arc, char **argv )
{
  int x,y,z,w;
  FILE * f;

  f = fopen (argv[1],"r+");
  fread( &x, sizeof x, 1, f );
  fread( &y, sizeof y, 1, f );
  fread( &w, sizeof w, 1, f );
  fread( &z, sizeof z, 1, f );
  //fscanf (f, "%d %d %d %d", &x, &y, &z, &w);
  gdk_pixbuf_new(x,y,z,w);
  return 0;
}
