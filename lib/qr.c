#include <stdlib.h>
#include <qrencode.h>

#include "utils.h"

/*
 * Inspired from https://github.com/google/google-authenticator-libpam/blob/master/src/google-authenticator.c
 *
 * Output QRCode using ANSI colors.
 * 
 * Instead of black on white, we output black on grey, as that works
 * independently of whether the user runs their terminal in a black on
 * white or white on black color scheme.
 */

#define RESET        "\x1B[0m"
#define BLACKONGREY  "\x1B[30;47;27m"
#define WHITE        "\x1B[27m"
#define BLACK        "\x1B[7m"

#define RESET_len       strlen(RESET)
#define BLACKONGREY_len strlen(BLACKONGREY)
#define WHITE_len       strlen(WHITE)
#define BLACK_len       strlen(BLACK)

static inline
int
output_empty_line(int width, char **bufptr, size_t* buflen)
{
  if(*buflen < BLACKONGREY_len) return -1;

  strncpy(*bufptr, BLACKONGREY, BLACKONGREY_len);
  *bufptr += BLACKONGREY_len;
  *buflen -= BLACKONGREY_len;

  int x;
  for (x = 0; x < width + 4; ++x){
    if(*buflen < 2) return -1;
    strncpy(*bufptr, "  ", 2);
    *bufptr += 2;
    *buflen -= 2;
  }

  if(*buflen < (RESET_len+1)) return -1;
  strncpy(*bufptr, RESET"\n", RESET_len+1);
  *bufptr += RESET_len+1;
  *buflen -= RESET_len+1;
  return 0;
}

static inline
int
output_line(unsigned char** data, int width, char **bufptr, size_t* buflen)
{
  if(*buflen < (BLACKONGREY_len+4)) return -1;
  strncpy(*bufptr, BLACKONGREY"    ", BLACKONGREY_len+4);
  *bufptr += BLACKONGREY_len + 4;
  *buflen -= BLACKONGREY_len + 4;

  int x, isBlack = 0;
  for (x = 0; x < width; ++x, *data += 1) {
    unsigned char v = **data;
    if (v & 1) {
      if (!isBlack) {
	if(*buflen < BLACK_len) return -1;
	strncpy(*bufptr, BLACK, BLACK_len);
	*bufptr += BLACK_len;
	*buflen -= BLACK_len;
      }
      isBlack = 1;
    } else {
      if (isBlack) {
	if(*buflen < WHITE_len) return -1;
	strncpy(*bufptr, WHITE, WHITE_len);
	*bufptr += WHITE_len;
	*buflen -= WHITE_len;
      }
      isBlack = 0;
    }
    if(*buflen < 2) return -1;
    strncpy(*bufptr, "  ", 2);
    *bufptr += 2;
    *buflen -= 2;
  }
  if (isBlack) {
    if(*buflen < WHITE_len) return -1;
    strncpy(*bufptr, WHITE, WHITE_len);
    *bufptr += WHITE_len;
    *buflen -= WHITE_len;
  }

  if(*buflen < (4 + RESET_len + 1)) return -1;
  strncpy(*bufptr, "    " RESET "\n", 4 + RESET_len + 1);
  *bufptr += 4 + RESET_len + 1;
  *buflen -= 4 + RESET_len + 1;
  return 0;
}

static int output_qrcode(unsigned char *data, int width, char* buffer, size_t buflen){

  if(output_empty_line(width,&buffer,&buflen)) return -1;
  if(output_empty_line(width,&buffer,&buflen)) return -1;
  int y;
  for (y = 0; y < width; ++y) { if(output_line(&data,width,&buffer,&buflen)) return -1; }
  if(output_empty_line(width,&buffer,&buflen)) return -1;
  if(output_empty_line(width,&buffer,&buflen)) return -1;
  *buffer = '\0';
  return 0;
}

int make_qrcode(const char* url, char** result)
{
  if (result == NULL) { D1("Where shall we allocate the result?"); return -1; }
  if (*result != NULL) { D1("Not overwriting the result [at %p]: %s", result, *result); return -2; }

  //QRcode *qrcode = QRcode_encodeStringMQR(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
  QRcode *qrcode = QRcode_encodeString(url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);

  int width = qrcode->width;
  unsigned char* data = qrcode->data;

  size_t size = 1024;

REALLOC:
  D3("Allocating buffer of size %zd", size);
  if(*result)free(*result);
  *result = malloc(sizeof(char) * size);
  if(!*result){ D3("Could not allocate buffer of size %zd", size); return -1; };
  memset(*result, '\0', size);
  /* **result = '\0'; */

  if( output_qrcode(data, width, *result, size) < 0 ){
    size = size << 1; /* double it */
    goto REALLOC;
  }

  D2("QR loaded [@ %p] [length: %zu]", *result, size);

  QRcode_free(qrcode);
  return 0;
}
