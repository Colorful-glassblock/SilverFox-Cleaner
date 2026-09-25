#ifndef SFC_ML_NET_H
#define SFC_ML_NET_H
extern const float TAB_MEANS[28], TAB_STDS[28], TAB_W1[7168], TAB_B1[256], TAB_W2[32768], TAB_B2[128], TAB_W3[128], TAB_B3; extern const float IMG_MEAN, IMG_STD, IMG_C1W[432], IMG_C1B[16], IMG_C2W[4608], IMG_C2B[32], IMG_C3W[18432], IMG_C3B[64], IMG_F1W[524288], IMG_F1B[128], IMG_F2W[128], IMG_F2B;
#endif
#include <stdio.h>
#include <string.h>
#include <math.h>
typedef struct { float score; int high; } MlVerdict;
float ml_tab_p(const double x[28]);
int ml_delta_img(const char *path, unsigned char out[3072]);
float ml_img_p(const unsigned char img[3072]);
MlVerdict ml_verdict(float tab, float img, int mode);
float ml_tab_threshold(int mode);
float ml_tab_floor(int mode);
