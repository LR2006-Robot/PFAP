#ifndef SMTCGO_HPP_
#define SMTCGO_HPP_

#ifdef __cplusplus
extern "C" {
#endif

void smtInsertCMT(const char* cmt_hex);
char* smtGetRoot();
void smtReset();
char* smtProve(const char* cmt_hex);
void smtFree(char* p);

#ifdef __cplusplus
}
#endif

#endif // SMTCGO_HPP_
