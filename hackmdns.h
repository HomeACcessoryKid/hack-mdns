#ifndef __HACK_MDNS_H__
#define __HACK_MDNS_H__

void hack_mdns_init();
void hack_mdns_configure_init(const char *inst_name, int port, const char *model_name);
void hack_mdns_add_txt(const char *key, const char *format, ...);
void hack_mdns_configure_finalize();

#endif // __HACK_MDNS_H__
