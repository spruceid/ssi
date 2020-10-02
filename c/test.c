#include <dlfcn.h>
#include <err.h>
#include <stdio.h>
#include "ssi.h"

int main() {
	void *lib = dlopen("target/release/libssi.so", RTLD_NOW);
	if (lib == NULL) errx(1, "dlopen: %s", dlerror());
	const char *(*ssi_get_version)() = dlsym(lib, "ssi_get_version");
	if (ssi_get_version == NULL) errx(1, "unable to find version function");
	const char *version = ssi_get_version();
	printf("C libssi version: %s\n", version);
	int rc = dlclose(lib);
	if (rc < 0) errx(1, "dlclose: %s", dlerror());
}
