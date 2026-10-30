/* Link-only test injection: exercise the real boundary initializer's runtime
 * failure branch after the real platform initializer has completed. */
int __wrap_encbound_runtime_init(void) { return -1; }
