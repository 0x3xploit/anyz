/* PE DLL fixture: named, ordinal-only and forwarded exports (see dll.def). */
__declspec(dllexport) int add_numbers(int a, int b) { return a + b; }
int secret_function(void) { return 0x1337; }
int exported_data = 42;
