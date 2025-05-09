
void
debugger(const char *message)
{
    printf("Debugger called: %s\n", message);
}


void debug_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
