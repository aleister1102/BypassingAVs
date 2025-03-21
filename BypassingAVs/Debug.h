#pragma once
#include <Windows.h>


#ifdef _MSC_VER  // If compiling with MSVC
#ifdef _DEBUG
// wprintf replacement
#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

// printf replacement
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }

// getchar replacement
#define GETCHAR() do { \
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); \
    INPUT_RECORD ir; \
    DWORD read; \
    while (1) { \
        ReadConsoleInput(hStdin, &ir, 1, &read); \
        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) { \
            break; \
        } \
    } \
} while (0)

#else

#define PRINTW( STR, ... )
#define PRINTA( STR, ... )
#define GETCHAR()

#endif
#endif
