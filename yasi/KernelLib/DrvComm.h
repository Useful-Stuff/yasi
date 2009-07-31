#pragma once
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>

HANDLE LoadDriver();

void UnloadDriver(HANDLE file);