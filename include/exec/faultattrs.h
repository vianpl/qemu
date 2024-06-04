/*
 * Memory fault attributes
 *
 * Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#ifndef MEMFAULTATTRS_H
#define MEMFAULTATTRS_H

typedef struct MemFaultAttrs {
    unsigned int write:1;
    unsigned int exec:1;
    unsigned int user:1;
} MemFaultAttrs;

#endif
