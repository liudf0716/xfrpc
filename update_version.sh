#!/bin/bash

# Get current date components
YEAR=$(date +%Y)
MONTH=$(date +%m)

# Calculate major version based on year
# Starting from major version 4 in 2025
BASE_YEAR=2025
BASE_VERSION=4
CURRENT_YEAR=$YEAR

if [ "$CURRENT_YEAR" -lt "$BASE_YEAR" ]; then
    # For years before 2025, use version 3
    MAJOR_VERSION=3
else
    # For 2025 and beyond, calculate the increasing version
    YEAR_DIFF=$((CURRENT_YEAR - BASE_YEAR))
    MAJOR_VERSION=$((BASE_VERSION + YEAR_DIFF))
fi

# Get Git commit count for current branch
COMMIT_COUNT=$(git rev-list --count HEAD 2>/dev/null || echo "0")

# Get current protocol version from existing file
PROTOCOL_VERSION=$(grep "PROTOCOL_VERESION" version.h | cut -d'"' -f2)

# Create version string
VERSION="${MAJOR_VERSION}.${MONTH}.${COMMIT_COUNT}"

# Create updated version.h file
cat > version.h << EOF
// filepath: /home/ubuntu/work/xfrpc/version.h
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_VERSION_H
#define XFRPC_VERSION_H

#define VERSION   "${VERSION}"
#define PROTOCOL_VERESION "${PROTOCOL_VERSION}"
#define CLIENT_V 1

#endif // XFRPC_VERSION_H
EOF

echo "Updated version to ${VERSION}"