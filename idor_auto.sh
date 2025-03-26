#!/bin/bash

# Configuration - change these paths to match your setup
IDORBUSTER="./idorbuster"
HTTP_FILES_DIR="./http_files"
CREDENTIALS_FILE="./credentials.json"

# Admin and user types
ADMIN_USER="admin"
USER_TYPE="user"

echo "===== IDORbuster Automated Testing ====="

# Step 1: Original (admin) login
echo "Logging in as admin ($ADMIN_USER)..."
$IDORBUSTER original-login $ADMIN_USER -c $CREDENTIALS_FILE
if [ $? -ne 0 ]; then
    echo "Error: Admin login failed"
    exit 1
fi

# Step 2: Impersonation (regular user) login
echo "Logging in as regular user ($USER_TYPE)..."
$IDORBUSTER impersonation-login $USER_TYPE -c $CREDENTIALS_FILE
if [ $? -ne 0 ]; then
    echo "Error: User login failed"
    exit 1
fi

# Step 3: Process HTTP files
echo "Processing HTTP files..."
$IDORBUSTER process -d $HTTP_FILES_DIR
if [ $? -ne 0 ]; then
    echo "Error: Processing files failed"
    exit 1
fi

# Step 4: Run IDOR test
echo "Running IDOR vulnerability test..."
# Removed the -c flag since it's not accepted
$IDORBUSTER idor -d $HTTP_FILES_DIR
if [ $? -ne 0 ]; then
    echo "Error: IDOR test failed"
    exit 1
fi

echo "===== Testing complete ====="
