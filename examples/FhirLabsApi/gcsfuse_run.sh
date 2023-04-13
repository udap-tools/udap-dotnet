#!/bin/bash
#Be very carefull to always save with unix line endings and no BOM.  
#Avoid saving with Visual Studio on Windows.  Use something like Notepad++
#Save with ANSI encoding
set -eo pipefail

# Create mount directory for service
mkdir -p $MNT_DIR

echo "Mounting GCS Fuse."
gcsfuse --debug_gcs --debug_fuse $BUCKET $MNT_DIR
echo "Mounting completed."

# Start the application
dotnet FhirLabsApi.dll

# Exit immediately when one of the background processes terminate.
wait -n