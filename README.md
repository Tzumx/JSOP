# Just a Simple 1Password Client

This is a lightweight client interface using the 1Password Command-Line Tool (op).

### Install 1Password CLI on Debian/Ubuntu

```bash
# Download the latest stable CLI version
wget https://downloads.1password.com/linux/debian/amd64/stable/1password-cli-amd64-latest.deb

# Install the package
sudo apt install ./1password-cli-amd64-latest.deb
```

### List items from the 'Employee' vault
```
import os
from dotenv import load_dotenv
from one_password import OnePasswordClient

load_dotenv()

secret = {
    "password": os.getenv("OP_PASSWORD"),
    "signin_address": os.getenv("OP_EMAIL"),
}

op = OnePasswordClient(
    secret=secret,
    account=os.getenv("OP_ACCOUNT"),
    url=os.getenv("OP_URL"),
    auth=True  # Automatically sign in
)

vaults = op.get_vaults()
documents = op.list("Employee")
```
