import base64
import json
import os
import re
import subprocess
from enum import Enum
from typing import Optional
from uuid import uuid4


class OnePasswordCategory(Enum):
    API_CREDENTIAL = "API Credential"
    BANK_ACCOUNT = "Bank Account"
    CREDIT_CARD = "Credit Card"
    DATABASE = "Database"
    DOCUMENT = "Document"
    DRIVER_LICENSE = "Driver License"
    EMAIL_ACCOUNT = "Email Account"
    IDENTITY = "Identity"
    LOGIN = "Login"
    MEMBERSHIP = "Membership"
    OUTDOOR_LICENSE = "Outdoor License"
    PASSPORT = "Passport"
    PASSWORD = "Password"
    REWARD_PROGRAM = "Reward Program"
    SECURE_NOTE = "Secure Note"
    SERVER = "Server"
    SOCIAL_SECURITY_NUMBER = "Social Security Number"
    SOFTWARE_LICENSE = "Software License"
    SSH_KEY = "SSH Key"
    WIRELESS_ROUTER = "Wireless Router"


def get_optional_flag(**kwargs):
    key, value = list(kwargs.items())[0]
    return f"--{key}='{value}'" if value else ""


class DeletionFailure(Exception):
    def __init__(self, item_name, vault):
        message = f"Unable to delete item '{item_name}' from vault '{vault}'"

        super().__init__(message)
        self.message = message


class Unauthorized(Exception):
    pass


class MissingCredentials(Exception):
    pass


class SigninFailure(Exception):
    pass


class UnknownResource(Exception):
    pass


class UnknownResourceItem(Exception):
    pass


class UnknownError(Exception):
    pass


class OnePasswordClient:
    def __init__(
        self,
        secret: Optional[dict] = None,
        token: Optional[str] = None,
        bin_path="",
        account: Optional[str] = None,
        url: Optional[str] = None,
        auth: bool = False,
    ):
        self.op = os.path.join(bin_path, "op")
        self.account: Optional[str] = account
        self.url: Optional[str] = url
        if auth is True:
            self._connect_account(secret)
        if secret is not None:
            self._session_token = self._get_access_token(secret)
        elif token is not None:
            self._session_token = token
        else:
            raise MissingCredentials()

    def _connect_account(self, secret: dict):
        process = None
        print("Connecting account...")
        try:
            process = subprocess.run(
                (
                    f"echo '{secret['password']}' | "
                    f"{self.op} account add "
                    f"{'--address ' + self.url if self.url else ''} "
                    f"--email {secret['signin_address']} "
                    f"--raw"
                ),
                shell=True,
                capture_output=True,
                env=os.environ,
                timeout=30,
            )
            process.check_returncode()
            res = process.stdout.decode("UTF-8").strip()
            return res
        except subprocess.CalledProcessError:
            if process:
                reason = process.stderr.decode("UTF-8").strip()
                raise SigninFailure(f"Error adding account: '{reason}'").with_traceback(None)

    def list(self, vault: Optional[str] = None):
        op_command = f"{self.op} items list {'--vault ' + vault if vault else ''} --session={self._session_token}"
        try:
            return json.loads(run_op_command_in_shell(op_command))
        except json.decoder.JSONDecodeError:
            raise UnknownResource(vault)

    def get_vaults(self):
        op_command = f"{self.op} vaults list --session={self._session_token}"
        return json.loads(run_op_command_in_shell(op_command))

    def create_document_in_vault(self, filename: str, title: str, vault: str):
        op_command = f"""
        {self.op} document create [file]='{filename}' --title='{title}' 
        --vault='{vault}' --session={self._session_token}
        """
        return json.loads(run_op_command_in_shell(op_command))

    def create_login(self, username: str, password: str, title: str, vault: str = None, url: str = None):
        username_str = f"username={username}"
        password_str = f"password={password}"
        command = f"{username_str} {password_str}"
        login_template = {
            "category": "LOGIN",
            "title": title,
            "fields": [
                {
                    # "value": username,
                    "id": "username",
                    "type": "STRING",
                    "purpose": "USERNAME",
                    "label": "username",
                },
                {
                    # "value": password,
                    "id": "password",
                    "type": "CONCEALED",
                    "purpose": "PASSWORD",
                    "label": "password",
                    "designation": "password",
                },
            ],
        }

        return self.create_item(
            category=OnePasswordCategory.LOGIN, cmd=command, template=login_template, title=title, vault=vault, url=url
        )

    def create_note(self, note: str, title: str, vault: str):
        cmd = f"notes='{note}'"
        note_template = {
            "category": "SECURE_NOTE",
            "title": title,
            "fields": [
                {
                    # "value": note,
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                }
            ],
        }
        return self.create_item(
            category=OnePasswordCategory.SECURE_NOTE,
            template=note_template,
            title=title,
            vault=vault,
            cmd=cmd,
        )

    def create_item(
        self, cmd: str, category: OnePasswordCategory, title: str, vault: str, template: dict = None, url: str = None
    ):
        vault_flag = get_optional_flag(vault=vault)
        url_flag = get_optional_flag(url=url)

        command = f"""
            {self.op} item create{'' if template and 'category' in template else '--category='+category.value.lower()}\
             --title='{title}' \
            {vault_flag} {url_flag} {cmd} 
            --session={self._session_token} \
        """
        return run_op_command_in_shell(command, template, json_format=False)

    def delete_item(self, item_name: str, vault: dict = None):
        vault_flag = get_optional_flag(vault=vault)
        op_command = f"{self.op} items delete {item_name} {vault_flag} --session={self._session_token}"
        try:
            run_op_command_in_shell(op_command)
        except subprocess.CalledProcessError:
            raise DeletionFailure(item_name, vault)
        except UnknownError as e:
            error_message = str(e)
            if "multiple items found" in error_message:
                multiple_uuids = []
                rg = re.compile(f"\\s*for the item {item_name} in vault {vault}: (.*)")
                for line in error_message.split("\n"):
                    match = rg.match(line)
                    if match:
                        multiple_uuids.append(match.group(1))

                return {"multiple_uuids": multiple_uuids}
            if "no item found" in error_message:
                return "not found"
        return "ok"

    def get_value(self, vault: str, title: str, value_name: str):
        op_command = f"{self.op} read 'op://{vault}/{title}/{value_name}' --session={self._session_token}"
        try:
            return run_op_command_in_shell(op_command)
        except subprocess.CalledProcessError:
            raise UnknownResourceItem(f"{title}: {value_name}")

    def get_item(self, vault: str, title: str):
        op_command = f"{self.op} item get '{title}' --vault={vault} --session={self._session_token}"
        try:
            return json.loads(run_op_command_in_shell(op_command, json_format=True))
        except subprocess.CalledProcessError:
            raise UnknownResourceItem(f"{vault}: {title}")

    def _get_access_token(self, secret: dict):
        print("Getting access token...")
        process = None
        try:
            if not os.environ.get("OP_DEVICE"):
                os.environ["OP_DEVICE"] = base64.b32encode(os.urandom(16)).decode().lower().rstrip("=")
            process = subprocess.run(
                (
                    f"echo '{secret['password']}' | "
                    f"{self.op} signin {'--account ' + self.account if self.account else ''} "
                    f"--raw"
                ),
                shell=True,
                capture_output=True,
                env=os.environ,
                timeout=30,
            )
            process.check_returncode()
            res = process.stdout.decode("UTF-8").strip()
            return res
        except subprocess.CalledProcessError:
            if process:
                reason = process.stderr.decode("UTF-8").strip()
                raise SigninFailure(f"Error sign in: '{reason}").with_traceback(None)

    def get_version(self):
        return run_op_command_in_shell(f"{self.op} --version")


def run_op_command_in_shell(op_command: str, template: dict = None, verbose=False, json_format: bool = True):
    if json_format:
        op_command += " --format json"
    encoded_template = json.dumps(template, separators=(",", ":")).encode("utf-8") if template else None
    op_command = " ".join(op_command.replace("\n", " ").split())
    process = subprocess.run(
        op_command, shell=True, check=False, input=encoded_template, capture_output=True, env=os.environ, timeout=30
    )
    try:
        process.check_returncode()
    except subprocess.CalledProcessError:
        if verbose:
            print(process.stderr.decode("UTF-8").strip())

        error_messages = ["not currently signed in", "Authentication required"]
        full_error_message = process.stderr.decode("UTF-8")
        if any(msg in full_error_message for msg in error_messages):
            raise Unauthorized().with_traceback(None)
        else:
            raise UnknownError(full_error_message).with_traceback(None)

    return process.stdout.decode("UTF-8").strip()


if __name__ == "__main__":
    from dotenv import find_dotenv, load_dotenv

    load_dotenv(find_dotenv())
    secret = {
        "password": os.getenv("OP_PASSWORD"),
        "signin_address": os.getenv("OP_EMAIL"),
    }
    auth = all([secret["password"], secret["signin_address"], os.getenv("OP_SECRET_KEY")])
    print(f"Auth: {auth}")
    op = OnePasswordClient(secret=secret, account=os.getenv("OP_ACCOUNT"), url=os.getenv("OP_URL"), auth=auth)

    vaults = op.get_vaults()
    documents = op.list("Employee")
    # new_item = op.create_login("test_user", "test_pass", "test", "Employee")
    # item = op.get_item("Employee", "test")
    # note = op.create_note("test note", "test note", "Employee")
    # key_contents = op.get_value("Employee", "test note", "notes")
    pass
