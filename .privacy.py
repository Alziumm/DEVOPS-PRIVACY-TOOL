import os, subprocess, tempfile, getpass

from base64 import b64encode, b64decode
from colorama import Fore
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from datetime import datetime
from dotenv import load_dotenv
from gitignore_parser import parse_gitignore
from pathlib import Path
from secrets import token_bytes, choice

class SDEVRandom:

    """
    A utility class for generating random strings and numbers.
    """

    @staticmethod
    def get_random_string(length: int, strong: bool = False) -> str:

        """
        Generates a random string of the specified length.

        Args:
            length (int): The length of the random string to generate.
            strong (bool, optional): Specifies whether the random string should include special characters. Defaults to False.

        Returns:
            str: The generated random string.
        """

        dfl = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z", "A", "B", "C", "D", "E", "F", "G", "H" , "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]

        return ''.join(choice(dfl + ["~", "!" , "@" , "#" ,"$" ,"%" ,"^" ,"&" ,"*" ,"(" ,")" ,"-" ,"_" ,"=" ,"+" ,"[" ,"]" ,"{", "}", ",", ".", "<", ">", "/", "?"] if strong else dfl) for _ in range(length))

class SDEVPrint:

    @staticmethod
    def _f_msg(msg, color, message_type, date=True):
        date_time = datetime.now().strftime('%H:%M:%S') if date else ''
        message = f"{color}{msg}{Fore.RESET}"
        return f"[{date_time} > {message_type}] {message}" if date else message

    @staticmethod
    def _print_or_return(formatted_msg, type):
        if type:
            return formatted_msg
        print(formatted_msg)

    @staticmethod
    def info(msg, type=False, date=True):
        formatted_msg = SDEVPrint._f_msg(msg, Fore.CYAN, "INFO", date)
        return SDEVPrint._print_or_return(formatted_msg, type)

    @staticmethod
    def content(msg, type=False, date=True):
        formatted_msg = SDEVPrint._f_msg(msg, Fore.MAGENTA, "CONTENT", date)
        return SDEVPrint._print_or_return(formatted_msg, type)

    @staticmethod
    def good(msg, type=False, date=True):
        formatted_msg = SDEVPrint._f_msg(msg, Fore.GREEN, "GOOD", date)
        return SDEVPrint._print_or_return(formatted_msg, type)

    @staticmethod
    def warn(msg, type=False, date=True):
        formatted_msg = SDEVPrint._f_msg(msg, Fore.YELLOW, "WARN", date)
        return SDEVPrint._print_or_return(formatted_msg, type)

    @staticmethod
    def error(msg, type=False, date=True, is_critical=False):
        formatted_msg = SDEVPrint._f_msg(msg, Fore.RED, "ERROR", date)
        result = SDEVPrint._print_or_return(formatted_msg, type)
        if is_critical:
            exit()
        return result

class SDEVCrypto():

    """
    The SDEVCrypto class provides methods for encrypting and decrypting files and text using the ChaCha20Poly1305 process.
    """

    def __init__(self) -> None:

        """
        Initializes an instance of SDEVCrypto.

        The __init__ method sets the initial values for the instance variables of SDEVCrypto.

        Parameters:
            None

        Returns:
            None
        """

        self.prefix = '$SDEV;'
        self.extension = '.sdev'
        self.cache = {}

    def _get_derive_key(self, password: str, salt: str | None = None) -> str:

        """
        Derives a key from the given password and salt.

        Args:
            password (str): The password to derive the key from.
            salt (str | None, optional): The salt value to use for key derivation. If None, a random salt will be generated. Defaults to None.

        Returns:
            str: The derived key.

        Raises:
            None
        """

        if isinstance(password, str):
            password = password.encode('utf-8')

        ckey = (password, salt)

        if ckey in self.cache:

            e = self.cache[ckey]

            self.cache[ckey] = e[0], e[1], e[2] + 1

            return self.cache[ckey]

        if salt is None:

            salt = token_bytes(16)

        key = Scrypt(salt, 32, 2**16, 8, 1).derive(password)

        self.cache[ckey] = [salt, key, 0]

        return [salt, key, 0]

    def encrypt_file(self, filepath: str, password: str, add_extension = True, printable = False, filepath_out : str = None, delete_initial_file : bool = False) -> bool:

        """
        Encrypts the contents of a file using the specified encryption method.

        Args:
            filepath (str): The path to the file to be encrypted.
            password (str): The additional data required for encryption.
            add_extension (str): The encryption method to be used.

        Returns:
            bool: True if the file was successfully encrypted, False otherwise.
        """

        if os.path.getsize(filepath) < 2**31:

            with open(filepath, 'rb') as fh:

                ciphertext = self.encrypt(fh.read(), password, True, True)

            if ciphertext is not None:

                f_out = filepath_out if filepath_out is not None else filepath

                try:
                    os.makedirs(os.path.dirname(f_out), exist_ok=True)
                except:
                    pass

                with open(f_out, 'wb') as fh:

                    fh.write(ciphertext)

                if add_extension:

                    os.rename(f_out, f_out + self.extension)

                if printable:

                    SDEVPrint.good(f"File '{filepath}' encrypted successfully.")

                if delete_initial_file and filepath_out is not None:

                    os.remove(filepath)

                return True

        if printable:

            SDEVPrint.error(f"Error when encrypting the following file: {filepath}.")

        return False

    def decrypt_file(self, filepath : str, password : str, printable : bool = False, filepath_out : str = None, delete_initial_file : bool= False, warning = True) -> bool:

        """
        Decrypts a file using the specified method.

        Args:
            filepath (str): The path to the file to be decrypted.
            password (str): Additional data required for decryption.
            method (str): The decryption method to be used.

        Returns:
            bool: True if the file was successfully decrypted, False otherwise.
            
        Example:

            sdev = SDEVCrypto()

            file_to_encrypt = ".env"
            password = "mypassword"

            while True:

                method = input('Do you want to Encrypt or Decrypt? (E/D)')

                if method.upper() not in ['E', 'D']:

                    continue

                break

            if method == 'E':

                sdev.encrypt_file(file_to_encrypt, password)

            elif method == 'D':

                sdev.decrypt_file(f'{file_to_encrypt}.sdev', password)
        """

        try:

            if filepath.endswith(self.extension):

                with open(filepath, 'rb') as f:

                    data_to_decrypt = self.decrypt(f.read(), password, True)

                if data_to_decrypt is not None:

                    f_out = filepath_out if filepath_out is not None else filepath

                    if os.path.isfile(f_out[:-len(self.extension)]):

                        if warning:

                            while True:

                                if input(SDEVPrint.warn(f"This process will overwritte the current file: {filepath}. Do you want to continue? (Y/N)", True)).upper() != 'Y':

                                    continue

                                break

                    try:
                        os.makedirs(os.path.dirname(f_out), exist_ok=True)
                    except:
                        pass

                    with open(f_out, 'wb') as f:

                        f.write(data_to_decrypt)

                    try:
                        os.remove(f_out[:-len(self.extension)])
                    except:
                        pass

                    os.rename(f_out, f_out[:-len(self.extension)])

                    if printable:

                        SDEVPrint.good(f"File '{filepath}' decrypted successfully.")

                    if delete_initial_file and filepath_out is not None:

                        os.remove(filepath)

                    return True

            else:

                SDEVPrint.error(f"This file is not encrypted by SDEV process or you modify the file extension of the file: {filepath}", is_critical=True)

        except Exception as e:

            if printable:

                SDEVPrint.error(f"Error when decrypting the following file: {filepath} with the following error: {str(e)}", is_critical=True)

        return None

    def encrypt(self, data_to_encrypt : str, password : str, bs64 : bool = True, file_enc = False) -> str | bytes:

        """
        Encrypts the given data using the ChaCha20Poly1305 encryption algorithm.

        Args:
            data_to_encrypt (str): The data to be encrypted.
            password (str): The password used for encryption.
            bs64 (bool, optional): Specifies whether to return the encrypted data as a base64-encoded string. 
                Defaults to True.

        Returns:
            str or bytes: The encrypted data. If `bs64` is True, it returns a base64-encoded string, 
                otherwise it returns bytes.

        Raises:
            None
        """
        
        version = b'\x01'
        salt, key, uc = self._get_derive_key(password)
        nonce = token_bytes(12)[:-4] + uc.to_bytes(4, 'big')

        if isinstance(data_to_encrypt, str) and file_enc == False:

            ciphertext = ChaCha20Poly1305(key).encrypt(nonce, data_to_encrypt.encode('utf-8'), None)

        else:

            ciphertext = ChaCha20Poly1305(key).encrypt(nonce, data_to_encrypt, None)

        if bs64:

            r = self.prefix.encode('utf-8') + b64encode(version + salt + nonce + ciphertext)

            if file_enc:

                return r + b'\n'

            return r.decode('utf-8')
        
        return version + salt + nonce + ciphertext

    def decrypt(self, data_to_decrypt : str | bytes, password : str, file_enc : bool = False, printable : bool = False) -> str | bytes | None:

        """
        Decrypts the given data using the provided password.

        Args:
            data_to_decrypt (str | bytes): The data to decrypt.
            password (str): The password used for decryption.

        Returns:
            str | bytes | None: The decrypted data, or None if decryption fails.
        """

        if isinstance(data_to_decrypt, str) and file_enc == False:

            data_to_decrypt = data_to_decrypt.encode('utf-8')

        try:

            if data_to_decrypt.lstrip().startswith(self.prefix.encode('utf-8')):

                data_to_decrypt = b64decode(data_to_decrypt.strip()[len(self.prefix):])

            if data_to_decrypt.startswith(b'\x01') and len(data_to_decrypt) > 29:

                key = self._get_derive_key(password, data_to_decrypt[1:17])[1]

                clear_data = ChaCha20Poly1305(key).decrypt(data_to_decrypt[17:29], data_to_decrypt[29:], None)

                if file_enc:

                    return clear_data

                return clear_data.decode('utf-8')

        except InvalidTag:

            if printable:

                SDEVPrint.error("Invalid password or the file have been corrupted.")

        return None

class SDEVFile:
    
    @staticmethod
    def get_all_files(path: str | None = None, exclude_list : list= []) -> list:

        """
        Get a list of all files in the specified directory and its subdirectories.
        By default, the function return the current all files in the current directory.

        Args:
            path (str): The path to the directory.

        Returns:
            list: A list of all files in the directory and its subdirectories.
        """

        if path is None:

            path = SDEVFile.get_current_dir()

        fichiers = [os.path.relpath(os.path.join(dossier_parent, fichier), path).replace('\\', '/') for dossier_parent, _, fichiers_dans_dossier in os.walk(path) for fichier in fichiers_dans_dossier if os.path.join(dossier_parent, fichier) not in exclude_list]

        return fichiers

    @staticmethod
    def get_all_gitignore_files(gitignore_path : str, path_to_get : str |  None = None, exclude_list : list = []) -> list:

        """
        Get a list of all files in the specified directory and its subdirectories without the files list in the .gitignore file.
        By default, the function return the current all files in the current directory.

        Args:
            path (str): The path to the directory.

        Returns:
            list: A list of all files in the directory and its subdirectories without the files in the .gitignore file.
        """

        try:

            if os.path.exists(gitignore_path) != True:

                if os.path.exists(".gitignore"):

                    gitignore_path = ".gitignore"

                raise

            matches = parse_gitignore(gitignore_path)

        except:

            SDEVPrint.error(".gitignore file not found.", is_critical=True)

        if path_to_get is None:

            path_to_get = SDEVFile.get_current_dir()

        return [fichier for fichier in SDEVFile.get_all_files(path_to_get) if matches(fichier) and fichier not in exclude_list]


    @staticmethod
    def get_current_dir() -> str:

        """
        Returns the absolute path of the directory containing the current file.

        :return: The absolute path of the directory containing the current file.
        :rtype: str
        """

        return str(Path(__file__).resolve().parent)

class SDEVPrivacyFiles():

    def __init__(self, over_key : str | bool = True, env_file : str = ".privacy.env") -> None:

        """
        Initialize the PrivacyTool class.

        Args:
            over_key (str | bool, optional): Flag indicating whether to prompt for an encryption/decryption key. Defaults to True.
            env_file (str, optional): Path to the environment file. Defaults to ".privacy.env".
        """

        load_dotenv(dotenv_path=env_file, override=True)

        self.crypto = SDEVCrypto()

        self.github_privacy_repo = os.environ.get("GITHUB_PRIVACY_REPO") or "https://github.com/User/PRIVACY.git"
        self.secret_key = os.environ.get("SECRET_KEY") or """A.GR?I*QG9UEAOKLUt/)#Mc_,3d8Ubwrp{vzVy|y$qh]mEF=`6<O<,iC!Q]z7SD_u~%}-H5e|t|]IjgVWw8kk%n_Zs`@Bd8qT&;7qFr0,dD0?0]_nRage4kb)8!oWimG"""

        self.data_name = os.path.basename(os.getcwd())
        self.random_commit_id = SDEVRandom.get_random_string(16)
        self.repo_name = os.path.splitext(os.path.basename(self.github_privacy_repo))[0]

        if self.github_privacy_repo.startswith("https://github.com/") != True:

            SDEVPrint.error("The repository URL is not valid. Please use a repository like: `https://github.com/User/Repo.git`", is_critical=True)

        if self.repo_name.startswith("http") or self.repo_name.endswith(".git"):

            SDEVPrint.error("[INTERNAL ERROR] The repository name is not valid [http or .git].", is_critical=True)

        if len(self.secret_key) < 64:

            SDEVPrint.error("For security reason, the secret key must be at least 64 characters long.", is_critical=True)

        if over_key:

            while True:

                self.entry_key = str(getpass.getpass(SDEVPrint.info("Enter the key to encrypt/decrypt the file: ", True)))

                if len(self.entry_key) < 8:

                    SDEVPrint.error("The key must be at least 8 characters long.")

                    continue

                break

        self.secret_key = self.secret_key + self.entry_key

    def save_privacy_files(self, specific_data_name : str | None = None, specific_privacy_path : str = '.privacy'):

        """
        Saves privacy files to a GitHub repository.

        Args:
            specific_data_name (str | None, optional): Specific data name to use for saving the files. Defaults to None.
            specific_privacy_path (str, optional): Specific privacy path to search for gitignore files. Defaults to '.privacy'.
        """

        if specific_data_name is not None and isinstance(specific_data_name, str):

            self.data_name = specific_data_name

        with tempfile.TemporaryDirectory() as temp_dir:

            SDEVPrint.info(temp_dir)

            try:

                subprocess.check_call(['git', 'clone', self.github_privacy_repo], cwd=temp_dir)

            except subprocess.CalledProcessError as e:

                SDEVPrint.error(f"Error during repository cloning: {e}", is_critical=True)

            github_dir = temp_dir + f'\\{self.repo_name}\\'

            existing_file = SDEVFile.get_all_files(github_dir)

            _s = False

            for file in existing_file:

                if str(file).startswith(self.data_name):

                    _s = True

            working_dir = github_dir + self.data_name + "\\"

            if _s:

                for file in SDEVFile.get_all_files(working_dir):

                    SDEVPrint.content("Content deleted: " + working_dir + file)

                    os.remove(working_dir + file)

            for file in SDEVFile.get_all_gitignore_files(specific_privacy_path):

                self.crypto.encrypt_file(file, self.secret_key, printable=True, filepath_out=working_dir + file)

            subprocess.check_call(['git', 'add', '.'], cwd=github_dir)

            subprocess.check_call(['git', 'commit', '-m', f"SDEVPrivacy >>> {self.data_name} #{self.random_commit_id}"], cwd=github_dir)

            subprocess.check_call(['git', 'push', 'origin', 'main'], cwd=github_dir)

            SDEVPrint.good("Changes committed and pushed to the repository.")

    def load_privacy_files(self, specific_data_name = None):

        """
        Loads privacy files from a GitHub repository.

        Args:
            specific_data_name (str, optional): Specific data name to load. Defaults to None.

        Raises:
            CalledProcessError: If an error occurs during the cloning of the repository.
            FileNotFoundError: If the required `data_name` does not exist in the repository.

        Returns:
            True
        """

        if specific_data_name is not None and isinstance(specific_data_name, str):

            self.data_name = specific_data_name

        with tempfile.TemporaryDirectory() as temp_dir:

            SDEVPrint.info(temp_dir)

            try:

                subprocess.check_call(['git', 'clone', self.github_privacy_repo], cwd=temp_dir)

            except subprocess.CalledProcessError as e:

                SDEVPrint.error(f"Error during repository cloning: {e}", is_critical=True)

            github_dir = temp_dir + F'\\{self.repo_name}\\'

            _s = False

            for file in SDEVFile.get_all_files(github_dir):

                if str(file).startswith(self.data_name):

                    _s = True

            if _s != True:

                SDEVPrint.error("The required `data_name` does not exist in the repository.", is_critical=True)

            working_dir = github_dir + self.data_name + "\\"

            for file in SDEVFile.get_all_files(working_dir):

                self.crypto.decrypt_file(working_dir + file, self.secret_key, printable=True, filepath_out=file)

        return True

if __name__ == '__main__':

    while True:

        _c = input(SDEVPrint.info("Do you want to save your files on Github (S) or load your files from Github (L)? (S/L): ", True))

        if _c.upper() not in ['S', 'L']:

            continue

        break

    SDEVPrivacyFiles().save_privacy_files() if _c == 'S' else SDEVPrivacyFiles().load_privacy_files()