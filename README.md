# DevOps Privacy Tool for managing sensitive data through GitHub without Github API.

## Project Description:

<strong>This Python code allows for classifying and storing sensitive data on GitHub, such as environment files or private keys, using the symmetric encryption method: ChaCha20Poly1305.</strong>

## In what context should this code be used?

* Personally, I use this code to synchronize and manage the sensitive elements of my various projects, allowing me to access them remotely and across my different computers.

## Make sure that:

* The repository where your data will be stored is private.
* All the files you want to save must be located in the same directory as: .privacy ||| .privacy.env ||| .privacy.py
* Since this code does not use the GitHub API, it is crucial that the Git instance on the computer(s) running the script has access to the repository where you store the data. To verify this, simply perform a basic git clone on the repository you want to use to ensure you are properly connected via Git.
* Python must be installed on your machine, otherwise you won't be able to run the script.

## .privacy file:

* The .privacy file work exactly like a .gitignore file with the exactly same format.

## .privacy.env file:

* A safest way to manage the secret_key but you can directly edit the `self.github_privacy_repo` & `self.secret_key` variable.

## How to start the script:

1) First, create the private repository where the data will be stored. You can create the repository directly on Github. 
2) Add the HTTP link of your private repository in ".privacy.env"
3) Create a secure secret_key in ".privacy.env"
4) `pip install -r requirements.txt`
5) `python .privacy.py`

## TODO : 

* Adding the ability to add files to the filesystem that are not necessarily at the root path.