# stratio-external-users-expired

This repo contains the code to check external users in LDAP. This code search all users based on [config.ini](config.ini) filter and check shadowExpire field. 
You can see the code to create a docker image with the [Dockerfile](Dockerfile)

## Dependencies
- Python >= 3.10.7
- pip3 >= 21.3.1
- ldap3 >= 2.9.1

### Install Dependencies
```
python3 -m pip install -r requirements.txt
```

# CICD
This repo is added to stratio CICD and autogenerate Docker in qa.int.stratio.com
