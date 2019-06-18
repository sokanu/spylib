# Spylib (Sokanu Python Lib)
![Spylib Logo](img.png)

*A library used for sharing abstract code between services*

## Goals

1. Encapsulate python modules shared across multiple services (linkforge, careless response, auth, ...) into one repository.
2. Lower the overhead when creating new microservices.
3. Create a standardization into how things are done in order to promote faster development time, better code quality, less bugs.
4. Be framework agnostic.
5. Use the least number of dependencies as possible.


## Tests

Tests are run be unit test discovery. Please run the following command locally to run the suite.

```
python3 -m unittest
```

## Upgrading Packages
- When upgrading `requirements.txt`, pleases also upgrade `setup.py` if the package will effect other applications that pull in spylib.
