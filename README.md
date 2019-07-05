# Spylib (Sokanu Python Lib)
![Spylib Logo](img.png)

*A library used for sharing abstract code between services*

## Goals

1. Encapsulate python modules shared across multiple services (linkforge, careless response, auth, ...) into one repository.
2. Lower the overhead when creating new microservices.
3. Create a standardization into how things are done in order to promote faster development time, better code quality, less bugs.
4. Be framework agnostic.
5. Use the least number of dependencies as possible.

## How to install spylib

Add the following to your requirements.txt file on its own line; and replace `va.b.c` with the SEMVER version of this library that you'd like to consume (e.g. `v0.0.1`)
`-e git+https://github.com/sokanu/spylib.git@va.b.c#egg=spylib`

## How to make service calls between services.

Spylib houses a class called `ServiceRequestFactory` that enables you to make cross-service requests. You can import this class like so.
```
from spylib import ServiceRequestFactory
```
ServiceRequestFactory requires you to know the `uuid` and `api_key` of the user making the cross-service request. In the future, we plan to expand this to include more fields (such as `email` and `password`). 

ServiceRequestFactory comes equipped with a token management system. Your `access_token` and `refresh_token` on a factory instance, will be kept up to date as calls are made. 

Most services will need to keep track of their tokens - such as in a cache or database. Spylib employs the Observer pattern, and is equipped with an overridable `Observer` that can be consumed to help make updates to your data store. 

In order to use the Observer pattern, you can import it and override it like so.

```
from spylib import Observer, ServiceRequestFactory
from database_wrapper import store_tokens

class DatabaseTokenObserver(Observer):
  def __init__(self, observable):
    super(DatabaseTokenObserver, self).__init__(observable)   
  
  # notify is overriden from the original Observer class
  def notify(self, observable):
    access_token = observable.access_token
    refresh_token = observable.refresh_token
    store_tokens(access_token, refresh_token)
    

def get_service_request_factory():
  request_instance = ServiceRequestFactory(
    uuid = <UUID>,
    api_key = <api_key>,
    access_token = <optional>,
    refresh_token = <optional>
  )
  observer = DatabaseTokenObserver(observable = request_instance)
  return request_instance
```

## Tests

Tests are run be unit test discovery. Please run the following command locally to run the suite.

```
python3 -m unittest
```


## Upgrading Packages
- When upgrading `requirements.txt`, pleases also upgrade `setup.py` if the package will effect other applications that pull in spylib.
