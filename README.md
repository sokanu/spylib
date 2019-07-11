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

Spylib makes making calls to foreign services easier. The way Spylib accomplishes this is by providing `ServiceRequestFactory`.

### Example: Service-to-Service

```
from spylib import ServiceRequestFactory

srf = ServiceRequestFactory(
  uuid=os.environ['MY_SERVICE_UUID'],
  api_key=os.environ['MY_SERVICE_API_KEY'],
)

resp = srf.post(
  'catdatabase.com',
  'api/v1/cats',
  payload={
    'breed': 'Tabby',
    'name': 'Salty'
  }
)
```

In the above example, we first initialize our request factory. This object is then used to make requests to a foreign service. In this example, we're adding a cat to some sort of cat database.

Under the hood, the ServiceRequestFactory will ensure your request has the associated `access_token` required to make the request. In the above example, it does this by using the `uuid` and `api_key` supplied to make a login request to the auth service, and then use the returned token to make the actual request.

To avoid having to make repeated calls to the auth service, however, Spylib offers a way for you to provide stored `access_token` and `refresh_token` values through something like a local cache.

```
from spylib import Observer, ServiceRequestFactory
from database_wrapper import store_tokens

class DatabaseTokenObserver(Observer):
  def __init__(self, *args,  **kwargs):
    super(DatabaseTokenObserver, self).__init__(*args, **kwargs)   
  
  # notify is overriden from the original Observer class
  def notify(self, observable):
    access_token = observable.access_token
    refresh_token = observable.refresh_token
    store_tokens(access_token, refresh_token)
    
db_token_observer = DatabaseTokenObserver()

srf = ServiceRequestFactory(
  uuid=os.environ['MY_SERVICE_UUID'],
  api_key=os.environ['MY_SERVICE_API_KEY'],
  access_token = get_access_token_from_db(),
  refresh_token = get_refresh_token_from_db()
  observer_lst=[db_token_observer]
)
```

In the above example, we've created an observer class called `DatabaseTokenObserver`, and when it is notified, it updates the database with the new tokens.

The `ServiceRequestFactory` we instantiate also gets the current `access_token` and `refresh_token` from the DB (if they exist, presumably). The benefit of all of this work is that now subsequent calls that the factory makes will not have to go through auth, until of course the `access_token` expires. Intermediary calls to the auth service will only happen when the stored `access_token` expires, or the `refresh_token` is also expired.

### Example: User-to-Service

You may need to make calls to another service on behalf of a current user. To do that, we use the `ServiceRequestFactory` again.

```
from spylib import ServiceRequestFactory

def my_view(request)
    srf = ServiceRequestFactory(
        access_token=get_at_from_request(request),
        refresh_token=get_rt_from_request(request),
    )

    resp = srf.post(
        'catdatabase.com',
        'api/v1/cats',
        payload={
            'breed': 'Tabby',
            'name': 'Salty'
        }
    )
```

In this example, `get_at_from_request` and `get_rt_from_request` would be written in your project, as the different request types or contexts are beyond the scope of Spylib.

## Tests

Tests are run be unit test discovery. Please run the following command locally to run the suite.

```
docker build -t spylib . && docker run spylib
```

## Upgrading Packages
- When upgrading `requirements.txt`, pleases also upgrade `setup.py` if the package will effect other applications that pull in spylib.
