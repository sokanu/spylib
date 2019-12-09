FROM python:3.7


WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY spylib /app/spylib

ENV SPYLIB_AUTH_BASE_URL="https://auth.localhost:8000"

CMD python -m unittest
