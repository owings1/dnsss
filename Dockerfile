FROM docker.io/python:3.14-alpine
WORKDIR /app
RUN apk --no-cache -q add bash jq yq
COPY ./requirements.txt ./
RUN pip --no-input --no-cache-dir -qqq install -r requirements.txt
COPY . .
STOPSIGNAL SIGQUIT