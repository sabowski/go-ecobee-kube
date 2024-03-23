# go-ecobee-kube

A go library and simple tools for accessing the [Ecobee Thermostat
API](https://www.ecobee.com/home/developer/api/documentation/v1/index.shtml).
This repo is a fork of [go-ecobee](https://github.com/rspier/go-ecobee) which
stores the ecobee oauth2 token in a Kubernetes secret, rather than in a file on
disk.

The go-ecobee CLI is built with the underlying go-ecobee API, and
serves as it's primary example.

## Setup

### Install

```shell
go install -u github.com/rspier/go-ecobee`
```

### Build

```shell
go build main.go

# fully static binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main
```

### Application ID

[Enable your developer
dashboard](https://www.ecobee.com/home/developer/loginDeveloper.jsp), if you
have not already.

Create an Ecobee API Application ID (API key) by going to the
[consumer portal](https://www.ecobee.com/consumerportal/index.html), clicking
the "Developer" option in the menu, and clicking the "Create New" button.

You probably want to use the `ecobee PIN` authorization method for non-web based
tools.

### Thermostat ID

You'll need to know the serial number (Thermostat ID) of your
thermostat.  You can find it on the About page of the
[Ecobee portal](https://www.ecobee.com/consumerportal/index.html).

### Config

You can store your default thermostat id and appid in
`~/.go-ecobee.yaml` or you can use the `--thermostat` and `--appid`
flags to the CLI.

```yaml
thermostat: <Thermostat ID>
appid: <App ID>
```

## CLI Usage

### Status

```shell
$ go-ecobee --command=status
Current Settings (Home): 68.0 - 75.0.  Fan: auto
Holding at 68.0 - 75.0 (Fan: auto) until 2017-04-22 00:00:00
Temperature: 75.0
  Bedroom\*: 74.7
  My ecobee3\*: 76.2
```

### Hold Temperature

```shell
$ go-ecobee hold --heat 70 --cool 76 --duration 10m
Successfully Held Temperature
```

### Message

```shell
$ go-ecobee message --message="Hi there!"
Successfully sent message: "Hi there!"
```

### Fan

```shell
$ go-ecobee fan --duration=5m
Running fan for 5 minutes"
```

### List

```shell
$ go-ecobee list
${THERMID}: My ecobee3
```

## Development

## Lint

Use [golangci-lint](https://golangci-lint.run/):

```shell
docker run --rm -v $(pwd):/app -w /app \
  golangci/golangci-lint:v1.35.2 golangci-lint run \
  -E golint,goimports,misspell
```

## Ideas for future development

### Sensor Failure Test

Use includeSensors on the thermostat endpoint to analyze sensors where
the presence sensor may have failed -- i.e. present all the time.

## Disclaimer

This is not an official Google project.
