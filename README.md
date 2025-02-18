![Ziggy using the sdk-golang](https://raw.githubusercontent.com/openziti/branding/main/images/banners/Go.jpg)

# Ziti SDK for Golang

The OpenZiti SDK for GoLang allows developers to create their own custom OpenZiti network endpoint clients and
management tools. OpenZiti is a modern, programmable network overlay with associated edge components, for
application-embedded, zero trust network connectivity, written by developers for developers. The SDK harnesses that
power via APIs that allow developers to imagine and develop solutions beyond what OpenZiti handles by default.

This SDK does the following:

- enable network endpoint clients allow a device to [dial (access) or bind (host)](#dialbind-a-service) OpenZiti Services
- provides [authentication](https://openziti.io/docs/learn/core-concepts/security/authentication/auth) interfaces for
  [x509 certificates, username/password, external IdPs (JWT)](#example-code-configuration) flows
- collects and submits security posture collection/submission
  for [Posture Checks](https://openziti.io/docs/learn/core-concepts/security/authorization/posture-checks)
- allows Golang applications to bind or dial services via [`net.Listener` and`net.Dialer`](#dialbind-a-service) interfaces
- enables [raw access](#accessing-the-managementclient-api) to the [Ziti Edge Management API](https://openziti.io/docs/reference/developer/api) for custom
  management tooling of all OpenZiti network identities, policies, and more
- enables [raw access](#accessing-the-managementclient-api) to the [Ziti Edge Client API](https://openziti.io/docs/reference/developer/api) for custom client
  tooling

## Table of Contents

- [Important Packages](#important-packages)
- [Writing Your Own Endpoint Client](#writing-your-own-endpoint-client)
  - [Load/Create A Configuration](#loadcreate-a-configuration)
  - [Create A Ziti Context](#create-a-ziti-context)
  - [Dial/Bind A Service](#dialbind-a-service)
  - [Creating & Enrolling an Identity](#creating--enrolling-an-identity)
  - [Allowing Dial/Bind Access to a Service](#allowing-dialbind-access-to-a-service)
- [Accessing the Management/Client API](#accessing-the-managementclient-api) 

## Important Packages

This repository has a number of different folders, however below are the most important ones for a new developer
to be aware of.

- [`ziti`](ziti) - the main SDK package that will be included in your project
- [`edge-apis`](edge-apis) - provides low-level abstractions for authenticating and accessing
  the [Ziti Edge Client and Management APIs]((https://openziti.io/docs/reference/developer/api))
- [`example`](example) - various example applications that illustrate different uses of the SDK. Each example contains its own
  README.md.
    - [`chat`](example/chat) - a bare-bones example of a client and server for a chat program over an OpenZiti Service
    - [`chat-p2p`](example/chat-p2p) - highlights `addressable terminators` which allows clients to dial specific
      services hosts if there are multiple hosts
    - [`curlz`](example/curlz) - wrapping existing network tooling (curl) to work over OpenZiti
    - [`grpc-example`](example/grpc-example) - using GRPC over OpenZiti
    - [`http-client`](example/http-client) - a HTTP client accessing a web server over HTTP
    - [`jwtchat`](example/jwtchat) - highlights
      using [external JWTs](https://openziti.io/docs/learn/core-concepts/security/authentication/external-jwt-signers) (
      from OIDC/oAuth/etc.) to authenticate with OpenZIti
    - [`reflect`](example/reflect) - a low level network "echo" client and server example
    - [`simple-server`](example/simple-server) - a bare-bones HTTP server side only example
    - [`udp-offload`](example/udp-offload) - an example demonstrating how to work with an OpenZiti client and a UDP server
    - [`zcat`](example/zcat) - wrapping existing network tooling (netcat) to work over OpenZiti
    - [`zping`](example/zping) - wrapping existing network tooling (ping) to work over OpenZiti

## Writing Your Own Endpoint Client

An "endpoint client" in OpenZiti's language is
an [identity](https://openziti.io/docs/learn/core-concepts/identities/overview) that is dialing (accessing)
or binding (hosting) a [service](https://openziti.io/docs/learn/core-concepts/services/overview). Dialing contacts
either another identity hosting a service, which may be another client endpoint, or it may be handled by an Edge Router
depending on its [termination](https://openziti.io/docs/learn/core-concepts/services/overview#service-termination)
configuration. This SDK supports binding and dialing, which means it can host or access services depending on what it is
[instructed to do](#dialbind-a-service) and the [policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview) 
affecting the software's identity and service(s).

To test a client endpoint you will need the following outside your normal Golang development environment:

1. An OpenZiti Network with controller with at least one Edge Router 
   (See [Quick Starts](https://openziti.io/docs/learn/quickstarts/))
2. A service to dial (access) and bind (host) 
   (See [Allowing Dial/Bind Access To A Service](#allowing-dialbind-access-to-a-service))
3. An identity for your client to test with 
   (See [Creating & Enrolling a Dial Identity](#creating--enrolling-a-dial-identity))

The steps for writing any endpoint client are:

1. [Load/Create a configuration](#loadcreate-a-configuration)
2. [Create a instance](#create-a-ziti-context)
3. [Dial/Bind a service](#dialbind-a-service)

The above links provide the steps in more detail, but here is the most basic setup to dial a service with most error 
handling removed for brevity:

```golang
	cfg, _ := ziti.NewConfigFromFile("client.json")
	
	context, _ := ziti.NewContext(cfg)
	
	conn, _ := context.Dial(serviceName)
	
	if _, err := conn.Write([]byte("hello I am myTestClient")); err != nil {
		panic(err)
	}
```

### Load/Create A Configuration

Configuration can be done through a file or through code that creates a [`Config`](ziti/config.go) instance. Loading
through a file support x509 authentication only while creating custom `Config` instances allows for all authentication
methods (x509, Username/Password, JWT, etc.).

The easiest way to create a configuration is by using
the [`ziti edge enroll`](https://openziti.io/docs/learn/core-concepts/identities/enrolling) capabilities that will
generate an identity file that provides the location of the OpenZiti controller, the configuration types the client is
interested in, and the x509 certificate and private key to use.

#### Example: File Configuration

```golang
cfg, err := ziti.NewConfigFromFile("client.json")
if err != nil {
    _, _ = fmt.Fprintf(os.Stderr, "failed to read configuration: %v", err)
    os.Exit(1)
}
```

#### Example: Code Configuration
```golang
// Note that GetControllerWellKnownCaPool() does not verify the authenticity of the controller, it is assumed
// this is handled in some other way.
caPool, err := ziti.GetControllerWellKnownCaPool("https://localhost:1280")

if err != nil {
    panic(err)
}

credentials := edge_apis.NewUpdbCredentials("Joe Admin", "20984hgn2q048ngq20-3gn")
credentials.CaPool = caPool

cfg := &ziti.Config{
    ZtAPI:       "https://localhost:1280/edge/client/v1",
    Credentials: credentials,
}
ctx, err := ziti.NewContext(cfg)
```

### Create A Ziti Context

A [`Context`](ziti/contexts.go) instances represent a specific identity connected to a Ziti Controller. The instance,
once configured, will handle authentication, re-authentication, posture state submission, and provides interfaces
to dial/bind services.

```golang
context, err := ziti.NewContext(cfg)

if err != nil {
    _, _ = fmt.Fprintf(os.Stderr, "failed to create context: %v", err)
    os.Exit(1)
}
```

### Dial/Bind A Service

The main activity performed with a [`Context`](ziti/contexts.go) is to dial or bind a service. In order for a dial or
bind to be successful, the following must be true:

1. The identity must have the proper dial or bind service policy to the service via [Service Policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview#service-policies)
2. The identity must have the proper dial or bind services over at least one Edge Router via [Edge Router Policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview#edge-router-policies)
3. The service must be allowed to be dialed or bound on at least one Edge Router via [Service Edge Router Policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview#service-policies))

The easiest way to satisfy #2 and #3 are the make use of the `#all` 
[role attribute](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview#roles-and-role-attributes) 
when creating the policies. Edge Router policies and Service Edge Router Policies are useful for geographic connection 
management. For smaller networks, test networks, and networks without geographic network entry are not concerns they
add complexity without inherent benefit. Using the `#all` role attributes makes all service accessible and valid 
dial/bind targets on all Edge Routers.

#### Example: "All" Edge Router and Service Edge Router Policies

```
> ziti edge create service-edge-router-policy serp-all --edge-router-roles "#all" --service-roles "#all"
> ziti edge create edge-router-policy erp-all --edge-router-roles "#all" --identity-roles "#all"
```

#### Example: Dial and Bind Policies For a Service

```
> ziti edge create service-policy  testDial Dial --identity-roles "@myTestClient" --service-roles "@myChat"
> ziti edge create service-policy  testBind Bind --identity-roles "@myTestServer" --service-roles "@myChat"
```

_Note: While policies can be created targeting specific users, services, or routers, using `#attribute` style assignments
allows you to grant access based on groupings. (See [Roles and Role Attributes](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview#roles-and-role-attributes))_

#### Example: Dial

```golang
conn, err := context.Dial(serviceName)

if err != nil {
    _, _ = fmt.Fprintf(os.Stderr, "failed to dial service %v, err: %+v\n", serviceName, err)
    os.Exit(1)
}

if _, err := conn.Write([]byte("hello I am myTestClient")); err != nil {
    panic(err)
}
```

#### Example: Bind
_Note: A full implementation will have to accept connections, hand them off to another goroutine and then re-wait on 
`listener.Accept()`_

```golang
func main(){
    //... load configuration, create context
    
    listener, err := context.ListenWithOptions(serviceName, &options)
    if err != nil {
        logrus.Errorf("Error binding service %+v", err)
        panic(err)
    }
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            logger.Errorf("server error, exiting: %+v\n", err)
            panic(err)
        }
        logger.Infof("new connection")
        go handleConn(conn)
    }
}

func handleConn(conn net.Conn){
    for {
        buf := make([]byte, 1024)
        n, err := conn.Read(buf)
        if err != nil {
            _ = conn.Close()
            return
        }
        stringData := string(buf[:n])
        println(stringData)
    }
}
```

### Creating & Enrolling an Identity

For more detail on how to create and enroll identities see the
[identities](https://openziti.io/docs/learn/core-concepts/identities/overview) section in the OpenZiti documentation.

1. Login to the controller `ziti edge login https://ctrl-api/edge/client/v1 -u <username> -p <password>`
2. Create a new identity `ziti edge create identity device myTestClient -o client.enroll.jwt`
3. Enroll the identity `ziti edge enroll client.enroll.jwt -o client.json`

The output file, `client.json` in this file, is used as that target in the SDK call 
`ziti.NewConfigFromFile("client.json")` to create a configuration.


### Allowing Dial/Bind Access to a Service

For more detail on policies see the
[policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview) section in the
OpenZiti documentation.

1. Login if not already logged in `ziti edge login https://ctrl-api/edge/client/v1 -u <username> -p <password>`
2. Create a new service ` ziti edge create service myChat`
3. Allow the service to be accessed by the `myTestClient` through any Edge Router and the service `myChat` through any
   Edge Router
    1. `ziti edge create service-policy testPolicy Dial --identity-roles "@myTestClient" --service-roles "@myChat"`
    2. `ziti edge create service-edge-router-policy chatOverAll --edge-router-roles "#all" --service-roles "@myChat"`

_Note: While policies can be created targeting specific users, services, or routers, using `#attribute` style assignments
allows you to grant access based on groupings. (See [Roles and Role Attributes](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/overview#roles-and-role-attributes))_


## Accessing the Management/Client API

The Edge Management and Client APIs are defined by an OpenAPI 2.0 specification and have a client that is generated
and maintained in [another GitHub repository](https://github.com/openziti/edge-api). Accessing this repository directly
should not be necessary. This SDK provides a wrapper around the generated clients found in [`edge-apis`](edge-apis).

#### Example: Creating an Edge Management API Client
```golang
func emptyTotpCallback(ch chan string) {
	ch <- "" // Send an empty string
	close(ch)
}

apiUrl, _ = url.Parse("https://localhost:1280/edge/management/v1") 

// Note that GetControllerWellKnownCaPool() does not verify the authenticity of the controller, it is assumed
// this is handled in some other way.
caPool, err := ziti.GetControllerWellKnownCaPool("https://localhost:1280")

if err != nil {
panic(err)
}

credentials := edge_apis.NewUpdbCredentials("Joe Admin", "20984hgn2q048ngq20-3gn")
credentials.CaPool = caPool

//Note: the CA pool can be provided here or during the Authenticate(<creds>) call. It is allowed here to enable
//      calls to REST API endpoints that do not require authentication.
var apiUrls []*url.URL
apiUrls = append(apiUrls, apiUrl)

managementClient := edge_apis.NewManagementApiClient(apiUrls, credentials.GetCaPool(), emptyTotpCallback)),

//"configTypes" are string identifiers of configuration that can be requested by clients. Developers may
//specify their own in order to provide distributed identity and/or service specific configurations.
//
//See: https://openziti.io/docs/learn/core-concepts/config-store/overview
//Example: configTypes = []string{"myCustomAppConfigType"}
var configTypes []string

apiSesionDetial, err := managementClient.Authenticate(credentials, configTypes)
```

#### Example: Creating an Edge Client API Client
```golang

apiUrl, _ = url.Parse("https://localhost:1280/edge/client/v1") 

// Note that GetControllerWellKnownCaPool() does not verify the authenticity of the controller, it is assumed
// this is handled in some other way.
caPool, err := ziti.GetControllerWellKnownCaPool("https://localhost:1280")

if err != nil {
panic(err)
}

credentials := edge_apis.NewUpdbCredentials("Joe Admin", "20984hgn2q048ngq20-3gn")
credentials.CaPool = caPool

//Note: the CA pool can be provided here or during the Authenticate(<creds>) call. It is allowed here to enable
//      calls to REST API endpoints that do not require authentication.
client := edge_apis.NewClientApiClient(apiUrl, credentials.GetCaPool(), ),

//"configTypes" are string identifiers of configuration that can be requested by clients. Developers may
//specify their own in order to provide distributed identity and/or service specific configurations. The
//OpenZiti tunnelers use this capability to configure interception of network connections.
//See: https://openziti.io/docs/learn/core-concepts/config-store/overview
//Example: configTypes = []string{"myCustomAppConfigType"}
var configTypes []string

apiSesionDetial, err := client.Authenticate(credentials, configTypes)
```

### Example: Requesting Management Services

The following example show how to list services. Altering the names of the package types used will allow the same
code to work for the Edge Client API.

```golang
// GetServices retrieves services in chunks of 500 till it has accumulated all services.
func GetServices(client *apis.ManagementApiClient) ([]*rest_model.ServiceDetail, error) {
	params := service.NewListServicesParams()

	pageOffset := int64(0)
	pageLimit := int64(500)

	var services []*rest_model.ServiceDetail

	for {
		params.Limit = &pageLimit
		params.Offset = &pageOffset

		resp, err := client.API.Service.ListServices(params, nil)

		if err != nil {
			return nil, rest_util.WrapErr(err)
		}

		if services == nil {
			services = make([]*rest_model.ServiceDetail, 0, *resp.Payload.Meta.Pagination.TotalCount)
		}

		services = append(services, resp.Payload.Data...)

		pageOffset += pageLimit
		if pageOffset >= *resp.Payload.Meta.Pagination.TotalCount {
			break
		}
	}

	return services, nil
}
```
